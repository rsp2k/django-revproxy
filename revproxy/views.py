import hashlib
import re
import logging
import time

import requests
from django.http import HttpResponseServerError
from django.utils import timezone
from django.utils.functional import cached_property

from revproxy.models import CachedResponse

try:
    from django.utils.six.moves.urllib.parse import (
        urlparse, urlencode, quote_plus)
except ImportError:
    # Django 3 has no six
    from urllib.parse import urlparse, urlencode, quote_plus

from django.shortcuts import redirect
from django.views.generic import View
from django.utils.decorators import classonlymethod

from .exceptions import InvalidUpstream
from .response import get_django_response
from .utils import normalize_request_headers

logger = logging.getLogger()

ERRORS_MESSAGES = {
    'upstream-no-scheme': ("Upstream URL scheme must be either "
                           "'http' or 'https' (%s).")
}


class ProxyView(View):
    """View responsable by excute proxy requests, process and return
    their responses.

    """
    _upstream = None

    # Store request and server response in the database
    store_in_db = False

    # List of strings to consider in request hash for caching
    headers_to_hash = []

    add_x_forwarded = False
    add_remote_user = False

    strict_cookies = False

    #: Do not send any body if it is empty (put ``None`` into the ``urlopen()``
    #: call).  This is required when proxying to Shiny apps, for example.
    suppress_empty_body = False

    # The buffering amount for streaming HTTP response(in bytes), response will
    # be buffered until it's length exceeds this value. `None` means using
    # default value, override this variable to change.
    streaming_amount = None

    def __init__(self, *args, **kwargs):
        self.store_in_db = kwargs.pop('store_in_db', False)
        self.cache_responses = kwargs.pop('cache_responses', False)
        self.headers_to_hash = kwargs.pop('headers_to_hash', [])
        self.rewrite = kwargs.pop('rewrite', [])

        super().__init__(*args, **kwargs)

        self._rewrite = []
        # Take all elements inside tuple, and insert into _rewrite
        for from_pattern, to_pattern in self.rewrite:
            from_re = re.compile(from_pattern)
            self._rewrite.append((from_re, to_pattern))

    @property
    def upstream(self):
        if not self._upstream:
            raise NotImplementedError('Upstream server must be set')
        return self._upstream

    @upstream.setter
    def upstream(self, value):
        self._upstream = value

    def get_upstream(self, path):
        upstream = self.upstream

        if not getattr(self, '_parsed_url', None):
            self._parsed_url = urlparse(upstream)

        if self._parsed_url.scheme not in ('http', 'https'):
            raise InvalidUpstream(ERRORS_MESSAGES['upstream-no-scheme'] %
                                  upstream)

        if path and not upstream.endswith('/'):
            upstream += '/'

        return upstream

    @classonlymethod
    def as_view(cls, **initkwargs):
        view = super(ProxyView, cls).as_view(**initkwargs)
        view.csrf_exempt = True
        return view

    def _format_path_to_redirect(self, request):
        full_path = request.get_full_path()
        logger.debug("Dispatch full path: %s", full_path)
        for from_re, to_pattern in self._rewrite:
            if from_re.match(full_path):
                redirect_to = from_re.sub(to_pattern, full_path)
                logger.debug("Redirect to: %s", redirect_to)
                return redirect_to

    def get_proxy_request_headers(self, request):
        """Get normalized headers for the upstream

        Gets all headers from the original request and normalizes them.
        Normalization occurs by removing the prefix ``HTTP_`` and
        replacing and ``_`` by ``-``. Example: ``HTTP_ACCEPT_ENCODING``
        becames ``Accept-Encoding``.

        .. versionadded:: 0.9.1

        :param request:  The original HTTPRequest instance
        :returns:  Normalized headers for the upstream
        """
        return normalize_request_headers(request)

    @cached_property
    def request_headers(self):
        """Return request headers that will be sent to upstream.

        The header REMOTE_USER is set to the current user
        if AuthenticationMiddleware is enabled and
        the view's add_remote_user property is True.

        .. versionadded:: 0.9.8

        If the view's add_x_forwarded property is True, the
        headers X-Forwarded-For and X-Forwarded-Proto are set to the
        IP address of the requestor and the request's protocol (http or https),
        respectively.

        .. versionadded:: TODO

        """
        request_headers = self.get_proxy_request_headers(self.request)

        if (self.add_remote_user and hasattr(self.request, 'user')
                and self.request.user.is_active):
            request_headers['REMOTE_USER'] = self.request.user.email
            logger.info(f"REMOTE_USER set to {request_headers['REMOTE_USER']}")

        if self.add_x_forwarded:
            request_ip = self.request.META.get('REMOTE_ADDR')
            logger.debug("Proxy request IP: %s", request_ip)
            request_headers['X-Forwarded-For'] = request_ip

            request_proto = "https" if self.request.is_secure() else "http"
            logger.debug("Proxy request using %s", request_proto)
            request_headers['X-Forwarded-Proto'] = request_proto

        return request_headers

    def fetch_from_proxy(self, request, path):
        request_payload = request.body
        if self.suppress_empty_body and not request_payload:
            request_payload = None

        logger.debug("Request headers: {self.request_headers}")

        fetch = getattr(requests, request.method.lower())

        request_url = f"{self.get_upstream(path)}" + path

        logger.debug(f"Using {fetch} to get {request_url}")
        try:
            proxy_response = fetch(
                request_url,
                params=self.request.GET,
                allow_redirects=False,
                headers=self.request_headers,
                data=request_payload,
            )
        except requests.exceptions.SSLError as error:
            logger.exception(error)
            return HttpResponseServerError(
                "The server has a security problem!"
            )

        except (
                requests.exceptions.Timeout,
                requests.exceptions.ConnectionError
        ) as error:
            logger.exception(error)
            return HttpResponseServerError(
                "Something went wrong connecting to the server"
            )

        except requests.exceptions.RequestException as error:
            logger.exception(error)
            return HttpResponseServerError(
                "Unknown error!"
            )

        logger.debug("Proxy response header: %s",
                     proxy_response.headers)

        return proxy_response

    def _replace_host_on_redirect_location(self, request, proxy_response):
        location = proxy_response.headers.get('Location')
        if location:
            if request.is_secure():
                scheme = 'https://'
            else:
                scheme = 'http://'
            request_host = scheme + request.get_host()

            upstream_host_https = 'https://' + self._parsed_url.netloc

            location = location.replace(upstream_host_https, request_host)
            proxy_response.headers['Location'] = location
            logger.debug("Proxy response LOCATION: %s",
                           proxy_response.headers['Location'])

    def dispatch(self, request, *args, **kwargs):
        path = kwargs.get('path')
        redirect_to = self._format_path_to_redirect(request)
        if redirect_to:
            return redirect(redirect_to)

        request_ip = self.request.META.get(
            'X-Forwarded-For',
            self.request.META.get('REMOTE_ADDR', None)
        )

        if self.store_in_db:
            extra_salt = None
            if self.cache_responses == 'per_ip':
                extra_salt = request_ip

            request_hash = self.get_request_hash(extra_salt=extra_salt)

            try:
                proxy_response_object = CachedResponse.objects.get(
                    request_md5=request_hash
                )
                logger.debug("💸 CACHE HIT!!")
                proxy_response = proxy_response_object.response

            except CachedResponse.DoesNotExist:
                logger.debug("🍟 CACHE MISS!")
                started = timezone.now()
                proxy_response = self.fetch_from_proxy(request, path)
                response_time = timezone.now() - started
                try:
                    proxy_response_object = CachedResponse.objects.create(
                        request_md5=request_hash,
                        request_ip=request_ip,
                        request=self.request,
                        response=proxy_response,
                        response_time=response_time,
                    )

                except Exception as e:
                    logger.exception(e)
                    pass

            else:
                proxy_response = self.fetch_from_proxy(request, path)
        else:
            proxy_response = self.fetch_from_proxy(request, path)

        response = self.modified_proxy_response(request, proxy_response)

        logger.debug("RESPONSE RETURNED: %s", response)

        return response

    def modified_proxy_response(self, request, proxy_response):
        self._replace_host_on_redirect_location(request, proxy_response)

        response = get_django_response(proxy_response,
                                       strict_cookies=self.strict_cookies,
                                       streaming_amount=self.streaming_amount)

        return response

    def get_request_hash(self, extra_salt=''):
        if self.request.method == 'POST':
            return None

        body_hash = ""
        if self.request.body:
            body_hash = hashlib.md5(self.request.body.body).hexdigest()

        if not extra_salt:
            extra_salt = 'revproxy'

        query_string = self.request.META.get('QUERY_STRING', "")
        data_to_hash = [
            extra_salt,
            self.request.path,
            query_string,
            body_hash,
        ]

        # only consider headers in self.headers_to_hash
        for h, k in self.request.headers.items():
            if h in self.headers_to_hash:
                data_to_hash.append(f"{h}:{k}")

        d = ''.join(data_to_hash)
        return hashlib.md5(d.encode()).hexdigest()
