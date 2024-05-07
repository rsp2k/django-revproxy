import hashlib
import mimetypes
import os
import re
import logging

import requests
from django.http import HttpResponseServerError
from django.utils import timezone
from django.utils.functional import cached_property

from revproxy.models import CachedResponse
from .utils import required_header

try:
    from django.utils.six.moves.urllib.parse import urlparse
except ImportError:
    # Django 3 has no six
    from urllib.parse import urlparse, quote_plus

from django.shortcuts import redirect
from django.views.generic import View
from django.utils.decorators import classonlymethod

from ipware import get_client_ip

from .exceptions import InvalidUpstream
from .response import get_django_response



logger = logging.getLogger(__name__)

from revproxy import app_settings as revproxy_app_settings

ERRORS_MESSAGES = {
    'upstream-no-scheme': ()
}


class ProxyView(View):
    """
    View responsible by execute proxy requests, process and return
    their responses.

    """
    _upstream = None

    # Store request and server response in the database
    db_cache = revproxy_app_settings.DB_CACHE

    # List of strings to consider in request hash for caching
    headers_to_hash = []

    add_x_forwarded = False
    add_remote_user = False

    #: Do not send any body contents if it is empty (put ``None`` into the ``urlopen()``
    #: call).  This is required when proxying to Shiny apps, for example.
    suppress_empty_body = False

    _rewrite_compiled = []

    request = None

    def __init__(self, *args, **kwargs):
#        self.rewrite = kwargs.pop('rewrite', [])
#        self.db_cache = kwargs.pop('db_cache', False)
#        self.cache_responses = kwargs.pop('cache_responses', False)
#        self.headers_to_hash = kwargs.pop('headers_to_hash', [])

        super().__init__(*args, **kwargs)

        if hasattr(self, 'rewrite'):
            # Take all elements inside tuple, and insert into _rewrite
            for from_pattern, to_pattern in self.rewrite:
                from_re = re.compile(from_pattern)
                self._rewrite_compiled.append((from_re, to_pattern))

    @property
    def request_ip(self):
        ip, routable = get_client_ip(self.request)
        return ip

    @property
    def upstream(self):
        if not self._upstream:
            raise NotImplementedError('Upstream server must be set')
        return self._upstream

    @upstream.setter
    def upstream(self, value):
        self._upstream = value

    def get_upstream(self):
        upstream = self.upstream

        if not getattr(self, '_parsed_url', None):
            self._parsed_url = urlparse(upstream)

        if self._parsed_url.scheme not in revproxy_app_settings.ALLOWED_SCHEMES:
            raise InvalidUpstream(f"Upstream URL scheme must be one of {revproxy_app_settings.ALLOWED_SCHEMES}")

        path = self.request.path
        if path.startswith("/"):
            path = path[1:]

        fetchpath = os.path.join(upstream, path)

        return fetchpath

    def _format_path_to_redirect(self):
        full_path = self.request.get_full_path()
        for from_re, to_pattern in self._rewrite_compiled:
            if from_re.match(full_path):
                redirect_to = from_re.sub(to_pattern, full_path)
                return redirect_to
        return None

    @cached_property
    def upstream_request_headers(self):
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

        headers = {}

        for header, value in self.request.META.items():
            if required_header(header):
                norm_header = header.replace('HTTP_', '').title().replace('_', '-')
                headers[norm_header] = value

        if self.add_remote_user:
            logger.debug(f"self.add_remote_user set, checking for authed user")
            if hasattr(self.request, 'user'):
                if self.request.user.is_active:
                    headers['REMOTE_USER'] = self.request.user.email
                    logger.info(f"REMOTE_USER set to {self.request.user.email}")
            else:
                pass

        if self.add_x_forwarded:
            logger.debug(f"Adding X-Forwarded-For: {self.request_ip}")
            headers['X-Forwarded-For'] = self.request_ip

            request_proto = "https" if self.request.is_secure() else "http"
            logger.debug(f"Adding X-Forwarded-Proto: {request_proto}")
            headers['X-Forwarded-Proto'] = request_proto

        return headers

    def fetch_from_proxy(self):
        request_url = self.get_upstream()

        request_payload = self.request.body
        if self.suppress_empty_body and not request_payload:
            logger.debug("Suppressing empty body!")
            request_payload = None

        logger.debug(f"Request headers: {self.upstream_request_headers}")

        fetch = getattr(requests, self.request.method.lower())
        logger.debug(f"Using {fetch} to get {request_url}")

        if revproxy_app_settings.DEBUG_HTTP:
            try:
                import http.client as http_client
            except ImportError:
                # Python 2
                import httplib as http_client
            http_client.HTTPConnection.debuglevel = 1

        try:
            proxy_response = fetch(
                url=request_url,
                params=self.request.GET,
                allow_redirects=False,
                headers=self.upstream_request_headers,
                data=request_payload,
                stream=True,
            )

            content_type = None
            if 'Content-Type' not in proxy_response.headers:
                filename = os.path.basename(self.request.path)
                if len(filename) > 3:
                    logger.debug(f"Guessing mimetime from {filename}")
                    content_type, encoding = mimetypes.guess_type(
                        filename
                    )
                if not content_type:
                    logger.debug(f"No MIME type found for {filename}, defaulting to {revproxy_app_settings.DEFAULT_CONTENT_TYPE}")
                    content_type = revproxy_app_settings.DEFAULT_CONTENT_TYPE
                else:
                    logger.debug(f"Guessed content type of {content_type}")

                proxy_response.headers['Content-Type'] = content_type

        except requests.exceptions.SSLError as error:
            logger.exception(error)
            raise InvalidUpstream(
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
                "Unknown request error!"
            )
        except Exception as error:
            logger.exception(error)
            return HttpResponseServerError(
                "Something went terribly wrong!"
            )

        return proxy_response

    def _replace_host_on_redirect_location(self, proxy_response):
        location = proxy_response.headers.get('Location')
        if location:
            if self.request.is_secure():
                scheme = 'https://'
            else:
                scheme = 'http://'
            request_host = scheme + self.request.get_host()

            upstream_host_https = 'https://' + self._parsed_url.netloc

            location = location.replace(upstream_host_https, request_host)
            proxy_response.headers['Location'] = location
            logger.debug("Proxy response LOCATION: %s",
                           proxy_response.headers['Location'])
        return proxy_response

    def dispatch(self, request, *args, **kwargs):
        path = kwargs.get('path', request.path)

        self.request = request

        redirect_to = self._format_path_to_redirect()
        if redirect_to:
            return redirect(redirect_to)

        if not self.db_cache:
            upstream_response = self.fetch_from_proxy()
        else:
            extra_salt = None
#            if self.cache_responses == 'per_ip':
#                extra_salt = self.request_ip

            request_hash = self.get_request_hash(extra_salt=extra_salt)

            upstream_response_object = CachedResponse.objects.valid_cache_responses(request_hash).first()
            if upstream_response_object:
                logger.debug(f"💸 CACHE HIT!! {upstream_response_object}")
                upstream_response = upstream_response_object.response
            else:
                logger.debug("🍟 CACHE MISS!")
                started = timezone.now()

                upstream_response = self.fetch_from_proxy()

                logger.debug(upstream_response)

                response_time = timezone.now() - started

                try:
                    upstream_response_object = CachedResponse.objects.create(
                        request_md5=request_hash,
                        request_ip=self.request_ip,
                        request=self.request,
                        response=upstream_response,
                        response_time=response_time,
                    )
                except Exception as error:
                    logger.exception(error)
#                    raise

        response = self.modified_proxy_response(upstream_response)
        response = get_django_response(response)
        return response

    def modified_proxy_response(self, proxy_response):
        response = self._replace_host_on_redirect_location(proxy_response)
        return response

    def get_request_hash(self, extra_salt=''):
        if self.request.method == 'POST':
            return None

        body_hash = ""
        if self.request.body:
            body_hash = hashlib.md5(self.request.body).hexdigest()

        if not extra_salt:
            extra_salt = 'revproxy'

        query_string = self.request.META.get('QUERY_STRING', "")
        data_to_hash = [
            self.request.method,
            extra_salt,
            self.request.path,
            query_string,
            body_hash,
        ]

        # only consider headers in self.headers_to_hash
        for header_name in self.headers_to_hash:
            if header_name in self.request.headers:
                data_to_hash.append(f"{header_name}:{self.request.headers[header_name]}")
        else:
            logger.debug(f"Not adding any headers to request hash because {self.__class__.__name__}.headers_to_hash is empty")

        d = ''.join(data_to_hash)
        request_hash = hashlib.md5(d.encode()).hexdigest()
        logger.debug(f"Request hash is {request_hash}")
        return request_hash

    @classonlymethod
    def as_view(cls, *args, **kwargs):
        """
        Disable CSRF Checks!
        """
        view = super(ProxyView, cls).as_view(*args, **kwargs)
        view.csrf_exempt = True
        return view
