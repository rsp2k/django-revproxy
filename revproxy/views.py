import hashlib
import itertools
import json
import mimetypes
import os
import re
import logging

import pprint as pp
from typing import LiteralString, Never

import requests
from django.conf import settings
from django.http import HttpResponseServerError, HttpResponsePermanentRedirect, HttpResponseRedirect
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

        super().__init__(*args, **kwargs)
        self._compile_rewrite()

    def _compile_rewrite(self) -> Never:
        if hasattr(self, 'rewrite'):
            # Take all elements inside tuple, and insert into _rewrite
            for from_pattern, to_pattern in self.rewrite:
                from_re = re.compile(from_pattern)
                self._rewrite_compiled.append((from_re, to_pattern))

    @cached_property
    def request_ip(self) -> str:
        ip, routable = get_client_ip(self.request)
        return ip

    @property
    def upstream(self) -> str:
        if not self._upstream:
            raise NotImplementedError(f'Upstream server must be set in {self.__class__.__name__} call in urls.py')
        return self._upstream

    @upstream.setter
    def upstream(self, value):
        self._upstream = value

    @cached_property
    def get_upstream(self) -> LiteralString | str | bytes:
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

    def check_path_for_rewrite(self) -> None | str:
        full_path = self.request.get_full_path()
        for from_re, to_pattern in self._rewrite_compiled:
            if from_re.match(full_path):
                redirect_to = from_re.sub(to_pattern, full_path)
        return None

    @cached_property
    def upstream_request_headers(self) -> {str: str}:
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

    def fetch_from_upstream(self) -> requests.Response:
        request_url = self.get_upstream

        request_payload = self.request.body
        if self.suppress_empty_body and not request_payload:
            logger.debug("Suppressing empty body!")
            request_payload = None

        logger.debug(f"Request headers: {pp.pformat(self.upstream_request_headers, indent=2)}")

        fetch = getattr(requests, self.request.method.lower())
        logger.debug(f"Using {fetch} to get {request_url}")

        if revproxy_app_settings.DEBUG_HTTP:
            try:
                import http.client as http_client
            except ImportError:
                # Python 2
                import httplib as http_client
            logger.critical("REVPROXY_DEBUG_HTTP is set. enabling http_client HTTPConnection DEBUG!")
            http_client.HTTPConnection.debuglevel = 1

        proxy_response = fetch(
            url=request_url,
            params=self.request.GET,
            allow_redirects=False,
            headers=self.upstream_request_headers,
            data=request_payload,
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

        return proxy_response

    def _replace_host_on_redirect_location(self, proxy_response):
        logger.debug(proxy_response.headers)
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

    def get_request_hash(self, extra_salt='') -> str | None:
        if self.request.method == 'POST':
            return None

        body_hash = "-"
        if self.request.body:
            body_hash = hashlib.md5(self.request.body).hexdigest()

        if not extra_salt:
            extra_salt = 'revproxy'

        query_string = self.request.META.get('QUERY_STRING')
        if not query_string:
            query_string = "no-query-string"

        data_to_hash = [
            self.request.method,
            extra_salt,
            self.request.path,
            query_string,
            body_hash,
        ]

        logger.debug(f"Request Data to hash: {pp.pformat(data_to_hash)}")

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

    def file_cache_proxy_response(self) -> requests.Response:
        extra_salt = None
        #            if self.cache_responses == 'per_ip':
        #                extra_salt = self.request_ip
        from revproxy.models import response_data_directory_path
        request_hash = self.get_request_hash(extra_salt=extra_salt)
        response_dir = os.path.join(
            settings.MEDIA_ROOT, response_data_directory_path(request_hash)
        )
        r = requests.Response()
        if os.path.isdir(response_dir):
            logger.debug(f"💸 CACHE HIT!! {response_dir}")

            body_file = os.path.join(response_dir, "_body")
            if os.path.isfile(body_file):
                r.raw = open(os.path.join(response_dir, "_body"), "rb")
                r.stream = True

            request_file = os.path.join(response_dir, "_request")
            if os.path.isfile(request_file):
                with open(request_file, "r") as f:
                    json_data = f.read()
                # Update utime for
                os.utime(request_file, None)

            request = json.loads(json_data)
            r.headers = request["headers"]
            r.status_code = request["status_code"]
            r.content_type = request["content_type"]

            return r

        else:
            logger.debug("🍟 CACHE MISS!")

            started = timezone.now()
            upstream_response = self.fetch_from_upstream()
            response_time = timezone.now() - started

            os.makedirs(response_dir)

            with open(os.path.join(response_dir, "_body"), "wb") as f:
                file_iterator, response_iterator = itertools.tee(upstream_response.iter_content())
                f.writelines(file_iterator)

            with open(os.path.join(response_dir, "_request"), "wb") as f:
                json_data = json.dumps({
                    "headers": dict(upstream_response.headers),
                    "status_code": upstream_response.status_code,
                    "content_type": upstream_response.headers.get("Content-Type"),
                })
                f.write(json_data.encode())

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

        return upstream_response

    def dispatch(self, request, *args, **kwargs):
        self.request = request

        redirect_to = self.check_path_for_rewrite()
        if redirect_to:
            return redirect(redirect_to)

        try:
            if not self.db_cache:
                upstream_response = self.fetch_from_upstream()
            else:
                upstream_response = self.file_cache_proxy_response()

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

        response = self.modified_proxy_response(upstream_response)
        response = get_django_response(response)

        return response

    def modified_proxy_response(self, proxy_response):
        response = self._replace_host_on_redirect_location(proxy_response)
        return response

    @classonlymethod
    def as_view(cls, *args, **kwargs):
        """
        Disable CSRF Checks!
        """
        view = super(ProxyView, cls).as_view(*args, **kwargs)
        view.csrf_exempt = True
        return view
