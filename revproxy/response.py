import logging
import pprint as pp

from django.conf import settings
from revproxy import app_settings as revproxy_app_settings

from .utils import should_stream

from django.http import HttpResponse, StreamingHttpResponse

logger = logging.getLogger('revproxy.response')

from wsgiref.util import is_hop_by_hop


def get_django_response(proxy_response):
    """This method is used to create an appropriate response based on the
    Content-Length of the proxy_response. If the content is bigger than
    MIN_STREAMING_LENGTH, which is found on utils.py,
    than django.http.StreamingHttpResponse will be created,
    else a django.http.HTTPResponse will be created instead

    :param proxy_response: An Instance of urllib3.response.HTTPResponse that
                           will create an appropriate response

    :returns: Returns an appropriate response based on the proxy_response
              content-length
    """
    content_type = proxy_response.headers.get('Content-Type')

    if should_stream(proxy_response):
        amt = get_streaming_amt(proxy_response)

        logger.info(('Starting streaming HTTP Response, buffering amount='
                     '"%s bytes"'), amt)

        logger.debug(proxy_response)
        logger.debug(proxy_response.iter_content)
        response = StreamingHttpResponse(
            streaming_content=proxy_response.iter_content(amt),
            status=proxy_response.status_code,
            content_type=content_type,
        )
    else:
        response = HttpResponse(
            content=proxy_response.content,
            status=proxy_response.status_code,
            content_type=content_type,
        )

    logger.debug(f'☢️{response = }\n {proxy_response.headers = }')

    logger.info('Normalizing response headers')
    for header, value in proxy_response.headers.items():
        if not (is_hop_by_hop(header) or header.lower() == 'set-cookie'):
            response.headers[header] = value

    logger.debug(f"!Response Headers: {pp.pformat(response.headers, indent=2)}")

    logger.info('🫙 Cookies')
    for cookie in proxy_response.cookies:
        logger.debug(f'🍪 {cookie = }')
        httponly = cookie.has_nonstandard_attr('httponly')
        response.set_cookie(
            cookie.name,
            value=cookie.value,
            path=cookie.path,
            domain=cookie.domain,
            secure=cookie.secure,
            expires=cookie.expires,
            httponly=httponly,
# Do we need to set these?
# RFC something or other?
#            samesite=,
#            max_age=,
        )
    logger.debug(f"{response.cookies=}")

    return response


# Default number of bytes that are going to be read in a file lecture
DEFAULT_AMT = 2**16
# The amount of chunk being used when no buffering is needed: return every byte
# eagerly, which might be bad in performance perspective, but is essential for
# some special content types, e.g. "text/event-stream". Without disabling
# buffering, all events will pending instead of return in realtime.
NO_BUFFERING_AMT = 1


def get_streaming_amt(proxy_response):
    """Get the value of streaming amount(in bytes) when streaming response

    :param proxy_response: urllib3.response.HTTPResponse object
    """
    content_type = proxy_response.headers.get('content-type', revproxy_app_settings.DEFAULT_CONTENT_TYPE)
    # Disable buffering for "text/event-stream" (or other special types)
    if content_type.lower() in revproxy_app_settings.STREAM_CONTENT_TYPES:
        return NO_BUFFERING_AMT
    return DEFAULT_AMT
