import importlib
import re

import logging
from django.conf import settings

from wsgiref.util import is_hop_by_hop
from revproxy import app_settings as revproxy_app_settings

try:
    from http.cookies import SimpleCookie
    COOKIE_PREFIX = ''
except ImportError:
    from Cookie import SimpleCookie
    COOKIE_PREFIX = 'Set-Cookie: '

logger = logging.getLogger()

#: Regex used to find charset in a html content type
_get_charset_re = re.compile(r';\s*charset=(?P<charset>[^\s;]+)', re.I)

#: Regex used to clean extra HTTP prefixes in headers
_get_header_name_re = re.compile(
    r'((http[-|_])*)(?P<header_name>(http[-|_]).*)',
    re.I,
)

# sadfadsf = settings.ALLOWED_SCHEMES

def should_stream(proxy_response):
    """Function to verify if the proxy_response must be converted into
    a stream.This will be done by checking the proxy_response content-length
    and verify if its length is bigger than one stipulated
    by MIN_STREAMING_LENGTH.

    :param proxy_response: An Instance of urllib3.response.HTTPResponse
    :returns: A boolean stating if the proxy_response should
              be treated as a stream
    """
    content_type = proxy_response.headers.get(
        'Content-Type',
        revproxy_app_settings.DEFAULT_CONTENT_TYPE,
    )

    if content_type in revproxy_app_settings.HTML_CONTENT_TYPES:
        return False

    try:
        content_length = int(proxy_response.headers.get('Content-Length', 0))

    except ValueError:
        content_length = 0

    if not content_length or content_length > revproxy_app_settings.MIN_STREAMING_LENGTH:
        return True

    return False


def get_charset(content_type):
    """Function used to retrieve the charset from a content-type.If there is no
    charset in the content type then the charset defined on DEFAULT_CHARSET
    will be returned

    :param  content_type:   A string containing a Content-Type header
    :returns:               A string containing the charset
    """
    if not content_type:
        return revproxy_app_settings.DEFAULT_CHARSET

    matched = _get_charset_re.search(content_type)
    if matched:
        # Extract the charset and strip its double quotes
        return matched.group('charset').replace('"', '')
    return revproxy_app_settings.DEFAULT_CHARSET


def required_header(header):
    """Function that verify if the header parameter is an essential header

    :param header:  A string represented a header
    :returns:       A boolean value that represent if the header is required
    """
    matched = _get_header_name_re.search(header)

    # Ensure there is only one HTTP prefix in the header
    header_name = matched.group('header_name') if matched else header

    header_name_upper = header_name.upper().replace('-', '_')

    if header_name_upper in revproxy_app_settings.IGNORE_HEADERS:
        return False

    if header_name_upper.startswith('HTTP_') or header == 'CONTENT_TYPE':
        return True

    return False


def filter_response_headers(response, response_headers):
    filtered_headers = {}
    for header, value in response_headers.items():
        if not (is_hop_by_hop(header) or header.lower() == 'set-cookie'):
            filtered_headers[header] = value

    logger.debug(f"Modified response headers: {filtered_headers}")

    return filtered_headers


def encode_items(items):
    """Function that encode all elements in the list of items passed as
    a parameter

    :param items:  A list of tuple
    :returns:      A list of tuple with all items encoded in 'utf-8'
    """
    encoded = []
    for key, values in items:
        for value in values:
            encoded.append((key.encode('utf-8'), value.encode('utf-8')))
    return encoded


def import_attribute(path):
    assert isinstance(path, str)
    pkg, attr = path.rsplit(".", 1)
    ret = getattr(importlib.import_module(pkg), attr)
    return ret


def import_callable(path_or_callable):
    if not hasattr(path_or_callable, "__call__"):
        ret = import_attribute(path_or_callable)
    else:
        ret = path_or_callable
    return ret


def get_setting(name, dflt):
    getter = getattr(
        settings,
        "REVPROXY_SETTING_GETTER",
        lambda name, dflt: getattr(settings, name, dflt),
    )
    getter = import_callable(getter)
    return getter(name, dflt)
