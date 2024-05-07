#from django.apps import apps
# apps.is_installed('app_name')

from django.conf import settings

class AppSettings(object):
    def __init__(self, prefix):
        self.prefix = prefix

    def _setting(self, name, default):
        from revproxy.utils import get_setting

        return get_setting(self.prefix + name, default)

    #: Store response in databaes
    @property
    def DB_CACHE(self):
        return self._setting("STORE_IN_DB", False)

    @property
    def DEFAULT_AUTO_FIELD(self):
        return self._setting("DEFAULT_AUTO_FIELD", None)

    @property
    def ALLOWED_SCHEMES(self):
        return (
            'http', 'https'
        )

    # Headers that aren't passed in request to upstream
    # to get content uncompressed, remove the Accept-Encoding
    @property
    def IGNORE_HEADERS(self):
        return (
            'HTTP_ACCEPT_ENCODING',
            'HTTP_HOST',
            'HTTP_REMOTE_USER',
        )

    # Default from HTTP RFC 2616
    #   See: http://www.w3.org/Protocols/rfc2616/rfc2616-sec3.html#sec3.7.1
    #: Variable that represent the default charset used
    @property
    def DEFAULT_CHARSET(self):
        return 'latin-1'

    @property
    def DEFAULT_CONTENT_TYPE(self):
        return 'application/octet-stream'

    #: List containing string constants that represents possible html content type
    @property
    def HTML_CONTENT_TYPES(self):
        return (
            'text/html',
            'application/xhtml+xml',
        )

    @property
    def STREAM_CONTENT_TYPES(self):
        return (
            'text/event-stream',
        )

    @property
    #: Minimal content size required for response to be turned into stream
    def MIN_STREAMING_LENGTH(self):
        return 4 * 1024  # 4KB

    @property
    #: Enable httplib level debugging!
    def DEBUG_HTTP(self):
        return False


_app_settings = AppSettings("REVPROXY_")


def __getattr__(name):
    # See https://peps.python.org/pep-0562/
    return getattr(_app_settings, name)
