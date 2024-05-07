import logging

logger = logging.getLogger(__name__)


def short_circuit_middleware(f):
    """ view decorator, the sole purpose to is 'rename' the function
    '_shortcircuitmiddleware' """
    def _shortcircuitmiddleware(*args, **kwargs):
        return f(*args, **kwargs)
    return _shortcircuitmiddleware


class ShortCircuitMiddleware:
    """ Middleware; looks for a view function named '_shortcircuitmiddleware'
    and short-circuits. Relies on the fact that if you return an HttpResponse
    from a view, it will short-circuit other middleware, see:
    https://docs.djangoproject.com/en/dev/topics/http/middleware/#process-request
     """

    def __init__(self, get_response):
        self.get_response = get_response
        # One-time configuration and initialization.

    def __call__(self, request):
        # Code to be executed for each request before
        # the view (and later middleware) are called.

        response = self.get_response(request)

        # Code to be executed for each request/response after
        # the view is called.

        return response

    def process_view(self, request, view_func, view_args, view_kwargs):
        if view_func.__name__ == "_short_circuit_middleware":
            logger.debug("SHORT CIRCUIT MIDDLEWARE!")
            return view_func(request, *view_args, **view_kwargs)
        return None
