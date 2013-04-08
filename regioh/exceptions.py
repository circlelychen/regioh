# -*- coding: utf-8 -*-
from werkzeug.exceptions import default_exceptions, HTTPException
from flask import make_response, abort as flask_abort, request

ERROR_CODE = {
    200: 'success',
    201: 'created',
    202: 'accepted',
    204: 'no_content',
    302: 'redirect',
    304: 'not_modified',
    400: 'bad_request',
    401: 'unauthorized',
    403: 'forbidden',
    404: 'not_found',
    405: 'method_not_allowed',
    409: 'conflict',
    412: 'precondition_failed',
    429: 'took_many_requests',
    500: 'internal_server_error',
    507: 'insufficient_storage',
}

class JSONHTTPException(HTTPException):
    """A base class for HTTP exceptions with ``Content-Type:
    application/json``.

    The ``description`` attribute of this class must set to a string (*not* an
    HTML string) which describes the error.

    """

    def get_body(self, environ):
        """Overrides :meth:`werkzeug.exceptions.HTTPException.get_body` to
        return the description of this error in JSON format instead of HTML.

        """
        from json import dumps
        if type(self.get_description(environ)) is dict:
            return dumps(dict(self.get_description(environ),
                              status=self.code,
                              code=ERROR_CODE.get(self.code, 200)))
        else:
            return dumps(dict(message=self.get_description(environ),
                              status=self.code,
                              code=ERROR_CODE.get(self.code, 200)))

    def get_headers(self, environ):
        """Returns a list of headers including ``Content-Type:
        application/json``.

        """
        return [('Content-Type', 'application/json')]


def abort(status_code, body=None, headers={}):
    """Content negiate the error response.
    ref: http://flask.pocoo.org/snippets/97/
    """

    if 'text/html' in request.headers.get("Accept", ""):
        error_cls = HTTPException
    else:
        error_cls = JSONHTTPException

    class_name = error_cls.__name__
    bases = [error_cls]
    attributes = {'status': status_code}

    if status_code in default_exceptions:
        # Mixin the Werkzeug exception
        bases.insert(0, default_exceptions[status_code])

    error_cls = type(class_name, tuple(bases), attributes)
    flask_abort(make_response(error_cls(body), status_code, headers))
