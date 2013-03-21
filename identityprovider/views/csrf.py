from django.shortcuts import render_to_response
from django.template import RequestContext


def csrf_failure(request, reason=""):
    response = render_to_response("403-csrf.html",
                                  RequestContext(request))
    response.status_code = 403
    return response
