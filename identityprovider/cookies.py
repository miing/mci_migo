def set_test_cookie(response):
    """Adds the test cookie to the response.  Returns the response for
    convenient chaining."""
    response.set_cookie('C', '1')
    return response


def test_cookie_worked(request):
    return request.COOKIES.get('C') == '1'
