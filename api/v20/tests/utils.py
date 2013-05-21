from django.test.client import RequestFactory


request_factory = RequestFactory()


def call(method, url, data):
    request = request_factory.post(url, data, content_type='application/json')
    # fake the json deserialisation that piston framework performs
    request.data = data
    response = method(request)
    response._base_content_is_iter = False
    return response, response._container
