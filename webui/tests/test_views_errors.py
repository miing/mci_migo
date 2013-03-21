from django.conf import settings
from django.test import TestCase
from django.test.client import RequestFactory
from mock import patch

from webui.views.errors import server_error


class ErrorViewTestCase(TestCase):

    def test_error_show_sentry_id(self):
        sentry_id = 12345

        with patch.multiple(settings, DEBUG=True):
            request = RequestFactory().get('/error/500/')
            request.sentry = {'id': sentry_id}
            request.session = {}

            response = server_error(request)
            self.assertContains(
                response, "Sentry <abbr>ID</abbr>: %s" % sentry_id,
                status_code=500)
