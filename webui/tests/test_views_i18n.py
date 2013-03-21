from identityprovider.models.account import Account
from identityprovider.tests.utils import SSOBaseTestCase
from identityprovider.tests import DEFAULT_USER_PASSWORD


class SetLanguageTestCase(SSOBaseTestCase):

    fixtures = ["test"]

    def setUp(self):
        super(SetLanguageTestCase, self).setUp()
        self.disable_csrf()
        self.addCleanup(self.reset_csrf)

    def test_when_supplying_non_local_next_url_redirects_to_main(self):
        r = self.client.post('/set_language',
                             {'language': 'es', 'next': 'http://example.com'})
        self.assertRedirects(r, '/')

    def test_next_must_be_resolved_to_existing_view(self):
        r = self.client.post('/set_language',
                             {'language': 'es', 'next': '/not-existing'})
        self.assertRedirects(r, '/')

    def test_next_works_for_to_be_resolved_for_existing_view(self):
        r = self.client.post('/set_language',
                             {'language': 'es', 'next': '/+login'})
        self.assertRedirects(r, '/+login')

    def test_not_known_http_method_cases_404(self):
        # Faking client.put method
        r = self.client.get('/set_language', REQUEST_METHOD='PUT')
        self.assertEqual(r.status_code, 404)

    def test_setting_unsupported_language_raises_404(self):
        r = self.client.post('/set_language', {'language': 'xx'})
        self.assertEqual(r.status_code, 404)

    def test_getting_renders_choose_page(self):
        r = self.client.get('/set_language')
        self.assertTemplateUsed(r, 'select_language.html')

    def test_setting_language_for_authenticated_users_updates_db(self):
        self.client.login(username='mark@example.com',
                          password=DEFAULT_USER_PASSWORD)
        self.client.post('/set_language', {'language': 'es', 'next': '/'})

        account = Account.objects.get_by_email('mark@example.com')

        self.assertEqual(account.preferredlanguage, 'es')
