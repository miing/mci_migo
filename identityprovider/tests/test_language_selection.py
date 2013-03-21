from identityprovider.tests.utils import SSOBaseTestCase


class SelectLanguagePageTestCase(SSOBaseTestCase):

    def setUp(self):
        super(SelectLanguagePageTestCase, self).setUp()

        self.client.login(username='mark@example.com', password='test')

    def test_link_for_language_choosing_is_displayed_on_main_page(self):
        r = self.client.get('/')
        self.assertContains(r, 'id="language_footer"')

    def test_link_for_language_choosing_is_not_diplayed_on_language_page(self):
        r = self.client.get('/set_language')
        self.assertNotContains(r, 'id="language_footer"')
