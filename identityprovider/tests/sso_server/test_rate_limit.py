from django.conf import settings

from identityprovider.tests.helpers import FunctionalTestCase


class RateLimitTestCase(FunctionalTestCase):

    def test(self):
        # = Rate limits =

        # Rate limiting is enforced only on POST requests to the login screen,
        # on a per-username, per-IP basis.
        # There are two settings that control the rate at which you can submit
        # requests: no more than LOGIN_LIMIT_REQUESTS requests can be submitted
        # every LOGIN_LIMIT_MINUTES minutes.
        #
        # So, first, let's find out how many requests is our limit

        limit = getattr(settings, 'LOGIN_LIMIT_REQUESTS', 20)
        # Now, we should be able to submit the login form so many times without
        # trouble:

        email = 'something@example.com'
        for i in range(limit):
            self.login(email=email, password='wrong')

        # But on the next request, it should fail:

        response = self.login(email=email, password='wrong')
        self.assertContains(response, 'Rate limit exceeded', status_code=403)

        # This shouldn't prevent us from logging in as a different user:

        response = self.login()
        self.assert_home_page(response)
