# Copyright 2010 Canonical Ltd.  This software is licensed under the
# GNU Affero General Public License version 3 (see the file LICENSE).

from identityprovider.const import (
    PERSON_VISIBILITY_PUBLIC,
    PERSON_VISIBILITY_PRIVATE_MEMBERSHIP,
)
from identityprovider.models import (
    Account,
    Person,
    TeamParticipation,
    get_team_memberships_for_user,
)
from identityprovider.tests import DEFAULT_USER_PASSWORD
from identityprovider.tests.utils import SSOBaseTestCase


class TeamParticipationTestCase(SSOBaseTestCase):

    def test_unicode(self):
        team = Person.objects.create(displayname='Team', name='team')
        person = Person.objects.create(displayname='Person', name='person')
        tp = TeamParticipation.objects.create(team=team, person=person)
        self.assertEqual(unicode(tp), u'Person in Team')


class TeamMembershipTest(SSOBaseTestCase):

    fixtures = ["test"]

    def _set_team_to_private_membership(self, team_name):
        self._set_team_privacy(team_name, PERSON_VISIBILITY_PRIVATE_MEMBERSHIP)

    def _set_team_to_public_membership(self, team_name):
        self._set_team_privacy(team_name, PERSON_VISIBILITY_PUBLIC)

    def _set_team_privacy(self, team_name, privacy):
        team = Person.objects.get(name=team_name)
        team.visibility = privacy
        team.save()

    def setUp(self):
        super(TeamMembershipTest, self).setUp()
        self.account = Account.objects.get(pk=1)

    def test_get_team_memberships_on_personless_account(self):
        account = Account.objects.create_account('test', 'x@example.com',
                                                 DEFAULT_USER_PASSWORD)
        memberships = get_team_memberships_for_user(
            ['ubuntu-team'], account, False)
        self.assertEqual(memberships, [])

    def test_get_team_memberships_when_team_is_visible(self):
        memberships = get_team_memberships_for_user(
            ['ubuntu-team'], self.account, False)
        self.assertEqual(memberships, ['ubuntu-team'])

    def test_get_team_membership_when_team_is_not_visible(self):
        self._set_team_to_private_membership('ubuntu-team')
        memberships = get_team_memberships_for_user(
            ['ubuntu-team', 'myteam'], self.account, False)
        self.assertEqual(memberships, [])

    def test_team_is_private_but_you_can_see_them(self):
        self._set_team_to_private_membership('ubuntu-team')
        memberships = get_team_memberships_for_user(
            ['ubuntu-team', 'myteam'], self.account, True)
        self.assertEqual(memberships, ['ubuntu-team'])
