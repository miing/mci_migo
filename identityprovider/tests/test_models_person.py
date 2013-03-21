# Copyright 2010 Canonical Ltd.  This software is licensed under the
# GNU Affero General Public License version 3 (see the file LICENSE).
from random import randint

from identityprovider.models.account import Account, LPOpenIdIdentifier
from identityprovider.models.const import (
    AccountCreationRationale,
    AccountStatus,
)
from identityprovider.models.person import Person
from identityprovider.models.team import TeamParticipation
from identityprovider.tests.utils import SSOBaseTestCase


class PersonTestCase(SSOBaseTestCase):

    def setUp(self):
        super(PersonTestCase, self).setUp()
        lp_account = randint(100, 10000)
        LPOpenIdIdentifier.objects.create(identifier='oid',
                                          lp_account=lp_account)
        self.person1 = Person.objects.create(
            displayname='Person', name='person', lp_account=lp_account)
        self.person2 = Person.objects.create(displayname='Other', name='other')
        self.team1 = Person.objects.create(name='team',
                                           teamowner=self.person2.id)
        self.team2 = Person.objects.create(name='other-team',
                                           teamowner=self.person1.id)

    def test_unicode(self):
        self.assertEqual(unicode(self.person1), u'Person')

    def test_in_team_no_team(self):
        self.assertFalse(self.person1.in_team('no-team'))

    def test_in_team(self):
        TeamParticipation.objects.create(team=self.team1, person=self.person1)
        self.assertTrue(self.person1.in_team('team'))

    def test_in_team_object(self):
        TeamParticipation.objects.create(team=self.team1, person=self.person1)
        self.assertTrue(self.person1.in_team(self.team1))

    def test_not_in_team(self):
        self.assertFalse(self.person1.in_team('team'))

    def test_in_team_no_teamparticipation_same_owner(self):
        Person.objects.create(name='otherteam', teamowner=self.person1.id)
        self.assertTrue(self.person1.in_team('otherteam'))

    def test_account_when_no_account(self):
        self.assertEqual(self.person1.account, None)

    def test_account_when_account(self):
        account = Account.objects.create(
            creation_rationale=AccountCreationRationale.USER_CREATED,
            status=AccountStatus.ACTIVE, displayname='Person',
            openid_identifier='oid')
        self.assertEqual(self.person1.account, account)
