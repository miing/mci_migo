from __future__ import absolute_import
import re

from gargoyle import gargoyle
from gargoyle.builtins import ModelConditionSet, RequestConditionSet
from gargoyle.conditions import String, Field

from identityprovider.models.account import Account
from identityprovider.models.const import EmailStatus
from identityprovider.models.team import TeamParticipation


class Team(String):
    def is_active(self, condition, value):
        return condition in value


class LPTeamConditionSet(ModelConditionSet):
    team = Team()

    def get_namespace(self):
        return 'lp_team'

    def get_group_label(self):
        return 'LP Team'

    def can_execute(self, instance):
        return isinstance(instance, Account)

    def get_field_value(self, instance, field_name):
        teams = []
        if field_name == 'team':
            if instance.person is not None:
                ts = TeamParticipation.objects.filter(person=instance.person)
                teams = [p.team.name for p in ts]
        return teams


class Regex(Field):
    def is_active(self, condition, value):
        if value is None:
            return False
        if isinstance(value, basestring):
            match = re.match(condition, value)
            return match is not None
        matches = [re.match(condition, v) for v in value]
        return any(matches)


class AccountConditionSet(ModelConditionSet):
    email = Regex(label="Email address")

    def get_field_value(self, instance, field_name):
        if field_name == 'email':
            emails = instance.emailaddress_set.filter(
                status__in=[EmailStatus.NEW, EmailStatus.VALIDATED,
                            EmailStatus.PREFERRED])
            return [email.email for email in emails]
        return super(AccountConditionSet, self).get_field_value(
            instance, field_name)


class RequestDataConditionSet(RequestConditionSet):
    email = Regex(label="Email address")

    def get_namespace(self):
        return 'request'

    def get_group_label(self):
        return 'Request'

    def get_field_value(self, instance, field_name):
        if field_name == 'email':
            return instance.REQUEST.get('email')


gargoyle.register(LPTeamConditionSet(Account))
gargoyle.register(AccountConditionSet(Account))
gargoyle.register(RequestDataConditionSet)
