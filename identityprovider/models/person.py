# Copyright 2010 Canonical Ltd.  This software is licensed under the
# GNU Affero General Public License version 3 (see the file LICENSE).

from django.db import models

from identityprovider.models import Account, LPOpenIdIdentifier
from identityprovider.models.const import AccountCreationRationale

__all__ = (
    'Person',
)


class Person(models.Model):
    displayname = models.TextField(null=True, blank=True)
    teamowner = models.IntegerField(db_column='teamowner',
                                    null=True, blank=True)
    teamdescription = models.TextField(null=True, blank=True)
    name = models.TextField(unique=True, null=True)
    language = models.IntegerField(
        db_column='language', null=True, blank=True)
    fti = models.TextField(null=True)
    defaultmembershipperiod = models.IntegerField(null=True, blank=True)
    defaultrenewalperiod = models.IntegerField(null=True, blank=True)
    subscriptionpolicy = models.IntegerField(default=1, null=True)
    merged = models.IntegerField(db_column='merged',
                                 null=True, blank=True)
    datecreated = models.DateTimeField(auto_now_add=True, null=True)
    addressline1 = models.TextField(null=True, blank=True)
    addressline2 = models.TextField(null=True, blank=True)
    organization = models.TextField(null=True, blank=True)
    city = models.TextField(null=True, blank=True)
    province = models.TextField(null=True, blank=True)
    country = models.IntegerField(
        db_column='country', null=True, blank=True)
    postcode = models.TextField(null=True, blank=True)
    phone = models.TextField(null=True, blank=True)
    homepage_content = models.TextField(null=True, blank=True)
    icon = models.IntegerField(db_column='icon',
                               null=True, blank=True)
    mugshot = models.IntegerField(db_column='mugshot',
                                  null=True, blank=True)
    hide_email_addresses = models.NullBooleanField(default=False)
    creation_rationale = models.IntegerField(
        null=True, blank=True, choices=AccountCreationRationale._get_choices())
    creation_comment = models.TextField(null=True, blank=True)
    registrant = models.IntegerField(db_column='registrant',
                                     null=True, blank=True)
    logo = models.IntegerField(db_column='logo',
                               null=True, blank=True)
    renewal_policy = models.IntegerField(default=10, null=True)
    personal_standing = models.IntegerField(default=0, null=True)
    personal_standing_reason = models.TextField(null=True, blank=True)
    mail_resumption_date = models.DateField(null=True, blank=True)
    mailing_list_auto_subscribe_policy = models.IntegerField(default=1,
                                                             null=True)
    mailing_list_receive_duplicates = models.NullBooleanField(default=True)
    visibility = models.IntegerField(default=1, null=True)
    verbose_bugnotifications = models.NullBooleanField(default=False)
    lp_account = models.IntegerField(null=True, db_column='account',
                                     unique=True)

    class Meta:
        app_label = 'identityprovider'
        db_table = u'lp_person'

    def __unicode__(self):
        return self.displayname

    def in_team(self, team):
        from identityprovider.models import TeamParticipation
        # Just to be fully compatible with
        # lp:lib/registry/model/person.py:Person.inTeam()
        if isinstance(team, (str, unicode)):
            try:
                team = Person.objects.get(name=team)
            except Person.DoesNotExist:
                return False
        try:
            TeamParticipation.objects.get(team=team, person=self)
            return True
        except TeamParticipation.DoesNotExist:
            if self.id == team.teamowner:
                return True
        return False

    @property
    def account(self):
        if self.lp_account is not None:
            open_ids = LPOpenIdIdentifier.objects.filter(
                lp_account=self.lp_account)
            if len(open_ids) > 0:
                openid_identifier = open_ids[0].identifier
                accounts = Account.objects.filter(
                    openid_identifier=openid_identifier)
                if len(accounts) > 0:
                    return accounts[0]

    def is_team(self):
        return self.teamowner is not None

    @property
    def time_zone(self):
        try:
            return self.personlocation.time_zone
        except:
            return None


class PersonLocation(models.Model):
    date_created = models.DateTimeField(null=True)
    person = models.OneToOneField(Person, db_column='person', null=True)
    latitude = models.FloatField(null=True, blank=True)
    longitude = models.FloatField(null=True, blank=True)
    time_zone = models.TextField(null=True, blank=True)
    last_modified_by = models.IntegerField(
        db_column='last_modified_by',
        null=True)
    date_last_modified = models.DateTimeField(null=True)
    visible = models.NullBooleanField(default=True)
    locked = models.NullBooleanField(default=False)

    class Meta:
        app_label = 'identityprovider'
        db_table = u'lp_personlocation'
