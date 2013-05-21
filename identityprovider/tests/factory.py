from itertools import count

from identityprovider.const import (
    PERSON_VISIBILITY_PUBLIC,
    PERSON_VISIBILITY_PRIVATE_MEMBERSHIP,
)
from identityprovider.models import (
    Account,
    AuthToken,
    APIUser,
    AuthenticationDevice,
    EmailAddress,
    LPOpenIdIdentifier,
    Person,
    TeamParticipation,
)
from identityprovider.models.const import EmailStatus, TokenType
from identityprovider.tests import (
    DEFAULT_API_PASSWORD,
    DEFAULT_USER_PASSWORD,
)


class SSOObjectFactory(object):
    """A factory for creating model objects for tests."""

    def __init__(self):
        super(SSOObjectFactory, self).__init__()
        self.counter = count()

    def get_unique_string(self, prefix=None):
        if prefix is None:
            prefix = "generic-string"
        return prefix + str(self.get_unique_integer())

    def get_unique_integer(self):
        """Return a unique integer for the test run."""
        return self.counter.next()

    def make_apiuser(self, username=None, password=DEFAULT_API_PASSWORD):
        if username is None:
            username = self.get_unique_string(prefix='apiuser-')
        user, created = APIUser.objects.get_or_create(username=username)
        user.set_password(password)
        user.save()
        return user

    def make_account(self, displayname=None, email=None,
                     password=DEFAULT_USER_PASSWORD,
                     creation_rationale=None, salt=None,
                     password_encrypted=False, email_validated=True,
                     openid_identifier=None, status=None, date_created=None,
                     teams=None):
        if displayname is None:
            displayname = self.get_unique_string(prefix='Test Account ')
        if email is None:
            email = self.make_email_address()
        account = Account.objects.create_account(
            displayname, email, password=password,
            creation_rationale=creation_rationale,
            salt=salt,
            password_encrypted=password_encrypted,
            email_validated=email_validated,
            openid_identifier=openid_identifier,
        )
        if status is not None:
            account.status = status
        if date_created is not None:
            account.date_created = date_created

        account.save()

        if teams:
            for t in teams:
                team = Person.objects.filter(name=t)
                if len(team) > 0:
                    team = team[0]
                else:
                    team = self.make_team(t)
                self.add_account_to_team(account, team)

        return account

    def make_account_token(self, account, email=None):
        if email is None:
            email = account.preferredemail
        token = self.make_authtoken(
            requester=account, requester_email=email, email=email,
            token_type=TokenType.NEWPERSONLESSACCOUNT)
        return token

    def make_person(self, name=None, displayname=None, account=None):
        if name is None:
            name = self.get_unique_string(prefix='person-')
        if displayname is None:
            displayname = self.get_unique_string(prefix='Person ')
        lp_account = None
        if account is not None:
            lp_account = account.id

        person = Person.objects.create(name=name, displayname=displayname,
                                       lp_account=lp_account)
        if lp_account is not None:
            LPOpenIdIdentifier.objects.create(
                identifier=account.openid_identifier,
                lp_account=lp_account)
        return person

    def make_team(self, name=None, private=False, owner=None):
        if private:
            visibility = PERSON_VISIBILITY_PRIVATE_MEMBERSHIP
        else:
            visibility = PERSON_VISIBILITY_PUBLIC
        if owner is None:
            owner = self.make_person()
        if name is None:
            name = self.get_unique_string(prefix='team-')
        displayname = 'Team ' + name
        team = self.make_person(name, displayname=displayname)
        team.visibility = visibility
        team.teamowner = owner
        team.save()
        return team

    def add_account_to_team(self, account, team):
        if account.person is None:
            self.make_person(account=account)
        elif account.person.in_team(team.name):
            return
        TeamParticipation.objects.create(person=account.person, team=team)

    def make_email_address(self, prefix='email-', domain='example.com'):
        return "%s@%s" % (self.get_unique_string(prefix=prefix), domain)

    def make_email_for_account(self, account, email=None, status=None):
        if email is None:
            email = self.make_email_address()

        if status is None:
            status = EmailStatus.VALIDATED
        elif status is EmailStatus.PREFERRED:
            # make sure there is no other preferred email address
            # or reset it if there is
            account_emails = EmailAddress.objects.filter(account=account,
                                                         status=status)
            account_emails.update(status=EmailStatus.VALIDATED)

        email, _ = EmailAddress.objects.get_or_create(
            email=email, defaults={'account': account, 'status': status})
        if status == EmailStatus.PREFERRED:
            account.preferredemail = email
        return email

    def make_device(self, account, name='MyDevice', key=None):
        if key is None:
            key = ''
        device = AuthenticationDevice.objects.create(
            account=account, name=name, key=key)
        return device

    def make_oauth_token(self, account=None, token_name=None):
        """Create a new set of OAuth token and consumer creds."""
        if account is None:
            account = self.make_account()
        if token_name is None:
            token_name = self.get_unique_string(prefix='token-name')
        return account.create_oauth_token(token_name)

    def make_authtoken(self, token_type=None, email=None, redirection_url=None,
                       displayname=None, password=None, requester=None,
                       requester_email=None):
        if token_type is None:
            token_type = TokenType.NEWPERSONLESSACCOUNT
        token = AuthToken.objects.create(
            token_type=token_type, email=email,
            redirection_url=redirection_url, displayname=displayname,
            password=password, requester=requester,
            requester_email=requester_email)
        return token
