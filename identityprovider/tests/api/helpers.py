import quopri
import re

from u1testutils import mail


class EmailScraper(object):

    def __init__(self):
        self.account_verification_link = None

    def get_account_validation_link(self, email_address):
        if self.account_verification_link is None:
            self.account_verification_link = self.get_verification_link(
                email_address)
        return self.account_verification_link

    def _get_verification_data(self, email_address):
        """A private helper for public helpers below.

        Note: We have two different public helpers here for verification
        code and link so that functional tests don't need to deal with
        idioms like:
            vcode, ignored = get_verification_for_address(email_address).
        """
        email_msg = mail.get_latest_email_sent_to(email_address)
        vcode = link = None
        if email_msg:
            # The body is encoded as quoted-printable. This affects any line
            # longer than a certain length.  Decode now to not have to worry
            # about it in the regexen.
            body = quopri.decodestring(email_msg.get_payload())
            # get code
            match = re.search(
                '(Here is your confirmation code:|Copy and paste the '
                'confirmation code below into the desktop application.)'
                '(.*?)(Enter|If you made|If you don)',
                body, re.S)
            if match:
                vcode = match.group(2).strip()
            else:
                vcode = None
            # get link
            match = re.search(
                'confirm your (?:account|email address|reset):(.*)If',
                body, re.S)
            link = None
            if match:
                link = match.group(1).strip()
        return vcode, link

    def get_verification_link(self, email_address):
        vcode, link = self._get_verification_data(email_address)
        return link
