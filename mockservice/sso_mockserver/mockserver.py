# Copyright 2010 Canonical Ltd.  This software is licensed under the
# GNU Affero General Public License version 3 (see the file LICENSE).

from wsgiref.simple_server import make_server
import os
import re
import urlparse
from django.utils import simplejson as json
from random import choice
import string

jsons = {
    '':  '{"registrations_collection_link": "%(svc_root)s/registration", "captchas_collection_link": "%(svc_root)s/captchas", "validations_collection_link": "%(svc_root)s/validation", "authentications_collection_link": "%(svc_root)s/authentications", "resource_type_link": "%(svc_root)s/#service-root", "accounts_collection_link": "%(svc_root)s/accounts"}',
    'captchas': '{"total_size": 0, "start": null, "resource_type_link": "%(svc_root)s/#captchas", "entries": []}',
    'registration': '{"total_size": 0, "start": null, "resource_type_link": "%(svc_root)s/#registrations", "entries": []}',
    'new captcha': '{"image_url": "https://api-secure.recaptcha.net/image?c=02x85ZN7gXtZK0CKOvQtIRGGTW7_FzkhFoMUo3nEIR1DYb4mvimchw4BbvMTohrXV3tnFvdsblhUVK4ECpYjb6fUx3V1Ve29Wpg8AY1eWsEUY4CkZTSMFKCCcKkpMDo42ivD-qc0vp8Hdp7CswD7xpq5ncL3qSOtezClUl-Mbhk-7YFdzmtBYsmqrCvTMGHHI5gtgwVwh8X1w65R6tgOzlfU7zUYhPAiwSALp7z_auU6bVPRSQBsJC_JHuFzLiHOm1l9U7Cyf0iKxhvMvf6BwaPePUYZ8B", "captcha_id": "02x85ZN7gXtZK0CKOvQtIRGGTW7_FzkhFoMUo3nEIR1DYb4mvimchw4BbvMTohrXV3tnFvdsblhUVK4ECpYjb6fUx3V1Ve29Wpg8AY1eWsEUY4CkZTSMFKCCcKkpMDo42ivD-qc0vp8Hdp7CswD7xpq5ncL3qSOtezClUl-Mbhk-7YFdzmtBYsmqrCvTMGHHI5gtgwVwh8X1w65R6tgOzlfU7zUYhPAiwSALp7z_auU6bVPRSQBsJC_JHuFzLiHOm1l9U7Cyf0iKxhvMvf6BwaPePUYZ8B"}',
    'register_error':  '{"password": ["Password must be at least 8 characters long."], "email": ["Enter a valid e-mail address."]}',
    'registration': '{"total_size": 0, "start": null, "resource_type_link": "%(svc_root)s/#authentications", "entries": []}',
    'accounts': '{"username": "username", "preferred_email": null, "displayname": "Blu Bli", "unverified_emails": ["blu@bli.com"], "verified_emails": [], "openid_identifier": "openid_identifier"}',
    'verified_accounts': '{"username": "username", "preferred_email": "blu@bli.com", "displayname": "Blu Bli", "unverified_emails": [], "verified_emails": [], "openid_identifier": "openid_identifier"}',
    'validated email': '{"email": "blu@bli.com"}',
    'bad email token': '{"errors": {"email_token": ["Bad email token!"]}}',
    'team_memberships': '[]',
    'password reset token': '{"status": "ok", "message": "Password reset token sent."}',
    'set new password': '{"status": "ok", "message": "Password changed"}'
}

email_re = re.compile(
    r"(^[-!#$%&'*+/=?^_`{}|~0-9A-Z]+(\.[-!#$%&'*+/=?^_`{}|~0-9A-Z]+)*"  # dot-atom
    r'|^"([\001-\010\013\014\016-\037!#-\[\]-\177]|\\[\001-011\013\014\016-\177])*"'  # quoted-string
    r')@(?:[A-Z0-9](?:[A-Z0-9-]{0,61}[A-Z0-9])?\.)+[A-Z]{2,6}\.?$', re.IGNORECASE)  # domain

server_users = [('MyUsername', 'password')]

tokens = {}


def new_token(name, token=None):
    def nonsense(n):
        return ''.join(choice(string.letters) for x in range(n))
    consumer_secret = nonsense(30)
    if token is None:
        token = nonsense(50)
    consumer_key = 'name12_oid'
    token_secret = nonsense(50)
    # The test expects the keys to be in a certain order!
    tokenjson = ('{"consumer_secret": "%s", "token": "%s", '
                 '"consumer_key": "%s", "name": "%s", "token_secret": "%s"}'
                 % (consumer_secret, token, consumer_key, name, token_secret))
    tokens[token] = json.loads(tokenjson)
    return tokenjson


def password_policy_compliant(password):
    if len(password) < 8:
        return False
    has_upper = False
    has_number = False
    has_punctuation = False
    if re.search(r'[A-Z]', password):
        has_upper = True
    if re.search(r'[0-9]', password):
        has_number = True
    if re.search('[\.\?\!\,\-\_\[\]\(\)"#$%&\'\*\+/:;\<\>=\^`\{\}\|~ ]', password):
        has_punctuation = True
    return ((int(has_upper) + int(has_number) + int(has_punctuation)) >= 2)

password_policy_violation = "Password must be at least 8 characters long."

def validate_new_account_form(email, password, captcha_id, captcha_solution, displayname=''):
    errors = {}
    if not email_re.match(email):
        errors['email'] = ["Enter a valid e-mail address."]
    if not password_policy_compliant(password):
        errors['password'] = [password_policy_violation]
    if errors:
        result = {'status': 'error', 'errors': errors}
    else:
        result = {
            'status': 'ok',
            'message': "Email verification required."
        }
    return result

def validate_new_password(new_password):
    if not password_policy_compliant(new_password):
        return {u'status': u'error', u'errors': [password_policy_violation]}
    else:
        return {u'status': u'ok', u'message': u'Password changed'}


class MockSSOServer(object):
    def __init__(self, host, port, api_root, scheme='http'):
        self.api_root = api_root
        defaultports = {'http': 80, 'https': 443}
        portstring = ''
        if port != defaultports.get(scheme):
            portstring = ':%s' % port
        self.service_root = '%s://%s%s%s' % (scheme, host, portstring,
                                             api_root)

    def __call__(self, environ, start_response):
        self.environ = environ
        self.start_response = start_response

        accepted = [x.strip()
                    for x in environ.get('HTTP_ACCEPT', '').split(',')]
        if ('application/vd.sun.wadl+xml' in accepted or
            'application/vnd.sun.wadl+xml' in accepted):
            if environ['PATH_INFO'] == self.api_root:
                f = open(os.path.join(os.path.dirname(__file__), 'wadl.xml'))
                self.success()
                return [f.read().replace('@@SERVICE_ROOT@@',
                                         self.service_root)]
        elif 'application/json' in accepted:
            if environ['PATH_INFO'].startswith(self.api_root):
                path = environ['PATH_INFO'][len(self.api_root) + 1:]
                if hasattr(self, 'handle_' + path):
                    return getattr(self, 'handle_' + path)()
                elif path in jsons:
                    return self.jsons(path)
        self.fail404()
        return []

    def decode_form(self, encoded_form):
        def strip(k, v):
            if k == 'ws.op':
                return k, v
            else:
                return k, v[1:-1]
        form = urlparse.parse_qs(encoded_form)
        form = dict(strip(k, v[0]) for k, v in form.items())

        return form

    def success(self, content_type='text/plain'):
        status = '200 OK'
        headers = [('Content-type', content_type)]
        self.start_response(status, headers)
        return

    def fail404(self):
        status = '404 Not found'
        headers = [('Content-type', 'text/plain')]
        self.start_response(status, headers)
        return

    def fail403(self):
        status = '403 FORBIDDEN'
        headers = [('Content-type', 'text/plain')]
        self.start_response(status, headers)
        return

    def fail401(self, extra_headers=None):
        status = '401 Unauthorized'
        headers = [('Content-type', 'text/plain')]
        if extra_headers is not None:
            headers += extra_headers
        self.start_response(status, headers)
        return

    def fail400(self):
        status = '400 Bad Request'
        headers = [('Content-type', 'application/json')]
        self.start_response(status, headers)
        return

    def jsons(self, jsonid=None, json=None):
        self.success(content_type='application/json')
        if json is None:
            json = jsons[jsonid] % {'svc_root': self.service_root}
        return json

    def check_server_user(self):
        header = self.environ['HTTP_AUTHORIZATION']
        userpwd = header.split(' ')[-1].decode('base64')
        user, password = userpwd.split(':')
        if not (user, password) in server_users:
            self.fail403()
            return False
        return True

    def check_plain_user(self):
        header = self.environ['HTTP_AUTHORIZATION']
        userpwd = header.split(' ')[-1].decode('base64')
        user, password = userpwd.split(':')
        if (user, password) in server_users:
            self.fail403()
            return False
        return True

    def handle_captchas(self):
        if self.environ['REQUEST_METHOD'] == 'GET':
            return self.jsons('captchas')
        else:
            return self.jsons('new captcha')

    def handle_registration(self):
        if self.environ['REQUEST_METHOD'] == 'GET':
            return self.jsons('captchas')
        else:
            clength = int(self.environ['CONTENT_LENGTH'])
            input = self.environ['wsgi.input'].read(clength)
            form = self.decode_form(input)
            if 'ws.op' in form:
                op = form['ws.op']
                if op == 'register':
                    form.pop('ws.op')
                    errors = validate_new_account_form(**form)
                    return self.jsons(json=json.dumps(errors))
                elif op == 'request_password_reset_token':
                    return self.jsons('password reset token')
                elif op == 'set_new_password':
                    password = form['new_password']
                    json = json.dumps(validate_new_password(password))
                    return self.jsons(json=json)


    def handle_authentications(self):
        # 1. Check that we have some auth
        if not 'HTTP_AUTHORIZATION' in self.environ:
            self.fail401(extra_headers=[('WWW-Authenticate',
                                         'Basic realm="Secure Area"')])
            return []
        # 2. Check that the auth is actually Basic
        auth_string = self.environ['HTTP_AUTHORIZATION']
        if not auth_string.startswith('Basic '):
            self.fail401(extra_headers=[('WWW-Authenticate',
                                         'Basic realm="Secure Area"')])
            return []
        if self.environ['REQUEST_METHOD'].lower() == 'get':
            form = self.decode_form(self.environ['QUERY_STRING'])
            if 'ws.op' in form:
                op = form['ws.op']
                if op == 'authenticate':
                    if not self.check_plain_user():
                        return ['403 FORBIDDEN']
                    token = new_token(form['token_name'])
                    return self.jsons(json=token)
                elif op == 'validate_token':
                    if not self.check_server_user():
                        return ['403 FORBIDDEN']
                    token = tokens[form['token']]
                    return self.jsons(json=json.dumps(token))
                elif op == 'list_tokens':
                    if not self.check_server_user():
                        return ['403 FORBIDDEN']
                    result = [{'token': t['token'], 'name': t['name']}
                              for t in tokens.values()
                              if t['consumer_key'] == form['consumer_key']
                             ]
                    return self.jsons(json=json.dumps(result))
                elif op == 'team_memberships':
                    return self.jsons(
                        json=json.dumps(["ubuntu-team", "myteam"]))
                elif op == 'account_by_email':
                    email = form['email']
                    if email == "blu@bli.com":
                        return self.jsons('verified_accounts')
                    else:
                        return self.jsons(json='null')
                elif op == 'account_by_openid':
                    openid = form['openid']
                    if openid == 'openid_identifier':
                        return self.jsons('verified_accounts')
                    else:
                        return self.jsons(json='null')

        elif self.environ['REQUEST_METHOD'].lower() == 'post':
            clength = int(self.environ['CONTENT_LENGTH'])
            input = self.environ['wsgi.input'].read(clength)
            form = self.decode_form(input)
            if 'ws.op' in form:
                op = form['ws.op']
                if op == 'invalidate_token':
                    if not self.check_server_user():
                        return ['403 FORBIDDEN']
                    if form['token'] in tokens:
                        del tokens[form['token']]
                    return self.jsons(json='null')
        return self.jsons('registration')

    def handle_accounts(self):
        # 1. Check that we have some auth
        if not 'HTTP_AUTHORIZATION' in self.environ:
            self.fail401(extra_headers=[('WWW-Authenticate',
                                         'OAuth realm="OAuth"')])
            return []
        # 2. Check that the auth is actually OAuth
        auth_string = self.environ['HTTP_AUTHORIZATION']
        if not auth_string.startswith('OAuth '):
            self.fail401(extra_headers=[('WWW-Authenticate',
                                         'OAuth realm="OAuth"')])
            return []
        form = self.decode_form(self.environ['QUERY_STRING'])
        op = form.get('ws.op')
        if op == 'me':
            return self.jsons('accounts')
        elif op == 'team_memberships':
            return self.jsons('team_memberships')
        elif op == 'validate_email':
            token = form['email_token']
            if token == "jJRkmngbHjmnJDEK":
                return self.jsons('validated email')
            else:
                return self.jsons('bad email token')
        else:
            return self.jsons('accounts')

if __name__ == '__main__':
    import logging
    import optparse
    import sys
    from cStringIO import StringIO

    parser = optparse.OptionParser()
    parser.add_option("-H", "--host", help="Bind HOST [%default]",
                      default="openid.launchpad.dev")
    parser.add_option("-P",
                      "--port",
                      help="Bind PORT [%default] (0 to bind a random port)",
                      default=80,
                      type="int")
    parser.add_option("-R", "--root", help="API starts at ROOT [%default]",
                      default='/api/1.0')
    options, args = parser.parse_args()
    server = MockSSOServer(options.host, options.port, options.root)
    httpd = make_server(options.host, options.port, server)

    # disable logging
    logging.disable(logging.CRITICAL)
    # fake stderr to capture HTTPServer output
    # as .serve_forever() will never return until the process is killed, there
    # is no need nor reason for restoring stderr afterwards
    sys.stderr = StringIO()

    print "Serving on http://%s:%d%s..." % (httpd.server_name,
                                            httpd.server_port,
                                            options.root,)
    httpd.serve_forever()
