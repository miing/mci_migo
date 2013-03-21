# -*- coding: utf-8 -*-
import datetime
from south.db import db
from south.v2 import SchemaMigration
from django.db import models


class Migration(SchemaMigration):

    def forwards(self, orm):
        # Adding model 'Account'
        db.create_table(u'account', (
            ('id', self.gf('django.db.models.fields.AutoField')(primary_key=True)),
            ('date_created', self.gf('django.db.models.fields.DateTimeField')(default=datetime.datetime.utcnow)),
            ('creation_rationale', self.gf('django.db.models.fields.IntegerField')()),
            ('status', self.gf('django.db.models.fields.IntegerField')()),
            ('date_status_set', self.gf('django.db.models.fields.DateTimeField')(default=datetime.datetime.utcnow)),
            ('displayname', self.gf('identityprovider.models.account.DisplaynameField')()),
            ('openid_identifier', self.gf('django.db.models.fields.TextField')(default=u'RcJW7Xt', unique=True)),
            ('status_comment', self.gf('django.db.models.fields.TextField')(null=True, blank=True)),
            ('old_openid_identifier', self.gf('django.db.models.fields.TextField')(db_index=True, null=True, blank=True)),
            ('preferredlanguage', self.gf('django.db.models.fields.TextField')(null=True, blank=True)),
            ('twofactor_required', self.gf('django.db.models.fields.BooleanField')(default=False)),
            ('twofactor_attempts', self.gf('django.db.models.fields.SmallIntegerField')(default=0, null=True)),
            ('warn_about_backup_device', self.gf('django.db.models.fields.BooleanField')(default=True)),
        ))
        db.send_create_signal('identityprovider', ['Account'])

        # Adding model 'AccountPassword'
        db.create_table(u'accountpassword', (
            ('id', self.gf('django.db.models.fields.AutoField')(primary_key=True)),
            ('account', self.gf('django.db.models.fields.related.OneToOneField')(to=orm['identityprovider.Account'], unique=True, db_column='account')),
            ('password', self.gf('identityprovider.models.account.PasswordField')()),
        ))
        db.send_create_signal('identityprovider', ['AccountPassword'])

        # Adding model 'LPOpenIdIdentifier'
        db.create_table(u'lp_openididentifier', (
            ('identifier', self.gf('django.db.models.fields.TextField')(unique=True, primary_key=True)),
            ('lp_account', self.gf('django.db.models.fields.IntegerField')(db_column='account', db_index=True)),
            ('date_created', self.gf('django.db.models.fields.DateTimeField')(default=datetime.date.today)),
        ))
        db.send_create_signal('identityprovider', ['LPOpenIdIdentifier'])

        # Adding model 'Person'
        db.create_table(u'lp_person', (
            ('id', self.gf('django.db.models.fields.AutoField')(primary_key=True)),
            ('displayname', self.gf('django.db.models.fields.TextField')(null=True, blank=True)),
            ('teamowner', self.gf('django.db.models.fields.IntegerField')(null=True, db_column='teamowner', blank=True)),
            ('teamdescription', self.gf('django.db.models.fields.TextField')(null=True, blank=True)),
            ('name', self.gf('django.db.models.fields.TextField')(unique=True, null=True)),
            ('language', self.gf('django.db.models.fields.IntegerField')(null=True, db_column='language', blank=True)),
            ('fti', self.gf('django.db.models.fields.TextField')(null=True)),
            ('defaultmembershipperiod', self.gf('django.db.models.fields.IntegerField')(null=True, blank=True)),
            ('defaultrenewalperiod', self.gf('django.db.models.fields.IntegerField')(null=True, blank=True)),
            ('subscriptionpolicy', self.gf('django.db.models.fields.IntegerField')(default=1, null=True)),
            ('merged', self.gf('django.db.models.fields.IntegerField')(null=True, db_column='merged', blank=True)),
            ('datecreated', self.gf('django.db.models.fields.DateTimeField')(auto_now_add=True, null=True, blank=True)),
            ('addressline1', self.gf('django.db.models.fields.TextField')(null=True, blank=True)),
            ('addressline2', self.gf('django.db.models.fields.TextField')(null=True, blank=True)),
            ('organization', self.gf('django.db.models.fields.TextField')(null=True, blank=True)),
            ('city', self.gf('django.db.models.fields.TextField')(null=True, blank=True)),
            ('province', self.gf('django.db.models.fields.TextField')(null=True, blank=True)),
            ('country', self.gf('django.db.models.fields.IntegerField')(null=True, db_column='country', blank=True)),
            ('postcode', self.gf('django.db.models.fields.TextField')(null=True, blank=True)),
            ('phone', self.gf('django.db.models.fields.TextField')(null=True, blank=True)),
            ('homepage_content', self.gf('django.db.models.fields.TextField')(null=True, blank=True)),
            ('icon', self.gf('django.db.models.fields.IntegerField')(null=True, db_column='icon', blank=True)),
            ('mugshot', self.gf('django.db.models.fields.IntegerField')(null=True, db_column='mugshot', blank=True)),
            ('hide_email_addresses', self.gf('django.db.models.fields.NullBooleanField')(default=False, null=True, blank=True)),
            ('creation_rationale', self.gf('django.db.models.fields.IntegerField')(null=True, blank=True)),
            ('creation_comment', self.gf('django.db.models.fields.TextField')(null=True, blank=True)),
            ('registrant', self.gf('django.db.models.fields.IntegerField')(null=True, db_column='registrant', blank=True)),
            ('logo', self.gf('django.db.models.fields.IntegerField')(null=True, db_column='logo', blank=True)),
            ('renewal_policy', self.gf('django.db.models.fields.IntegerField')(default=10, null=True)),
            ('personal_standing', self.gf('django.db.models.fields.IntegerField')(default=0, null=True)),
            ('personal_standing_reason', self.gf('django.db.models.fields.TextField')(null=True, blank=True)),
            ('mail_resumption_date', self.gf('django.db.models.fields.DateField')(null=True, blank=True)),
            ('mailing_list_auto_subscribe_policy', self.gf('django.db.models.fields.IntegerField')(default=1, null=True)),
            ('mailing_list_receive_duplicates', self.gf('django.db.models.fields.NullBooleanField')(default=True, null=True, blank=True)),
            ('visibility', self.gf('django.db.models.fields.IntegerField')(default=1, null=True)),
            ('verbose_bugnotifications', self.gf('django.db.models.fields.NullBooleanField')(default=False, null=True, blank=True)),
            ('lp_account', self.gf('django.db.models.fields.IntegerField')(unique=True, null=True, db_column='account')),
        ))
        db.send_create_signal('identityprovider', ['Person'])

        # Adding model 'PersonLocation'
        db.create_table(u'lp_personlocation', (
            ('id', self.gf('django.db.models.fields.AutoField')(primary_key=True)),
            ('date_created', self.gf('django.db.models.fields.DateTimeField')(null=True)),
            ('person', self.gf('django.db.models.fields.related.OneToOneField')(to=orm['identityprovider.Person'], unique=True, null=True, db_column='person')),
            ('latitude', self.gf('django.db.models.fields.FloatField')(null=True, blank=True)),
            ('longitude', self.gf('django.db.models.fields.FloatField')(null=True, blank=True)),
            ('time_zone', self.gf('django.db.models.fields.TextField')(null=True, blank=True)),
            ('last_modified_by', self.gf('django.db.models.fields.IntegerField')(null=True, db_column='last_modified_by')),
            ('date_last_modified', self.gf('django.db.models.fields.DateTimeField')(null=True)),
            ('visible', self.gf('django.db.models.fields.NullBooleanField')(default=True, null=True, blank=True)),
            ('locked', self.gf('django.db.models.fields.NullBooleanField')(default=False, null=True, blank=True)),
        ))
        db.send_create_signal('identityprovider', ['PersonLocation'])

        # Adding model 'EmailAddress'
        db.create_table(u'emailaddress', (
            ('id', self.gf('django.db.models.fields.AutoField')(primary_key=True)),
            ('email', self.gf('django.db.models.fields.TextField')()),
            ('lp_person', self.gf('django.db.models.fields.IntegerField')(null=True, db_column='person', blank=True)),
            ('status', self.gf('django.db.models.fields.IntegerField')()),
            ('date_created', self.gf('django.db.models.fields.DateTimeField')(default=datetime.datetime.utcnow, blank=True)),
            ('account', self.gf('django.db.models.fields.related.ForeignKey')(to=orm['identityprovider.Account'], null=True, db_column='account', blank=True)),
        ))
        db.send_create_signal('identityprovider', ['EmailAddress'])

        # Adding model 'AuthToken'
        db.create_table(u'authtoken', (
            ('id', self.gf('django.db.models.fields.AutoField')(primary_key=True)),
            ('date_created', self.gf('django.db.models.fields.DateTimeField')(default=datetime.datetime.utcnow, db_index=True, blank=True)),
            ('date_consumed', self.gf('django.db.models.fields.DateTimeField')(db_index=True, null=True, blank=True)),
            ('token_type', self.gf('django.db.models.fields.IntegerField')()),
            ('token', self.gf('django.db.models.fields.TextField')(unique=True)),
            ('requester', self.gf('django.db.models.fields.related.ForeignKey')(to=orm['identityprovider.Account'], null=True, db_column='requester', blank=True)),
            ('requester_email', self.gf('django.db.models.fields.TextField')(null=True, blank=True)),
            ('email', self.gf('django.db.models.fields.TextField')(db_index=True)),
            ('redirection_url', self.gf('django.db.models.fields.TextField')(null=True, blank=True)),
            ('displayname', self.gf('identityprovider.models.account.DisplaynameField')(null=True)),
            ('password', self.gf('identityprovider.models.account.PasswordField')(null=True)),
        ))
        db.send_create_signal('identityprovider', ['AuthToken'])

        # Adding model 'OpenIDAssociation'
        db.create_table(u'openidassociation', (
            ('server_url', self.gf('django.db.models.fields.CharField')(max_length=2047)),
            ('handle', self.gf('django.db.models.fields.CharField')(max_length=255, primary_key=True)),
            ('secret', self.gf('django.db.models.fields.TextField')()),
            ('issued', self.gf('django.db.models.fields.IntegerField')()),
            ('lifetime', self.gf('django.db.models.fields.IntegerField')()),
            ('assoc_type', self.gf('django.db.models.fields.CharField')(max_length=64)),
        ))
        db.send_create_signal('identityprovider', ['OpenIDAssociation'])

        # Adding unique constraint on 'OpenIDAssociation', fields ['server_url', 'handle']
        db.create_unique(u'openidassociation', ['server_url', 'handle'])

        # Adding model 'OpenIDAuthorization'
        db.create_table(u'openidauthorization', (
            ('id', self.gf('django.db.models.fields.AutoField')(primary_key=True)),
            ('account', self.gf('django.db.models.fields.related.ForeignKey')(to=orm['identityprovider.Account'], db_column='account')),
            ('client_id', self.gf('django.db.models.fields.TextField')(null=True, blank=True)),
            ('date_created', self.gf('django.db.models.fields.DateTimeField')(default=datetime.datetime.utcnow, blank=True)),
            ('date_expires', self.gf('django.db.models.fields.DateTimeField')()),
            ('trust_root', self.gf('django.db.models.fields.TextField')()),
        ))
        db.send_create_signal('identityprovider', ['OpenIDAuthorization'])

        # Adding model 'OpenIDNonce'
        db.create_table('openidnonce', (
            ('server_url', self.gf('django.db.models.fields.CharField')(max_length=2047, primary_key=True)),
            ('timestamp', self.gf('django.db.models.fields.IntegerField')()),
            ('salt', self.gf('django.db.models.fields.CharField')(max_length=40)),
        ))
        db.send_create_signal('identityprovider', ['OpenIDNonce'])

        # Adding unique constraint on 'OpenIDNonce', fields ['server_url', 'timestamp', 'salt']
        db.create_unique('openidnonce', ['server_url', 'timestamp', 'salt'])

        # Adding model 'OpenIDRPConfig'
        db.create_table('ssoopenidrpconfig', (
            ('id', self.gf('django.db.models.fields.AutoField')(primary_key=True)),
            ('trust_root', self.gf('django.db.models.fields.TextField')(unique=True)),
            ('displayname', self.gf('django.db.models.fields.TextField')()),
            ('description', self.gf('django.db.models.fields.TextField')()),
            ('logo', self.gf('django.db.models.fields.TextField')(null=True, blank=True)),
            ('allowed_sreg', self.gf('django.db.models.fields.TextField')(null=True, blank=True)),
            ('creation_rationale', self.gf('django.db.models.fields.IntegerField')(default=13)),
            ('can_query_any_team', self.gf('django.db.models.fields.BooleanField')(default=False)),
            ('auto_authorize', self.gf('django.db.models.fields.BooleanField')(default=False)),
            ('require_two_factor', self.gf('django.db.models.fields.BooleanField')(default=False)),
            ('ga_snippet', self.gf('django.db.models.fields.TextField')(null=True, blank=True)),
            ('prefer_canonical_email', self.gf('django.db.models.fields.BooleanField')(default=False)),
            ('flag_twofactor', self.gf('django.db.models.fields.CharField')(max_length=256, null=True, blank=True)),
        ))
        db.send_create_signal('identityprovider', ['OpenIDRPConfig'])

        # Adding model 'OpenIDRPSummary'
        db.create_table(u'openidrpsummary', (
            ('id', self.gf('django.db.models.fields.AutoField')(primary_key=True)),
            ('account', self.gf('django.db.models.fields.related.ForeignKey')(to=orm['identityprovider.Account'], db_column='account')),
            ('openid_identifier', self.gf('django.db.models.fields.TextField')(db_index=True)),
            ('trust_root', self.gf('django.db.models.fields.TextField')(db_index=True)),
            ('date_created', self.gf('django.db.models.fields.DateTimeField')(default=datetime.datetime.utcnow, blank=True)),
            ('date_last_used', self.gf('django.db.models.fields.DateTimeField')(default=datetime.datetime.utcnow, blank=True)),
            ('total_logins', self.gf('django.db.models.fields.IntegerField')(default=1)),
            ('approved_data', self.gf('django.db.models.fields.TextField')(default='', null=True, blank=True)),
        ))
        db.send_create_signal('identityprovider', ['OpenIDRPSummary'])

        # Adding unique constraint on 'OpenIDRPSummary', fields ['account', 'trust_root', 'openid_identifier']
        db.create_unique(u'openidrpsummary', ['account', 'trust_root', 'openid_identifier'])

        # Adding model 'TeamParticipation'
        db.create_table(u'lp_teamparticipation', (
            ('id', self.gf('django.db.models.fields.AutoField')(primary_key=True)),
            ('team', self.gf('django.db.models.fields.related.ForeignKey')(related_name='team_participations', null=True, db_column='team', to=orm['identityprovider.Person'])),
            ('person', self.gf('django.db.models.fields.related.ForeignKey')(to=orm['identityprovider.Person'], null=True, db_column='person')),
        ))
        db.send_create_signal('identityprovider', ['TeamParticipation'])

        # Adding unique constraint on 'TeamParticipation', fields ['team', 'person']
        db.create_unique(u'lp_teamparticipation', ['team', 'person'])

        # Adding model 'APIUser'
        db.create_table('api_user', (
            ('id', self.gf('django.db.models.fields.AutoField')(primary_key=True)),
            ('username', self.gf('django.db.models.fields.CharField')(max_length=256)),
            ('password', self.gf('django.db.models.fields.CharField')(max_length=256)),
            ('created_at', self.gf('django.db.models.fields.DateTimeField')(auto_now_add=True, blank=True)),
            ('updated_at', self.gf('django.db.models.fields.DateTimeField')(auto_now=True, blank=True)),
        ))
        db.send_create_signal('identityprovider', ['APIUser'])

        # Adding model 'AuthenticationDevice'
        db.create_table('identityprovider_authenticationdevice', (
            ('id', self.gf('django.db.models.fields.AutoField')(primary_key=True)),
            ('account', self.gf('django.db.models.fields.related.ForeignKey')(related_name='devices', to=orm['identityprovider.Account'])),
            ('key', self.gf('django.db.models.fields.TextField')()),
            ('name', self.gf('django.db.models.fields.TextField')()),
            ('counter', self.gf('django.db.models.fields.IntegerField')(default=0)),
            ('device_type', self.gf('django.db.models.fields.TextField')(null=True)),
        ))
        db.send_create_signal('identityprovider', ['AuthenticationDevice'])


    def backwards(self, orm):
        # Removing unique constraint on 'TeamParticipation', fields ['team', 'person']
        db.delete_unique(u'lp_teamparticipation', ['team', 'person'])

        # Removing unique constraint on 'OpenIDRPSummary', fields ['account', 'trust_root', 'openid_identifier']
        db.delete_unique(u'openidrpsummary', ['account', 'trust_root', 'openid_identifier'])

        # Removing unique constraint on 'OpenIDNonce', fields ['server_url', 'timestamp', 'salt']
        db.delete_unique('openidnonce', ['server_url', 'timestamp', 'salt'])

        # Removing unique constraint on 'OpenIDAssociation', fields ['server_url', 'handle']
        db.delete_unique(u'openidassociation', ['server_url', 'handle'])

        # Deleting model 'Account'
        db.delete_table(u'account')

        # Deleting model 'AccountPassword'
        db.delete_table(u'accountpassword')

        # Deleting model 'LPOpenIdIdentifier'
        db.delete_table(u'lp_openididentifier')

        # Deleting model 'Person'
        db.delete_table(u'lp_person')

        # Deleting model 'PersonLocation'
        db.delete_table(u'lp_personlocation')

        # Deleting model 'EmailAddress'
        db.delete_table(u'emailaddress')

        # Deleting model 'AuthToken'
        db.delete_table(u'authtoken')

        # Deleting model 'OpenIDAssociation'
        db.delete_table(u'openidassociation')

        # Deleting model 'OpenIDAuthorization'
        db.delete_table(u'openidauthorization')

        # Deleting model 'OpenIDNonce'
        db.delete_table('openidnonce')

        # Deleting model 'OpenIDRPConfig'
        db.delete_table('ssoopenidrpconfig')

        # Deleting model 'OpenIDRPSummary'
        db.delete_table(u'openidrpsummary')

        # Deleting model 'TeamParticipation'
        db.delete_table(u'lp_teamparticipation')

        # Deleting model 'APIUser'
        db.delete_table('api_user')

        # Deleting model 'AuthenticationDevice'
        db.delete_table('identityprovider_authenticationdevice')


    models = {
        'identityprovider.account': {
            'Meta': {'object_name': 'Account', 'db_table': "u'account'"},
            'creation_rationale': ('django.db.models.fields.IntegerField', [], {}),
            'date_created': ('django.db.models.fields.DateTimeField', [], {'default': 'datetime.datetime.utcnow'}),
            'date_status_set': ('django.db.models.fields.DateTimeField', [], {'default': 'datetime.datetime.utcnow'}),
            'displayname': ('identityprovider.models.account.DisplaynameField', [], {}),
            'id': ('django.db.models.fields.AutoField', [], {'primary_key': 'True'}),
            'old_openid_identifier': ('django.db.models.fields.TextField', [], {'db_index': 'True', 'null': 'True', 'blank': 'True'}),
            'openid_identifier': ('django.db.models.fields.TextField', [], {'default': "u'KczyHLX'", 'unique': 'True'}),
            'preferredlanguage': ('django.db.models.fields.TextField', [], {'null': 'True', 'blank': 'True'}),
            'status': ('django.db.models.fields.IntegerField', [], {}),
            'status_comment': ('django.db.models.fields.TextField', [], {'null': 'True', 'blank': 'True'}),
            'twofactor_attempts': ('django.db.models.fields.SmallIntegerField', [], {'default': '0', 'null': 'True'}),
            'twofactor_required': ('django.db.models.fields.BooleanField', [], {'default': 'False'}),
            'warn_about_backup_device': ('django.db.models.fields.BooleanField', [], {'default': 'True'})
        },
        'identityprovider.accountpassword': {
            'Meta': {'object_name': 'AccountPassword', 'db_table': "u'accountpassword'"},
            'account': ('django.db.models.fields.related.OneToOneField', [], {'to': "orm['identityprovider.Account']", 'unique': 'True', 'db_column': "'account'"}),
            'id': ('django.db.models.fields.AutoField', [], {'primary_key': 'True'}),
            'password': ('identityprovider.models.account.PasswordField', [], {})
        },
        'identityprovider.apiuser': {
            'Meta': {'object_name': 'APIUser', 'db_table': "'api_user'"},
            'created_at': ('django.db.models.fields.DateTimeField', [], {'auto_now_add': 'True', 'blank': 'True'}),
            'id': ('django.db.models.fields.AutoField', [], {'primary_key': 'True'}),
            'password': ('django.db.models.fields.CharField', [], {'max_length': '256'}),
            'updated_at': ('django.db.models.fields.DateTimeField', [], {'auto_now': 'True', 'blank': 'True'}),
            'username': ('django.db.models.fields.CharField', [], {'max_length': '256'})
        },
        'identityprovider.authenticationdevice': {
            'Meta': {'ordering': "('id',)", 'object_name': 'AuthenticationDevice'},
            'account': ('django.db.models.fields.related.ForeignKey', [], {'related_name': "'devices'", 'to': "orm['identityprovider.Account']"}),
            'counter': ('django.db.models.fields.IntegerField', [], {'default': '0'}),
            'device_type': ('django.db.models.fields.TextField', [], {'null': 'True'}),
            'id': ('django.db.models.fields.AutoField', [], {'primary_key': 'True'}),
            'key': ('django.db.models.fields.TextField', [], {}),
            'name': ('django.db.models.fields.TextField', [], {})
        },
        'identityprovider.authtoken': {
            'Meta': {'object_name': 'AuthToken', 'db_table': "u'authtoken'"},
            'date_consumed': ('django.db.models.fields.DateTimeField', [], {'db_index': 'True', 'null': 'True', 'blank': 'True'}),
            'date_created': ('django.db.models.fields.DateTimeField', [], {'default': 'datetime.datetime.utcnow', 'db_index': 'True', 'blank': 'True'}),
            'displayname': ('identityprovider.models.account.DisplaynameField', [], {'null': 'True'}),
            'email': ('django.db.models.fields.TextField', [], {'db_index': 'True'}),
            'id': ('django.db.models.fields.AutoField', [], {'primary_key': 'True'}),
            'password': ('identityprovider.models.account.PasswordField', [], {'null': 'True'}),
            'redirection_url': ('django.db.models.fields.TextField', [], {'null': 'True', 'blank': 'True'}),
            'requester': ('django.db.models.fields.related.ForeignKey', [], {'to': "orm['identityprovider.Account']", 'null': 'True', 'db_column': "'requester'", 'blank': 'True'}),
            'requester_email': ('django.db.models.fields.TextField', [], {'null': 'True', 'blank': 'True'}),
            'token': ('django.db.models.fields.TextField', [], {'unique': 'True'}),
            'token_type': ('django.db.models.fields.IntegerField', [], {})
        },
        'identityprovider.emailaddress': {
            'Meta': {'object_name': 'EmailAddress', 'db_table': "u'emailaddress'"},
            'account': ('django.db.models.fields.related.ForeignKey', [], {'to': "orm['identityprovider.Account']", 'null': 'True', 'db_column': "'account'", 'blank': 'True'}),
            'date_created': ('django.db.models.fields.DateTimeField', [], {'default': 'datetime.datetime.utcnow', 'blank': 'True'}),
            'email': ('django.db.models.fields.TextField', [], {}),
            'id': ('django.db.models.fields.AutoField', [], {'primary_key': 'True'}),
            'lp_person': ('django.db.models.fields.IntegerField', [], {'null': 'True', 'db_column': "'person'", 'blank': 'True'}),
            'status': ('django.db.models.fields.IntegerField', [], {})
        },
        'identityprovider.lpopenididentifier': {
            'Meta': {'object_name': 'LPOpenIdIdentifier', 'db_table': "u'lp_openididentifier'"},
            'date_created': ('django.db.models.fields.DateTimeField', [], {'default': 'datetime.date.today'}),
            'identifier': ('django.db.models.fields.TextField', [], {'unique': 'True', 'primary_key': 'True'}),
            'lp_account': ('django.db.models.fields.IntegerField', [], {'db_column': "'account'", 'db_index': 'True'})
        },
        'identityprovider.openidassociation': {
            'Meta': {'unique_together': "(('server_url', 'handle'),)", 'object_name': 'OpenIDAssociation', 'db_table': "u'openidassociation'"},
            'assoc_type': ('django.db.models.fields.CharField', [], {'max_length': '64'}),
            'handle': ('django.db.models.fields.CharField', [], {'max_length': '255', 'primary_key': 'True'}),
            'issued': ('django.db.models.fields.IntegerField', [], {}),
            'lifetime': ('django.db.models.fields.IntegerField', [], {}),
            'secret': ('django.db.models.fields.TextField', [], {}),
            'server_url': ('django.db.models.fields.CharField', [], {'max_length': '2047'})
        },
        'identityprovider.openidauthorization': {
            'Meta': {'object_name': 'OpenIDAuthorization', 'db_table': "u'openidauthorization'"},
            'account': ('django.db.models.fields.related.ForeignKey', [], {'to': "orm['identityprovider.Account']", 'db_column': "'account'"}),
            'client_id': ('django.db.models.fields.TextField', [], {'null': 'True', 'blank': 'True'}),
            'date_created': ('django.db.models.fields.DateTimeField', [], {'default': 'datetime.datetime.utcnow', 'blank': 'True'}),
            'date_expires': ('django.db.models.fields.DateTimeField', [], {}),
            'id': ('django.db.models.fields.AutoField', [], {'primary_key': 'True'}),
            'trust_root': ('django.db.models.fields.TextField', [], {})
        },
        'identityprovider.openidnonce': {
            'Meta': {'unique_together': "(('server_url', 'timestamp', 'salt'),)", 'object_name': 'OpenIDNonce', 'db_table': "'openidnonce'"},
            'salt': ('django.db.models.fields.CharField', [], {'max_length': '40'}),
            'server_url': ('django.db.models.fields.CharField', [], {'max_length': '2047', 'primary_key': 'True'}),
            'timestamp': ('django.db.models.fields.IntegerField', [], {})
        },
        'identityprovider.openidrpconfig': {
            'Meta': {'object_name': 'OpenIDRPConfig', 'db_table': "'ssoopenidrpconfig'"},
            'allowed_sreg': ('django.db.models.fields.TextField', [], {'null': 'True', 'blank': 'True'}),
            'auto_authorize': ('django.db.models.fields.BooleanField', [], {'default': 'False'}),
            'can_query_any_team': ('django.db.models.fields.BooleanField', [], {'default': 'False'}),
            'creation_rationale': ('django.db.models.fields.IntegerField', [], {'default': '13'}),
            'description': ('django.db.models.fields.TextField', [], {}),
            'displayname': ('django.db.models.fields.TextField', [], {}),
            'flag_twofactor': ('django.db.models.fields.CharField', [], {'max_length': '256', 'null': 'True', 'blank': 'True'}),
            'ga_snippet': ('django.db.models.fields.TextField', [], {'null': 'True', 'blank': 'True'}),
            'id': ('django.db.models.fields.AutoField', [], {'primary_key': 'True'}),
            'logo': ('django.db.models.fields.TextField', [], {'null': 'True', 'blank': 'True'}),
            'prefer_canonical_email': ('django.db.models.fields.BooleanField', [], {'default': 'False'}),
            'require_two_factor': ('django.db.models.fields.BooleanField', [], {'default': 'False'}),
            'trust_root': ('django.db.models.fields.TextField', [], {'unique': 'True'})
        },
        'identityprovider.openidrpsummary': {
            'Meta': {'unique_together': "(('account', 'trust_root', 'openid_identifier'),)", 'object_name': 'OpenIDRPSummary', 'db_table': "u'openidrpsummary'"},
            'account': ('django.db.models.fields.related.ForeignKey', [], {'to': "orm['identityprovider.Account']", 'db_column': "'account'"}),
            'approved_data': ('django.db.models.fields.TextField', [], {'default': "''", 'null': 'True', 'blank': 'True'}),
            'date_created': ('django.db.models.fields.DateTimeField', [], {'default': 'datetime.datetime.utcnow', 'blank': 'True'}),
            'date_last_used': ('django.db.models.fields.DateTimeField', [], {'default': 'datetime.datetime.utcnow', 'blank': 'True'}),
            'id': ('django.db.models.fields.AutoField', [], {'primary_key': 'True'}),
            'openid_identifier': ('django.db.models.fields.TextField', [], {'db_index': 'True'}),
            'total_logins': ('django.db.models.fields.IntegerField', [], {'default': '1'}),
            'trust_root': ('django.db.models.fields.TextField', [], {'db_index': 'True'})
        },
        'identityprovider.person': {
            'Meta': {'object_name': 'Person', 'db_table': "u'lp_person'"},
            'addressline1': ('django.db.models.fields.TextField', [], {'null': 'True', 'blank': 'True'}),
            'addressline2': ('django.db.models.fields.TextField', [], {'null': 'True', 'blank': 'True'}),
            'city': ('django.db.models.fields.TextField', [], {'null': 'True', 'blank': 'True'}),
            'country': ('django.db.models.fields.IntegerField', [], {'null': 'True', 'db_column': "'country'", 'blank': 'True'}),
            'creation_comment': ('django.db.models.fields.TextField', [], {'null': 'True', 'blank': 'True'}),
            'creation_rationale': ('django.db.models.fields.IntegerField', [], {'null': 'True', 'blank': 'True'}),
            'datecreated': ('django.db.models.fields.DateTimeField', [], {'auto_now_add': 'True', 'null': 'True', 'blank': 'True'}),
            'defaultmembershipperiod': ('django.db.models.fields.IntegerField', [], {'null': 'True', 'blank': 'True'}),
            'defaultrenewalperiod': ('django.db.models.fields.IntegerField', [], {'null': 'True', 'blank': 'True'}),
            'displayname': ('django.db.models.fields.TextField', [], {'null': 'True', 'blank': 'True'}),
            'fti': ('django.db.models.fields.TextField', [], {'null': 'True'}),
            'hide_email_addresses': ('django.db.models.fields.NullBooleanField', [], {'default': 'False', 'null': 'True', 'blank': 'True'}),
            'homepage_content': ('django.db.models.fields.TextField', [], {'null': 'True', 'blank': 'True'}),
            'icon': ('django.db.models.fields.IntegerField', [], {'null': 'True', 'db_column': "'icon'", 'blank': 'True'}),
            'id': ('django.db.models.fields.AutoField', [], {'primary_key': 'True'}),
            'language': ('django.db.models.fields.IntegerField', [], {'null': 'True', 'db_column': "'language'", 'blank': 'True'}),
            'logo': ('django.db.models.fields.IntegerField', [], {'null': 'True', 'db_column': "'logo'", 'blank': 'True'}),
            'lp_account': ('django.db.models.fields.IntegerField', [], {'unique': 'True', 'null': 'True', 'db_column': "'account'"}),
            'mail_resumption_date': ('django.db.models.fields.DateField', [], {'null': 'True', 'blank': 'True'}),
            'mailing_list_auto_subscribe_policy': ('django.db.models.fields.IntegerField', [], {'default': '1', 'null': 'True'}),
            'mailing_list_receive_duplicates': ('django.db.models.fields.NullBooleanField', [], {'default': 'True', 'null': 'True', 'blank': 'True'}),
            'merged': ('django.db.models.fields.IntegerField', [], {'null': 'True', 'db_column': "'merged'", 'blank': 'True'}),
            'mugshot': ('django.db.models.fields.IntegerField', [], {'null': 'True', 'db_column': "'mugshot'", 'blank': 'True'}),
            'name': ('django.db.models.fields.TextField', [], {'unique': 'True', 'null': 'True'}),
            'organization': ('django.db.models.fields.TextField', [], {'null': 'True', 'blank': 'True'}),
            'personal_standing': ('django.db.models.fields.IntegerField', [], {'default': '0', 'null': 'True'}),
            'personal_standing_reason': ('django.db.models.fields.TextField', [], {'null': 'True', 'blank': 'True'}),
            'phone': ('django.db.models.fields.TextField', [], {'null': 'True', 'blank': 'True'}),
            'postcode': ('django.db.models.fields.TextField', [], {'null': 'True', 'blank': 'True'}),
            'province': ('django.db.models.fields.TextField', [], {'null': 'True', 'blank': 'True'}),
            'registrant': ('django.db.models.fields.IntegerField', [], {'null': 'True', 'db_column': "'registrant'", 'blank': 'True'}),
            'renewal_policy': ('django.db.models.fields.IntegerField', [], {'default': '10', 'null': 'True'}),
            'subscriptionpolicy': ('django.db.models.fields.IntegerField', [], {'default': '1', 'null': 'True'}),
            'teamdescription': ('django.db.models.fields.TextField', [], {'null': 'True', 'blank': 'True'}),
            'teamowner': ('django.db.models.fields.IntegerField', [], {'null': 'True', 'db_column': "'teamowner'", 'blank': 'True'}),
            'verbose_bugnotifications': ('django.db.models.fields.NullBooleanField', [], {'default': 'False', 'null': 'True', 'blank': 'True'}),
            'visibility': ('django.db.models.fields.IntegerField', [], {'default': '1', 'null': 'True'})
        },
        'identityprovider.personlocation': {
            'Meta': {'object_name': 'PersonLocation', 'db_table': "u'lp_personlocation'"},
            'date_created': ('django.db.models.fields.DateTimeField', [], {'null': 'True'}),
            'date_last_modified': ('django.db.models.fields.DateTimeField', [], {'null': 'True'}),
            'id': ('django.db.models.fields.AutoField', [], {'primary_key': 'True'}),
            'last_modified_by': ('django.db.models.fields.IntegerField', [], {'null': 'True', 'db_column': "'last_modified_by'"}),
            'latitude': ('django.db.models.fields.FloatField', [], {'null': 'True', 'blank': 'True'}),
            'locked': ('django.db.models.fields.NullBooleanField', [], {'default': 'False', 'null': 'True', 'blank': 'True'}),
            'longitude': ('django.db.models.fields.FloatField', [], {'null': 'True', 'blank': 'True'}),
            'person': ('django.db.models.fields.related.OneToOneField', [], {'to': "orm['identityprovider.Person']", 'unique': 'True', 'null': 'True', 'db_column': "'person'"}),
            'time_zone': ('django.db.models.fields.TextField', [], {'null': 'True', 'blank': 'True'}),
            'visible': ('django.db.models.fields.NullBooleanField', [], {'default': 'True', 'null': 'True', 'blank': 'True'})
        },
        'identityprovider.teamparticipation': {
            'Meta': {'unique_together': "(('team', 'person'),)", 'object_name': 'TeamParticipation', 'db_table': "u'lp_teamparticipation'"},
            'id': ('django.db.models.fields.AutoField', [], {'primary_key': 'True'}),
            'person': ('django.db.models.fields.related.ForeignKey', [], {'to': "orm['identityprovider.Person']", 'null': 'True', 'db_column': "'person'"}),
            'team': ('django.db.models.fields.related.ForeignKey', [], {'related_name': "'team_participations'", 'null': 'True', 'db_column': "'team'", 'to': "orm['identityprovider.Person']"})
        }
    }

    complete_apps = ['identityprovider']