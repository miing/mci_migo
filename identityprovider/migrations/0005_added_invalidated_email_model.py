# -*- coding: utf-8 -*-
import datetime
from south.db import db
from south.v2 import SchemaMigration
from django.db import models


class Migration(SchemaMigration):

    def forwards(self, orm):
        # Adding model 'InvalidatedEmailAddress'
        db.create_table(u'invalidated_emailaddress', (
            ('id', self.gf('django.db.models.fields.AutoField')(primary_key=True)),
            ('email', self.gf('django.db.models.fields.TextField')()),
            ('date_created', self.gf('django.db.models.fields.DateTimeField')(blank=True)),
            ('account', self.gf('django.db.models.fields.related.ForeignKey')(to=orm['identityprovider.Account'], null=True, db_column='account', blank=True)),
        ))
        db.send_create_signal('identityprovider', ['InvalidatedEmailAddress'])


    def backwards(self, orm):
        # Deleting model 'InvalidatedEmailAddress'
        db.delete_table(u'invalidated_emailaddress')


    models = {
        'identityprovider.account': {
            'Meta': {'object_name': 'Account', 'db_table': "u'account'"},
            'creation_rationale': ('django.db.models.fields.IntegerField', [], {}),
            'date_created': ('django.db.models.fields.DateTimeField', [], {'default': 'datetime.datetime.utcnow'}),
            'date_status_set': ('django.db.models.fields.DateTimeField', [], {'default': 'datetime.datetime.utcnow'}),
            'displayname': ('identityprovider.models.account.DisplaynameField', [], {}),
            'id': ('django.db.models.fields.AutoField', [], {'primary_key': 'True'}),
            'old_openid_identifier': ('django.db.models.fields.TextField', [], {'db_index': 'True', 'null': 'True', 'blank': 'True'}),
            'openid_identifier': ('django.db.models.fields.TextField', [], {'default': "u'TkYKdLR'", 'unique': 'True'}),
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
            'displayname': ('identityprovider.models.account.DisplaynameField', [], {'null': 'True', 'blank': 'True'}),
            'email': ('django.db.models.fields.TextField', [], {'db_index': 'True'}),
            'id': ('django.db.models.fields.AutoField', [], {'primary_key': 'True'}),
            'password': ('identityprovider.models.account.PasswordField', [], {'null': 'True', 'blank': 'True'}),
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
        'identityprovider.invalidatedemailaddress': {
            'Meta': {'object_name': 'InvalidatedEmailAddress', 'db_table': "u'invalidated_emailaddress'"},
            'account': ('django.db.models.fields.related.ForeignKey', [], {'to': "orm['identityprovider.Account']", 'null': 'True', 'db_column': "'account'", 'blank': 'True'}),
            'date_created': ('django.db.models.fields.DateTimeField', [], {'blank': 'True'}),
            'email': ('django.db.models.fields.TextField', [], {}),
            'id': ('django.db.models.fields.AutoField', [], {'primary_key': 'True'})
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
            'allow_unverified': ('django.db.models.fields.BooleanField', [], {'default': 'False'}),
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