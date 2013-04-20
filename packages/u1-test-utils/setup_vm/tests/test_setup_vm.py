from cStringIO import StringIO
import os

from bzrlib import errors
import testtools

import tests
from bin import setup_vm


def requires_known_reference_image(test):
    # We need a pre-seeded download cache from the user running the tests
    # as downloading the cloud image is too long.
    user_conf = setup_vm.VmStack(None)
    download_cache = user_conf.get('vm.download_cache')
    if download_cache is None:
        test.skip('vm.download_cache is not set')
    # We use some known reference
    reference_cloud_image_name = 'raring-server-cloudimg-amd64-disk1.img'
    cloud_image_path = os.path.join(
        download_cache, reference_cloud_image_name)
    if not os.path.exists(cloud_image_path):
        test.skip('%s is not available' % (cloud_image_path,))
    return download_cache, reference_cloud_image_name


class TestCaseWithHome(testtools.TestCase):
    """Provide an isolated disk-based environment.

    A $HOME directory is setup as well as an /etc/ one so tests can setup
    config files.
    """

    def setUp(self):
        super(TestCaseWithHome, self).setUp()
        tests.set_cwd_to_tmp(self)
        tests.isolate_env(self)
        # Isolate tests from the user environment
        self.home_dir = os.path.join(self.test_base_dir, 'home')
        os.mkdir(self.home_dir)
        os.environ['HOME'] = self.home_dir
        # Also isolate from the system environment
        self.etc_dir = os.path.join(self.test_base_dir, 'etc')
        os.mkdir(self.etc_dir)
        self.patch(setup_vm, 'system_config_dir', lambda: self.etc_dir)


class TestVmMatcher(TestCaseWithHome):

    def setUp(self):
        super(TestVmMatcher, self).setUp()
        self.store = setup_vm.VmStore('.', 'foo.conf')
        self.matcher = setup_vm.VmMatcher(self.store, 'test')

    def test_empty_section_always_matches(self):
        self.store._load_from_string('foo=bar')
        matching = list(self.matcher.get_sections())
        self.assertEqual(1, len(matching))

    def test_specific_before_generic(self):
        self.store._load_from_string('foo=bar\n[test]\nfoo=baz')
        matching = list(self.matcher.get_sections())
        self.assertEqual(2, len(matching))
        # First matching section is for test
        self.assertEqual(self.store, matching[0][0])
        base_section = matching[0][1]
        self.assertEqual('test', base_section.id)
        # Second matching section is the no-name one
        self.assertEqual(self.store, matching[0][0])
        no_name_section = matching[1][1]
        self.assertIs(None, no_name_section.id)


class TestVmStores(TestCaseWithHome):

    def setUp(self):
        super(TestVmStores, self).setUp()
        self.conf = setup_vm.VmStack('foo')


    def test_default_in_empty_stack(self):
        self.assertEqual('1024', self.conf.get('vm.ram_size'))


    def test_system_overrides_internal(self):
        self.conf.system_store._load_from_string('vm.ram_size = 42')
        self.assertEqual('42', self.conf.get('vm.ram_size'))

    def test_user_overrides_system(self):
        self.conf.system_store._load_from_string('vm.ram_size = 42')
        self.conf.store._load_from_string('vm.ram_size = 4201')
        self.assertEqual('4201', self.conf.get('vm.ram_size'))

    def test_local_overrides_user(self):
        self.conf.system_store._load_from_string('vm.ram_size = 42')
        self.conf.store._load_from_string('vm.ram_size = 4201')
        self.conf.local_store._load_from_string('vm.ram_size = 8402')
        self.assertEqual('8402', self.conf.get('vm.ram_size'))


class TestVmStack(TestCaseWithHome):

    def setUp(self):
        super(TestVmStack, self).setUp()
        self.conf = setup_vm.VmStack('foo')
        self.conf.store._load_from_string('''
vm.release=raring
vm.cpu_model=amd64
''')

    def assertValue(self, expected_value, option):
        self.assertEqual(expected_value, self.conf.get(option))

    def test_raring_iso_url(self):
        self.assertValue('http://cdimage.ubuntu.com/daily-live/current/',
                         'vm.iso_url' )

    def test_raring_iso_name(self):
        self.assertValue( 'raring-desktop-amd64.iso', 'vm.iso_name')

    def test_raring_cloud_image_url(self):
        self.assertValue('http://cloud-images.ubuntu.com/raring/current/',
                         'vm.cloud_image_url')

    def test_raring_cloud_image_name(self):
        self.assertValue('raring-server-cloudimg-amd64-disk1.img',
                         'vm.cloud_image_name')

    def test_apt_proxy_set(self):
        proxy = 'apt_proxy: http://example.org:4321'
        self.conf.set('vm.apt_proxy', proxy)
        self.assertEqual(proxy, self.conf.expand_options('{vm.apt_proxy}'))

    def test_download_cache_with_user_expansion(self):
        download_cache = '~/installers'
        self.conf.set('vm.download_cache', download_cache)
        self.assertValue(os.path.join(self.home_dir, 'installers'),
                         'vm.download_cache')

    def test_images_dir_with_user_expansion(self):
        images_dir = '~/images'
        self.conf.set('vm.images_dir', images_dir)
        self.assertValue(os.path.join(self.home_dir, 'images'),
                         'vm.images_dir')


class TestPathOption(TestCaseWithHome):

    def assertConverted(self, expected, value):
        option = setup_vm.PathOption('foo', help='A path.')
        self.assertEquals(expected, option.convert_from_unicode(None, value))

    def test_absolute_path(self):
        self.assertConverted('/test/path', '/test/path')

    def test_home_path_with_expansion(self):
        self.assertConverted(self.home_dir, '~')

    def test_path_in_home_with_expansion(self):
        self.assertConverted(os.path.join(self.home_dir, 'test/path'),
                             '~/test/path')


class TestDownload(TestCaseWithHome):

# FIXME: Needs parametrization against vm.{cloud_image_name|iso_name} and
# {download_iso|download_cloud_image} -- vila 2013-02-07

    def setUp(self):
        # Downloading real isos or images is too long for tests, instead, we
        # fake it by downloading a small but known to exist file: MD5SUMS
        super(TestDownload, self).setUp()
        download_cache = os.path.join(self.test_base_dir, 'downloads')
        os.mkdir(download_cache)
        self.conf = setup_vm.VmStack('foo')
        self.conf.store._load_from_string('''
vm.iso_name=MD5SUMS
vm.cloud_image_name=MD5SUMS
vm.release=raring
vm.cpu_model=amd64
vm.download_cache=%s
''' % (download_cache,))

    def test_download_iso(self):
        vm = setup_vm.Kvm(self.conf)
        self.assertTrue(vm.download_iso())
        # Trying to download again will find the file in the cache
        self.assertFalse(vm.download_iso())
        # Forcing the download even when the file is present
        self.assertTrue(vm.download_iso(force=True))

    def test_download_cloud_image(self):
        vm = setup_vm.Kvm(self.conf)
        self.assertTrue(vm.download_cloud_image())
        # Trying to download again will find the file in the cache
        self.assertFalse(vm.download_cloud_image())
        # Forcing the download even when the file is present
        self.assertTrue(vm.download_cloud_image(force=True))

    def test_download_unknown_iso_fail(self):
        self.conf.set('vm.iso_name', 'I-dont-exist')
        vm = setup_vm.Kvm(self.conf)
        self.assertRaises(setup_vm.CommandError, vm.download_iso)

    def test_download_unknown_cloud_image_fail(self):
        self.conf.set('vm.cloud_image_name', 'I-dont-exist')
        vm = setup_vm.Kvm(self.conf)
        self.assertRaises(setup_vm.CommandError, vm.download_cloud_image)

    def test_download_iso_with_unknown_cache_fail(self):
        dl_cache = os.path.join(self.test_base_dir, 'I-dont-exist')
        self.conf.set('vm.download_cache', dl_cache)
        vm = setup_vm.Kvm(self.conf)
        self.assertRaises(setup_vm.ConfigValueError, vm.download_iso)

    def test_download_cloud_image_with_unknown_cache_fail(self):
        dl_cache = os.path.join(self.test_base_dir, 'I-dont-exist')
        self.conf.set('vm.download_cache', dl_cache)
        vm = setup_vm.Kvm(self.conf)
        self.assertRaises(setup_vm.ConfigValueError, vm.download_cloud_image)


class TestMetaData(TestCaseWithHome):

    def setUp(self):
        super(TestMetaData, self).setUp()
        self.conf = setup_vm.VmStack('foo')
        self.vm = setup_vm.Kvm(self.conf)
        images_dir = os.path.join(self.test_base_dir, 'images')
        os.mkdir(images_dir)
        config_dir = os.path.join(self.test_base_dir, 'config')
        self.conf.store._load_from_string('''
vm.name=foo
vm.images_dir=%s
vm.config_dir=%s
''' % (images_dir, config_dir,))

    def test_create_meta_data(self):
        self.vm.create_meta_data()
        self.assertTrue(os.path.exists(self.vm._config_dir))
        self.assertTrue(os.path.exists(self.vm._meta_data_path))
        with open(self.vm._meta_data_path) as f:
            meta_data = f.readlines()
        self.assertEqual(2, len(meta_data))
        self.assertEqual('instance-id: foo\n', meta_data[0])
        self.assertEqual('local-hostname: foo\n', meta_data[1])


class TestYaml(testtools.TestCase):

    def yaml_load(self, *args, **kwargs):
        return setup_vm.yaml.safe_load(*args, **kwargs)

    def yaml_dump(self, *args, **kwargs):
        return setup_vm.yaml.safe_dump(*args, **kwargs)

    def test_load_scalar(self):
        self.assertEqual({'foo': 'bar'}, self.yaml_load(StringIO('{foo: bar}')))
        # Surprisingly the enclosing braces are not needed, probably a special
        # case for the highest level
        self.assertEqual({'foo': 'bar'}, self.yaml_load(StringIO('foo: bar')))

    def test_dump_scalar(self):
        self.assertEqual('{foo: bar}\n', self.yaml_dump(dict(foo='bar')))

    def test_load_list(self):
        self.assertEqual({'foo': ['a', 'b', 'c']},
                         # Single space indentation is enough
                         self.yaml_load(StringIO('''\
foo:
 - a
 - b
 - c
''')))

    def test_dump_list(self):
        # No more enclosing braces... yeah for consistency :-/
        self.assertEqual('foo: [a, b, c]\n',
                         self.yaml_dump(dict(foo=['a', 'b', 'c'])))

    def test_load_dict(self):
        self.assertEqual({'foo': {'bar': 'baz'}},
                          self.yaml_load(StringIO('{foo: {bar: baz}}')))
        multiple_lines = '''\
foo: {bar: multiple
  lines}
'''
        self.assertEqual({'foo': {'bar': 'multiple lines'}},
                          self.yaml_load(StringIO(multiple_lines)))



class TestLaunchpadAccess(TestCaseWithHome):

    def setUp(self):
        super(TestLaunchpadAccess, self).setUp()
        self.conf = setup_vm.VmStack('foo')
        self.vm = setup_vm.Kvm(self.conf)
        self.ci_data = setup_vm.CIUserData(self.conf)

    def test_cant_find_private_key(self):
        self.conf.store._load_from_string('vm.launchpad_id = I-dont-exist')
        e = self.assertRaises(setup_vm.ConfigPathNotFound,
                              self.ci_data.set_launchpad_access)
        key_path = '~/.ssh/I-dont-exist@setup_vm'
        self.assertEqual(key_path, e.path)
        self.assertTrue(unicode(e).startswith(
                'You need to create the {p} keypair'.format(p=key_path)))

    def test_id_with_key(self):
        ssh_dir = os.path.join(self.home_dir, '.ssh')
        os.mkdir(ssh_dir)
        key_path = os.path.join(ssh_dir, 'user@setup_vm')
        with open(key_path, 'w') as f:
            f.write('key content')
        self.conf.store._load_from_string('vm.launchpad_id = user')
        self.assertEqual(None, self.ci_data.launchpad_hook)
        self.ci_data.set_launchpad_access()
        self.assertEqual('''\
#!/bin/sh
mkdir -p /home/ubuntu/.ssh
chown ubuntu:ubuntu ~ubuntu
chmod 0700 ~ubuntu
chown ubuntu:ubuntu /home/ubuntu/.ssh
chmod 0700 /home/ubuntu/.ssh
cat >/home/ubuntu/.ssh/id_rsa <<'EOSETUPVMCONTENTREALLYUNIQUEDONTBREAKFORFUN'
key content
EOSETUPVMCONTENTREALLYUNIQUEDONTBREAKFORFUN
chown ubuntu:ubuntu /home/ubuntu/.ssh/id_rsa
chmod 0400 /home/ubuntu/.ssh/id_rsa
''',
                         self.ci_data.launchpad_hook)
        cc = self.ci_data.cloud_config
        self.assertEquals([['sudo', '-u', 'ubuntu',
                            'bzr', 'launchpad-login', 'user']],
                          cc['runcmd'])


class TestCIUserData(TestCaseWithHome):

    def setUp(self):
        super(TestCIUserData, self).setUp()
        self.conf = setup_vm.VmStack('foo')
        self.ci_data = setup_vm.CIUserData(self.conf)

    def test_empty_config(self):
        self.ci_data.populate()
        # Check default values
        self.assertIs(None, self.ci_data.root_hook)
        self.assertIs(None, self.ci_data.ubuntu_hook)
        cc = self.ci_data.cloud_config
        self.assertFalse(cc['apt_update'])
        self.assertFalse(cc['apt_upgrade'])
        self.assertEqual({'expire': False}, cc['chpasswd'])
        self.assertEqual('setup_vm finished installing in ${uptime} seconds.',
                         cc['final_message'])
        self.assertTrue(cc['manage_etc_hosts'])
        self.assertEqual('ubuntu', cc['password'])
        self.assertEqual({'mode': 'poweroff'}, cc['power_state'])

    def test_password(self):
        self.conf.store._load_from_string('vm.password = tagada')
        self.ci_data.populate()
        self.assertEquals('tagada', self.ci_data.cloud_config['password'])

    def test_apt_proxy(self):
        self.conf.store._load_from_string('vm.apt_proxy = tagada')
        self.ci_data.populate()
        self.assertEquals('tagada', self.ci_data.cloud_config['apt_proxy'])

    def test_final_message_precise(self):
        self.conf.store._load_from_string('vm.release = precise')
        self.ci_data.populate()
        self.assertEqual('setup_vm finished installing in $UPTIME seconds.',
                         self.ci_data.cloud_config['final_message'])

    def test_poweroff_precise(self):
        self.conf.store._load_from_string('vm.release = precise')
        self.ci_data.populate()
        self.assertEqual(['halt'], self.ci_data.cloud_config['runcmd'])

    def test_poweroff_quantal(self):
        self.conf.store._load_from_string('vm.release = quantal')
        self.ci_data.populate()
        self.assertEqual(['halt'], self.ci_data.cloud_config['runcmd'])

    def test_poweroff_other(self):
        self.conf.store._load_from_string('vm.release = raring')
        self.ci_data.populate()
        self.assertEqual({'mode': 'poweroff'},
                          self.ci_data.cloud_config['power_state'])
        self.assertIs(None, self.ci_data.cloud_config.get('runcmd'))

    def test_update_true(self):
        self.conf.store._load_from_string('vm.update = True')
        self.ci_data.populate()
        cc = self.ci_data.cloud_config
        self.assertTrue(cc['apt_update'])
        self.assertTrue(cc['apt_upgrade'])

    def test_packages(self):
        self.conf.store._load_from_string('vm.packages = bzr,ubuntu-desktop')
        self.ci_data.populate()
        self.assertEqual(['bzr', 'ubuntu-desktop'],
                         self.ci_data.cloud_config['packages'])

    def test_apt_sources(self):
        self.conf.store._load_from_string('''\
vm.release = raring
# Ensure options are properly expanded (and comments supported ;)
_archive_url = http://archive.ubuntu.com/ubuntu
_ppa_url = https://u:p@ppa.lp.net/user/ppa/ubuntu
vm.apt_sources = deb {_archive_url} {vm.release} partner,\
 deb {_archive_url} {vm.release} main,\
 deb {_ppa_url} {vm.release} main|ABCDEF
''')
        self.ci_data.populate()
        self.assertEqual(
            [{'source': 'deb http://archive.ubuntu.com/ubuntu raring partner'},
             {'source': 'deb http://archive.ubuntu.com/ubuntu raring main'},
             {'source':
                  'deb https://u:p@ppa.lp.net/user/ppa/ubuntu raring main',
              'keyid': 'ABCDEF'}],
            self.ci_data.cloud_config['apt_sources'])

    def create_file(self, path, content):
        with open(path, 'wb') as f:
            f.write(content)

    def test_good_ssh_keys(self):
        paths = ('rsa', 'rsa.pub', 'dsa', 'dsa.pub', 'ecdsa', 'ecdsa.pub')
        for path in paths:
            self.create_file(path, '%s\ncontent\n' % (path,))
        paths_as_list = ','.join(paths)
        self.conf.store._load_from_string(
            'vm.ssh_keys = %s' % (paths_as_list,))
        self.ci_data.populate()
        self.assertEqual({'dsa_private': 'dsa\ncontent\n',
                          'dsa_public': 'dsa.pub\ncontent\n',
                          'ecdsa_private': 'ecdsa\ncontent\n',
                          'ecdsa_public': 'ecdsa.pub\ncontent\n',
                          'rsa_private': 'rsa\ncontent\n',
                          'rsa_public': 'rsa.pub\ncontent\n'},
                         self.ci_data.cloud_config['ssh_keys'])

    def test_bad_type_ssh_keys(self):
        self.conf.store._load_from_string('vm.ssh_keys = I-dont-exist')
        self.assertRaises(setup_vm.ConfigValueError, self.ci_data.populate)

    def test_unknown_ssh_keys(self):
        self.conf.store._load_from_string('vm.ssh_keys = rsa.pub')
        self.assertRaises(setup_vm.ConfigPathNotFound, self.ci_data.populate)

    def test_good_ssh_authorized_keys(self):
        paths = ('home.pub', 'work.pub')
        for path in paths:
            self.create_file(path, '%s\ncontent\n' % (path,))
        paths_as_list = ','.join(paths)
        self.conf.store._load_from_string(
            'vm.ssh_authorized_keys = %s' % (paths_as_list,))
        self.ci_data.populate()
        self.assertEqual(['home.pub\ncontent\n', 'work.pub\ncontent\n'],
                         self.ci_data.cloud_config['ssh_authorized_keys'])

    def test_unknown_ssh_authorized_keys(self):
        self.conf.store._load_from_string('vm.ssh_authorized_keys = rsa.pub')
        self.assertRaises(setup_vm.ConfigPathNotFound, self.ci_data.populate)

    def test_unknown_root_script(self):
        self.conf.store._load_from_string('vm.root_script = I-dont-exist')
        self.assertRaises(setup_vm.ConfigPathNotFound, self.ci_data.populate)

    def test_unknown_ubuntu_script(self):
        self.conf.store._load_from_string('vm.ubuntu_script = I-dont-exist')
        self.assertRaises(setup_vm.ConfigPathNotFound, self.ci_data.populate)

    def test_expansion_error_in_script(self):
        root_script_content = '''#!/bin/sh
echo Hello {I_dont_exist}
'''
        with open('root_script.sh', 'w') as f:
            f.write(root_script_content)
        self.conf.store._load_from_string('''\
vm.root_script = root_script.sh
''')
        e = self.assertRaises(errors.ExpandingUnknownOption,
                              self.ci_data.populate)
        self.assertEqual(root_script_content, e.string)

    def test_unknown_uploaded_scripts(self):
        self.conf.store._load_from_string(
            '''vm.uploaded_scripts = I-dont-exist ''')
        e = self.assertRaises(setup_vm.ConfigPathNotFound,
                              self.ci_data.populate)

    def test_root_script(self):
        with open('root_script.sh', 'w') as f:
            f.write('''#!/bin/sh
echo Hello {user}
''')
        self.conf.store._load_from_string('''\
vm.root_script = root_script.sh
user=root
''')
        self.ci_data.populate()
        # The additional newline after the script is expected
        self.assertEqual('''\
#!/bin/sh
cat >~root/setup_vm_post_install <<'EOSETUPVMCONTENTREALLYUNIQUEDONTBREAKFORFUN'
#!/bin/sh
echo Hello root

EOSETUPVMCONTENTREALLYUNIQUEDONTBREAKFORFUN
chown root:root ~root/setup_vm_post_install
chmod 0700 ~root/setup_vm_post_install
''', self.ci_data.root_hook)
        self.assertEqual(['~root/setup_vm_post_install'],
                         self.ci_data.cloud_config['runcmd'])

    def test_ubuntu_script(self):
        with open('ubuntu_script.sh', 'w') as f:
            f.write('''#!/bin/sh
echo Hello {user}
''')
        self.conf.store._load_from_string('''\
vm.ubuntu_script = ubuntu_script.sh
user = ubuntu
''')
        self.ci_data.populate()
        # The additional newline after the script is expected
        self.assertEqual('''\
#!/bin/sh
cat >~ubuntu/setup_vm_post_install <<'EOSETUPVMCONTENTREALLYUNIQUEDONTBREAKFORFUN'
#!/bin/sh
echo Hello ubuntu

EOSETUPVMCONTENTREALLYUNIQUEDONTBREAKFORFUN
chown ubuntu:ubuntu ~ubuntu/setup_vm_post_install
chmod 0700 ~ubuntu/setup_vm_post_install
''', self.ci_data.ubuntu_hook)
        # The command is run as root, so we need to 'su ubuntu' first
        self.assertEqual([['su', '-l',
                          '-c', '~ubuntu/setup_vm_post_install',
                          'ubuntu']],
                         self.ci_data.cloud_config['runcmd'])

    def test_uploaded_scripts(self):
        paths = ('foo', 'bar')
        for path in paths:
            self.create_file(path, '%s\ncontent\n' % (path,))
        paths_as_list = ','.join(paths)
        self.conf.store._load_from_string(
            'vm.uploaded_scripts = %s' % (paths_as_list,))
        self.ci_data.populate()
        self.assertEqual('''\
#!/bin/sh
cat >~ubuntu/setup_vm_uploads <<'EOSETUPVMCONTENTREALLYUNIQUEDONTBREAKFORFUN'
mkdir -p ~ubuntu/bin
cd ~ubuntu/bin
cat >foo <<'EOFfoo'
foo
content

EOFfoo
chmod 0755 foo
cat >bar <<'EOFbar'
bar
content

EOFbar
chmod 0755 bar
EOSETUPVMCONTENTREALLYUNIQUEDONTBREAKFORFUN
chown ubuntu:ubuntu ~ubuntu/setup_vm_uploads
chmod 0700 ~ubuntu/setup_vm_uploads
''',
                         self.ci_data.uploaded_scripts_hook)
        self.assertEqual([['su', '-l',
                          '-c', '~ubuntu/setup_vm_uploads',
                          'ubuntu']],
                         self.ci_data.cloud_config['runcmd'])


class TestCreateUserData(TestCaseWithHome):

    def setUp(self):
        super(TestCreateUserData, self).setUp()
        self.conf = setup_vm.VmStack('foo')
        self.vm = setup_vm.Kvm(self.conf)

    def test_empty_config(self):
        config_dir = os.path.join(self.test_base_dir, 'config')
        os.mkdir(config_dir)
        # The config is *almost* empty, we need to set config_dir though as the
        # user-data needs to be stored there.
        self.conf.store._load_from_string('vm.config_dir=%s' % (config_dir,))
        self.vm.create_user_data()
        self.assertTrue(os.path.exists(self.vm._config_dir))
        self.assertTrue(os.path.exists(self.vm._user_data_path))
        with open(self.vm._user_data_path) as f:
            user_data = f.readlines()
        # We care about the two first lines only here, checking the format (or
        # cloud-init is confused)
        self.assertEqual('#cloud-config-archive\n', user_data[0])
        self.assertEqual("- {content: '#cloud-config\n", user_data[1])


class TestSeed(TestCaseWithHome):

    def setUp(self):
        super(TestSeed, self).setUp()
        self.conf = setup_vm.VmStack('foo')
        self.vm = setup_vm.Kvm(self.conf)
        images_dir = os.path.join(self.test_base_dir, 'images')
        os.mkdir(images_dir)
        config_dir = os.path.join(self.test_base_dir, 'config')
        self.conf.store._load_from_string('''
vm.name=foo
vm.release=raring
vm.config_dir=%s
vm.images_dir=%s
''' % (config_dir, images_dir,))

    def test_create_meta_data(self):
        self.vm.create_meta_data()
        self.assertTrue(os.path.exists(self.vm._meta_data_path))

    def test_create_user_data(self):
        self.vm.create_user_data()
        self.assertTrue(os.path.exists(self.vm._user_data_path))

    def test_create_seed(self):
        self.assertTrue(self.vm._seed_path is None)
        self.vm.create_seed()
        self.assertFalse(self.vm._seed_path is None)
        self.assertTrue(os.path.exists(self.vm._seed_path))


class TestImageFromCloud(TestCaseWithHome):

    def setUp(self):
        super(TestImageFromCloud, self).setUp()
        self.conf = setup_vm.VmStack('foo')
        self.vm = setup_vm.KvmFromCloudImage(self.conf)
        images_dir = os.path.join(self.test_base_dir, 'images')
        os.mkdir(images_dir)
        download_cache_dir = os.path.join(self.test_base_dir, 'download')
        os.mkdir(download_cache_dir)
        self.conf.store._load_from_string('''
vm.name=foo
vm.release=raring
vm.images_dir=%s
vm.download_cache=%s
vm.cloud_image_name=fake.img
vm.disk_size=1M
''' % (images_dir, download_cache_dir))

    def test_create_disk_image(self):
        cloud_image_path = os.path.join(self.conf.get('vm.download_cache'),
                                        self.conf.get('vm.cloud_image_name'))
        # We need a fake cloud image that can be converted
        setup_vm.run_subprocess(
            ['sudo', 'qemu-img', 'create',
             cloud_image_path, self.conf.get('vm.disk_size')])
        self.assertTrue(self.vm._disk_image_path is None)
        self.vm.create_disk_image()
        self.assertFalse(self.vm._disk_image_path is None)
        self.assertTrue(os.path.exists(self.vm._disk_image_path))


class TestImageWithBacking(TestCaseWithHome):

    def setUp(self):
        (download_cache_dir,
         reference_cloud_image_name) = requires_known_reference_image(self)
        super(TestImageWithBacking, self).setUp()
        # We'll share the images_dir between vms
        images_dir = os.path.join(self.test_base_dir, 'images')
        os.mkdir(images_dir)
        # Create a shared config
        conf = setup_vm.VmStack(None)
        conf.store._load_from_string('''
vm.release=raring
vm.images_dir=%s
vm.download_cache=%s
vm.disk_size=2G
[selftest-from-cloud]
vm.name=selftest-from-cloud
vm.cloud_image_name=%s
[selftest-backing]
vm.name=selftest-backing
vm.backing=selftest-from-cloud.qcow2
''' % (images_dir, download_cache_dir, reference_cloud_image_name))
        conf.store.save()
        # To bypass creating a real vm, we start from the cloud image that is a
        # real and bootable one, so we just convert it. That also makes it
        # available in vm.images_dir
        temp_vm = setup_vm.KvmFromCloudImage(
            setup_vm.VmStack('selftest-from-cloud'))
        temp_vm.create_disk_image()

    def test_create_image_with_backing(self):
        vm = setup_vm.KvmFromBacking(setup_vm.VmStack('selftest-backing'))
        self.assertTrue(vm._disk_image_path is None)
        vm.create_disk_image()
        self.assertFalse(vm._disk_image_path is None)
        self.assertTrue(os.path.exists(vm._disk_image_path))


class TestVmStates(testtools.TestCase):

    def assertStates(self, expected, lines):
        self.assertEqual(expected, setup_vm.vm_states(lines))

    def test_empty(self):
        self.assertStates({},[])

    def test_garbage(self):
        self.assertRaises(ValueError, self.assertStates, None, [''])

    def test_known_states(self):
        # From a real life sample
        self.assertStates({'foo': 'shut off', 'bar': 'running'},
                          ['-     foo                            shut off',
                           '19    bar                            running'])


class TestConsoleParsing(testtools.TestCase):

    def _parse_console_monitor(self, string):
        mon = setup_vm.ConsoleMonitor(StringIO(string))
        lines = []
        for line in mon.parse():
            lines.append(line)
        return lines

    def test_fails_on_empty(self):
        self.assertRaises(setup_vm.ConsoleEOFError,
                          self._parse_console_monitor, '')

    def test_fail_on_knwon_cloud_init_errors(self):
        self.assertRaises(
            setup_vm.CloudInitError,
            self._parse_console_monitor,
            'Failed loading yaml blob\n')
        self.assertRaises(
            setup_vm.CloudInitError,
            self._parse_console_monitor,
            'Unhandled non-multipart userdata starting\n')
        self.assertRaises(
            setup_vm.CloudInitError,
            self._parse_console_monitor,
            "failed to render string to stdout: cannot find 'uptime'\n")
        self.assertRaises(
            setup_vm.CloudInitError,
            self._parse_console_monitor,
            "Failed loading of cloud config "
            "'/var/lib/cloud/instance/cloud-config.txt'. "
            "Continuing with empty config\n")

    def test_succeds_on_final_message(self):
        lines = self._parse_console_monitor('''
Lalala
I'm doing my work
It goes nicely
setup_vm finished installing in 1 seconds.
That was fast isn't it ?
 * Will now halt
[   33.204755] Power down.
''')
        # We stop as soon as we get the final message and ignore the rest
        self.assertEquals(' * Will now halt\n',
                          lines[-1])


class TestConsoleParsingWithFile(TestCaseWithHome):

    def _parse_file_monitor(self, string):
        with open('console', 'w') as f:
            f.write(string)
        mon = setup_vm.FileMonitor('console')
        for line in mon.parse():
            pass
        return mon.lines

    def test_succeeds_with_file(self):
        content = '''\
Yet another install
Going well
setup_vm finished installing in 0.5 seconds.
Wow, even faster !
 * Will now halt
Whatever, won't read that
'''
        lines = self._parse_file_monitor(content)

    def xtest_fails_on_empty_file(self):
        # FIXME: We need some sort of timeout there...
        self.assertRaises(setup_vm.CommandError, self._parse_file_monitor, '')

    def test_fail_on_knwon_cloud_init_errors_with_file(self):
        self.assertRaises(
            setup_vm.CloudInitError,
            self._parse_file_monitor,
            'Failed loading yaml blob\n')
        self.assertRaises(
            setup_vm.CloudInitError,
            self._parse_file_monitor,
            'Unhandled non-multipart userdata starting\n')
        self.assertRaises(
            setup_vm.CloudInitError,
            self._parse_file_monitor,
            "failed to render string to stdout: cannot find 'uptime'\n")


class TestInstallWithSeed(TestCaseWithHome):

    def setUp(self):
        (download_cache,
         reference_cloud_image_name) = requires_known_reference_image(self)
        super(TestInstallWithSeed, self).setUp()
        # We need to allow other users to read this dir
        os.chmod(self.test_base_dir, 0755)
        # We also need to sudo rm it as root created some files there
        self.addCleanup(
            setup_vm.run_subprocess,
            ['sudo', 'rm', '-fr',
             os.path.join(self.test_base_dir, 'home', '.virtinst')])
        self.conf = setup_vm.VmStack('selftest-seed')
        self.vm = setup_vm.KvmFromCloudImage(self.conf)
        images_dir = os.path.join(self.test_base_dir, 'images')
        os.mkdir(images_dir, 0755)
        config_dir = os.path.join(self.test_base_dir, 'config')
        self.conf.store._load_from_string('''
vm.name=selftest-seed
vm.update=False # Shorten install time
vm.cpus=2,
vm.release=raring
vm.config_dir=%s
vm.images_dir=%s
vm.download_cache=%s
vm.cloud_image_name=%s
vm.disk_size=8G
''' % (config_dir, images_dir, download_cache, reference_cloud_image_name))

    def assertVmState(self, expected):
        states = setup_vm.vm_states()
        self.assertEqual(expected, states[self.vm.conf.get('vm.name')])

    def test_install_with_seed(self):
        self.addCleanup(self.vm.undefine)
        self.vm.install()
        self.assertVmState('shut off')


class TestInstallWithBacking(TestCaseWithHome):

    def setUp(self):
        (download_cache_dir,
         reference_cloud_image_name) = requires_known_reference_image(self)
        super(TestInstallWithBacking, self).setUp()
        # We need to allow other users to read this dir
        os.chmod(self.test_base_dir, 0755)
        # We also need to sudo rm it as root created some files there
        self.addCleanup(
            setup_vm.run_subprocess,
            ['sudo', 'rm', '-fr',
             os.path.join(self.test_base_dir, 'home', '.virtinst')])
        self.conf = setup_vm.VmStack('selftest-backing')
        self.vm = setup_vm.KvmFromBacking(self.conf)
        # We'll share the images_dir between vms
        images_dir = os.path.join(self.test_base_dir, 'images')
        os.mkdir(images_dir, 0755)
        config_dir = os.path.join(self.test_base_dir, 'config')
        # Create a shared config
        conf = setup_vm.VmStack(None)
        conf.store._load_from_string('''
vm.release=raring
vm.config_dir=%s
vm.images_dir=%s
vm.download_cache=%s
vm.disk_size=2G
vm.update=False # Shorten install time
[selftest-from-cloud]
vm.name=selftest-from-cloud
vm.cloud_image_name=%s
[selftest-backing]
vm.name=selftest-backing
vm.backing=selftest-from-cloud.qcow2
''' % (config_dir, images_dir, download_cache_dir, reference_cloud_image_name))
        conf.store.save()
        # Fake a previous install by just re-using the reference cloud image
        temp_vm = setup_vm.KvmFromCloudImage(
            setup_vm.VmStack('selftest-from-cloud'))
        temp_vm.create_disk_image()

    def assertVmState(self, vm, expected):
        states = setup_vm.vm_states()
        self.assertEqual(expected, states[vm.conf.get('vm.name')])

    def test_install_with_backing(self):
        vm = setup_vm.KvmFromBacking(setup_vm.VmStack('selftest-backing'))
        self.addCleanup(vm.undefine)
        vm.install()
        self.assertVmState(vm, 'shut off')


class TestSshKeyGen(TestCaseWithHome):

    def setUp(self):
        super(TestSshKeyGen, self).setUp()
        self.conf = setup_vm.VmStack(None)
        self.vm = setup_vm.VM(self.conf)
        self.config_dir = os.path.join(self.test_base_dir, 'config')

    def load_config(self, more):
        content = '''\
vm.config_dir=%s
vm.name=foo
''' % (self.config_dir,)
        self.conf.store._load_from_string(content + more)

    def generate_key(self, ssh_type, upper_type=None):
        if upper_type is None:
            upper_type = ssh_type.upper()
        self.load_config('vm.ssh_keys={vm.config_dir}/%s' % (ssh_type,))
        self.vm.ssh_keygen()
        private_path = 'config/%s' % (ssh_type,)
        self.assertTrue(os.path.exists(private_path))
        public_path = 'config/%s.pub' % (ssh_type,)
        self.assertTrue(os.path.exists(public_path))
        public = file(public_path).read()
        private = file(private_path).read()
        self.assertTrue(private.startswith(
                '-----BEGIN %s PRIVATE KEY-----\n' % (upper_type,)))
        self.assertTrue(private.endswith(
                '-----END %s PRIVATE KEY-----\n' % (upper_type,)))
        return private, public

    def test_dsa(self):
        private, public = self.generate_key('dsa')
        self.assertTrue(public.startswith('ssh-dss '))
        self.assertTrue(public.endswith(' foo\n'))

    def test_rsa(self):
        private, public = self.generate_key('rsa')
        self.assertTrue(public.startswith('ssh-rsa '))
        self.assertTrue(public.endswith(' foo\n'))

    def test_ecdsa(self):
        private, public = self.generate_key('ecdsa', 'EC')
        self.assertTrue(public.startswith('ecdsa-sha2-nistp256 '))
        self.assertTrue(public.endswith(' foo\n'))


class TestOptionParsing(testtools.TestCase):

    def setUp(self):
        super(TestOptionParsing, self).setUp()
        self.out = StringIO()
        self.err = StringIO()

    def parse_args(self, args):
        return setup_vm.arg_parser.parse_args(args, self.out, self.err)

    def test_nothing(self):
        self.assertRaises(SystemExit, self.parse_args, [])

    def test_install(self):
        ns = self.parse_args(['foo', '--install'])
        self.assertEquals('foo', ns.name)
        self.assertTrue(ns.install)
        self.assertFalse(ns.download)

    def test_download(self):
        ns = self.parse_args(['foo', '--download'])
        self.assertEquals('foo', ns.name)
        self.assertFalse(ns.install)
        self.assertTrue(ns.download)

class TestBuildCommands(testtools.TestCase):

    def setUp(self):
        super(TestBuildCommands, self).setUp()
        self.out = StringIO()
        self.err = StringIO()

    def build_commands(self, args):
        return setup_vm.build_commands(args, self.out, self.err)

    def test_install(self):
        cmds = self.build_commands(['--install', 'foo'])
        self.assertEqual(1, len(cmds))
        self.assertTrue(isinstance(cmds[0], setup_vm.Install))

    def test_download(self):
        cmds = self.build_commands(['--download', 'foo'])
        self.assertEqual(1, len(cmds))
        self.assertTrue(isinstance(cmds[0], setup_vm.Download))

    def test_ssh_keygen(self):
        cmds = self.build_commands(['--ssh-keygen', 'foo'])
        self.assertEqual(1, len(cmds))
        self.assertTrue(isinstance(cmds[0], setup_vm.SshKeyGen))

    def test_download_and_install(self):
        cmds = self.build_commands(['--install', '--download', 'foo'])
        self.assertEqual(2, len(cmds))
        # Download comes first
        self.assertTrue(isinstance(cmds[0], setup_vm.Download))
        self.assertTrue(isinstance(cmds[1], setup_vm.Install))


# FIXME: This needs to be parametrized for KvmFromCloudImage and
# KvmFromBacking. Since we don't define vm.backing below, we're only testing
# KvmFromCloudImage for now. -- vila 2013-02-13
class TestInstall(TestCaseWithHome):

    def setUp(self):
        super(TestInstall, self).setUp()
        self.conf = setup_vm.VmStack('I-dont-exist')
        self.conf.store._load_from_string('''
vm.name=I-dont-exist
vm.release=raring
vm.cpu_model=amd64
''')
        self.states = []

        def vm_states(source=None):
            return self.states
        self.patch(setup_vm, 'vm_states', vm_states)
        self.vm = None

    def install(self):
        class FakeKvm(setup_vm.Kvm):

            def __init__(self, conf):
                super(FakeKvm, self).__init__(conf)
                self.undefine_called = False
                self.install_called = False

            # Make sure we avoid dangerous or costly calls
            def poweroff(self):
                pass

            def undefine(self):
                self.undefine_called = True

            def install(self):
                self.install_called = True


        self.vm = FakeKvm(self.conf)
        cmd = setup_vm.Install(self.vm)
        cmd.run()

    def test_install_while_running(self):
        self.conf.set('vm.name', 'foo')
        self.states = {'foo': 'running'}
        self.assertRaises(setup_vm.SetupVmError, self.install)
        self.assertFalse(self.vm.install_called)
        self.assertFalse(self.vm.undefine_called)

    def test_install_unknown(self):
        self.states = {}
        self.install()
        self.assertTrue(self.vm.install_called)
        self.assertFalse(self.vm.undefine_called)

    def test_install_shutoff(self):
        self.conf.set('vm.name', 'foo')
        self.states = {'foo': 'shut off'}
        self.install()
        self.assertTrue(self.vm.install_called)
        self.assertTrue(self.vm.undefine_called)
