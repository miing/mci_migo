#!/usr/bin/env python
"""
Setup a virtual machine from a config file.

Note: Most of the operations requires root access and this script uses ``sudo``
to get them.

"""
import argparse
import base64
from cStringIO import StringIO
import errno
import os
import subprocess
import sys
import tempfile
import time


from bzrlib import (
    config,
    osutils,
    transport,
    urlutils,
    )
import yaml

# Work around a bug in bzrlib.config forbidding some constructs in templates.
# Namely, spaces are invalid as an identifier and therefore should not match
# below.
config._option_ref_re = config.lazy_regex.lazy_compile('({[^ {},\n]+})')


class VmMatcher(config.NameMatcher):

    def match(self, section):
        if section.id is None:
            # The no name section contains default values
            return True
        return super(VmMatcher, self).match(section)

    def get_sections(self):
        matching_sections = super(VmMatcher, self).get_sections()
        return reversed(list(matching_sections))


class VmStore(config.LockableIniFileStore):
    """A config store for options specific to a directory."""

    def __init__(self, directory, file_name, possible_transports=None):
        t = transport.get_transport_from_path(
            directory, possible_transports=possible_transports)
        super(VmStore, self).__init__(t, file_name)
        self.id = 'vm'


def system_config_dir():
    return '/etc/libvirt'


class VmStack(config.Stack):
    """Per-directory options."""

    def __init__(self, name):
        """Make a new stack for a given vm.

        The following sections are queried:

        * the ``name`` section in ./vms.conf,
        * the no-name section in ./vms.conf
        * the ``name`` section in ~/vms.conf,
        * the no-name section in ~/vms.conf
        * the ``name`` section in /etc/libvirt/vms.conf,
        * the no-name section in /etc/libvirt/vms.conf

        :param name: The name of a virtual machine.
        """
        self.local_store = VmStore('.', 'vms.conf')
        user_store = VmStore(os.environ['HOME'], 'vms.conf')
        self.system_store = VmStore(system_config_dir(), 'vms.conf')
        # FIXME: Only available in bzr-2.6b3 :-/ -- vila 2012-01-31
        # dstore = self.get_shared_store()
        super(VmStack, self).__init__(
            [VmMatcher(self.local_store, name).get_sections,
             VmMatcher(user_store, name).get_sections,
             VmMatcher(self.system_store, name).get_sections,
             ],
            user_store, mutable_section_id=name)


def path_from_unicode(path_string):
    if not isinstance(path_string, basestring):
        raise TypeError
    return os.path.expanduser(path_string)


class PathOption(config.Option):

    def __init__(self, *args, **kwargs):
        """A path option definition.

        This possibly expands the user home directory.
        """
        super(PathOption, self).__init__(
            *args, from_unicode=path_from_unicode, **kwargs)


def register(option):
    config.option_registry.register(option)


register(config.Option(
        'vm', default=None,
        help='''The name space defining a virtual machine.

This option is a place holder to document the options that defines a virtual
machine and the options defining the infrastructure used to manage them all.

For qemu based vms, the definition of a vm is stored in an xml file under
'/etc/libvirt/qemu/{vm.name}.xml'. This is under the libvirt package control
and is out of scope for setup_vm.py.

There are 3 other significant files used for a given vm:

- a disk image mounted at '/' from '/dev/sda1':
  '{vm.images_dir}/{vm.name}.qcow2'

- a iso image available from '/dev/sdb' labeled 'cidata':
  {vm.images_dir}/{vm.name}.seed which contains the cloud-init data used to
  configure/install/update the vm.

- a console: {vm.images_dir}/{vm.name}.console which can be 'tail -f'ed from
  the host.

The data used to create the seed above are stored in a vm specific
configuration directory for easier debug and reference:
- {vm.config_dir}/user-data
- {vm.config_dir}/meta-data
- {vm.config_dir}/ecdsa
- {vm.config_dir}/ecdsa.pub
'''))

# The directory where we store vm files related to their configuration with
# cloud-init (user-data, meta-data, ssh keys).
register(config.Option(
        'vm.vms_dir', default='~/.config/setup_vm',
        help='''Where vm related config files are stored.

This includes user-data and meta-data for cloud-init and ssh server keys.

This directory must exist.

Each vm get a specific directory (automatically created) there based on its
name.
'''))
# The base directories where vms are stored for kvm
register(PathOption(
        'vm.images_dir', default='/var/lib/libvirt/images',
        help="Where vm disk images are stored.",
        ))
register(config.Option(
        'vm.qemu_etc_dir',
        default='/etc/libvirt/qemu',
        help="Where libvirt (qemu) stores the vms config files."
        ))

# Isos and images download handling
register(config.Option(
        'vm.iso_url',
        default='http://cdimage.ubuntu.com/daily-live/current/' ,
        help="Where an iso can be downloaded from."
        ))
register(config.Option(
        'vm.iso_name',
        default='{vm.release}-desktop-{vm.cpu_model}.iso',
        help="The name of the iso."
        ))
register(config.Option(
        'vm.cloud_image_url',
        default='http://cloud-images.ubuntu.com/{vm.release}/current/',
        help="Where a cloud image can be downloaded from."
        ))
register(config.Option(
        'vm.cloud_image_name',
        default='{vm.release}-server-cloudimg-{vm.cpu_model}-disk1.img',
        help="The name of the cloud image."
        ))
register(PathOption(
        'vm.download_cache',
        default='{vm.images_dir}',
        help="Where downloads end up.",
        ))

# The ubiquitous vm name
register(config.Option(
        'vm.name', default=None, invalid='error',
        help="The vm name, used as a prefix for related files."
        ))
# The second most important bit to define a vm: which ubuntu release ?
register(config.Option(
        'vm.release', default=None, invalid='error',
        help="The ubuntu release name."
        ))
# The third important piece to define a vm: where to store files like the
# console, the user-data and meta-data files, the ssh server keys, etc.
register(config.Option(
        'vm.config_dir', default='{vm.vms_dir}/{vm.name}',
        invalid='error',
        help='''The directory where files specific to a vm are stored.

This includes the user-data and meta-data files used at install time (for
reference and easier debug) as well as the optional ssh server keys.

By default this is {vm.vms_dir}/{vm.name}. You can put it somewhere else by
redifining it as long as it ends up being unique for the vm.

{vm.vms_dir}/{vm.release}/{vm.name} may better suit your taste for example.
'''
        ))
# The options defining the vm physical characteristics
register(config.Option(
        'vm.ram_size', default='1024',
        help="The ram size in megabytes."
        ))
register(config.Option(
        'vm.disk_size', default='8G',
        help='''The disk image size in bytes.

Optional suffixes "k" or "K" (kilobyte, 1024) "M" (megabyte, 1024k) "G"
(gigabyte, 1024M) and T (terabyte, 1024G) are supported.
'''))
register(config.Option(
        'vm.cpus', default='1',
        help="The number of cpus."
        ))
register(config.Option(
        'vm.cpu_model', default=None, invalid='error',
        help="The number of cpus."))
register(config.Option(
        'vm.network', default='network=default', invalid='error',
        help="""The --network parameter for virt-install.

This can be specialized for each machine but the default should work in most
setups. Watch for your DHCP server exhausting its address space if you create a
lot of vms with random MAC addresses.
"""))

register(config.Option(
        'vm.meta_data', default='''\
instance-id: {vm.name}
local-hostname: {vm.name}
''',
        invalid='error',
        help="The meta data for cloud-init to put in the seed."
        ))

# Some bits that may added to user-data but are optional

register(config.ListOption(
        'vm.packages', default=None,
        help='''A list of package names to be installed.
'''))
register(config.Option(
        'vm.apt_proxy', default=None, invalid='error',
        help='''A local proxy for apt to avoid repeated .deb downloads.

Example:

  vm.apt_proxy = http://192.168.0.42:8000

'''))
register(config.ListOption(
        'vm.apt_sources', default=None,
        help='''A list of apt sources entries to be added to the default ones.

Cloud-init already setup /etc/apt/sources.list with appropriate entries. Only
additional entries need to be specified here.
'''))
register(config.ListOption(
        'vm.ssh_authorized_keys', default=None,
        help='A list of paths to public ssh keys to be authorized for'
        ' the default user.'))
register(config.ListOption(
        'vm.ssh_keys', default=None,
        help='''A list of paths to server ssh keys.

Both public and private keys can be provided. Accepted ssh key types are rsa,
dsa and ecdsa. The file names should match <type>.*[.pub].
'''))
register(config.Option(
        'vm.update', default=False,
        from_unicode=config.bool_from_store,
        help='''Whether or not the vm should be updated.
Both apt-get update and apt-get upgrade are called if this option is set.
'''))
register(config.Option(
        'vm.password', default='ubuntu', invalid='error',
        help="The ubuntu user password."
        ))
register(config.Option(
        'vm.launchpad_id',
        help="The launchpad login used for launchpad ssh access from the guest."
        ))
# The scripts that are executed before powering off
register(PathOption(
        'vm.root_script', default=None,
        help='''The path to a script executed as root before powering off.

This script is executed before {vm.ubuntu_script}.
'''
        ))
register(PathOption(
        'vm.ubuntu_script', default=None,
        help='''The path to a script executed as ubuntu before powering off.

This script is excuted after {vm.root_script}.
'''))
register(config.ListOption(
        'vm.uploaded_scripts', default=None,
        help='''A list of scripts to be uploaded to the guest.

Scripts can use config options from their vm, they will be expanded before
upload. All scripts are uploaded into {vm.uploaded_scripts.guest_dir} under
their base name.
'''))
register(config.Option(
        'vm.uploaded_scripts.guest_dir', default='~ubuntu/bin',
        help='''Where {vm.uploaded_scripts} are uploaded on the guest.'''
        ))


class SetupVmError(Exception):

    msg = 'setup_vm Generic Error: %r'

    def __init__(self, msg=None, **kwds):
        if msg is not None:
            self.msg = msg
        for key, value in kwds.items():
            setattr(self, key, value)

    def __str__(self):
        return self.msg.format((), **self.__dict__)

    __repr__ = __str__


class CommandError(SetupVmError):

    msg = '''
  command: {joined_cmd}
  retcode: {retcode}
  output: {out}
  error: {err}
'''

    def __init__(self, cmd, retcode, out, err):
        super(CommandError, self).__init__(joined_cmd=' '.join(cmd),
                                           retcode=retcode, err=err, out=out)

class ConfigValueError(SetupVmError):

    msg = 'Bad value "{value}" for option "{name}".'

    def __init__(self, name, value):
        super(ConfigValueError, self).__init__(name=name, value=value)


class ConfigPathNotFound(SetupVmError):

    msg = 'No such file: {path} from {name}'

    def __init__(self, path, name):
        super(ConfigPathNotFound, self).__init__(path=path, name=name)


def run_subprocess(args):
    proc = subprocess.Popen(args,
                            stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE,
                            stdin=subprocess.PIPE)
    out, err = proc.communicate()
    if proc.returncode:
        raise CommandError(args, proc.returncode, out, err)
    return proc.returncode, out, err


def pipe_subprocess(args):
    proc = subprocess.Popen(args,
                            stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    return proc

def ssh_infos_from_path(key_path):
    """Analyze path to find ssh key type and kind.

    The basename should begin with ssh type used to create the key. and end
    with '.pub' for a public key.

    If the type is neither of rds, dsa or ecdsa, None if returned.

    :param key_path: A path to an ssh key.

    :return: (type, kind) 'type' is the ssh key type or None if neither of rds,
        dsa or ecdsa. 'kind' is 'public' if the path ends with '.pub',
        'private' otherwise.
    """
    base = os.path.basename(key_path)
    for p in ('rsa', 'dsa', 'ecdsa'):
        if base.startswith(p):
            ssh_type = p
            break
    else:
        ssh_type = None
    if base.endswith('.pub'):
        kind = 'public'
    else:
        kind = 'private'
    return ssh_type, kind


class ConsoleEOFError(SetupVmError):

    msg = 'Encountered EOF on console, something went wrong'


class CloudInitError(SetupVmError):

    msg = 'cloud-init reported: {line} check your config'

    def __init__(self, line):
        super(CloudInitError, self).__init__(line=line)


class ConsoleMonitor(object):
    """Monitor a console to identify known events."""

    def __init__(self, stream):
        super(ConsoleMonitor, self).__init__()
        self.stream = stream


    def parse(self):
        while True:
            line = self.stream.readline()
            yield line
            if not line:
                raise ConsoleEOFError()
            elif line.startswith(' * Will now halt'):
                # That's our final_message, we're done
                return
            elif ('Failed loading yaml blob' in line
                  or 'Unhandled non-multipart userdata starting' in line
                  or 'failed to render string to stdout:' in line
                  or 'Failed loading of cloud config' in line):
                raise CloudInitError(line)


class FileMonitor(ConsoleMonitor):

    def __init__(self, path):
        cmd = ['tail', '-f', path]
        proc = pipe_subprocess(cmd)
        super(FileMonitor, self).__init__(proc.stdout)
        self.path = path
        self.cmd = cmd
        self.proc = proc
        self.lines = []

    def parse(self):
        try:
            for line in super(FileMonitor, self).parse():
                self.lines.append(line)
                yield line
        finally:
            self.proc.terminate()


class CIUserData(object):
    """Maps configuration data into cloud-init user-data.

    This is a container for the data that will ultimately be encoded into a
    cloud-config-archive user-data file.
    """

    def __init__(self, conf):
        super(CIUserData, self).__init__()
        self.conf = conf
        # The objects we will populate before creating a yaml encoding as a
        # cloud-config-archive file
        self.cloud_config = {}
        self.root_hook = None
        self.ubuntu_hook = None
        self.launchpad_hook = None
        self.uploaded_scripts_hook = None

    def set(self, ud_name, conf_name=None, value=None):
        """Set a user-data option from it's corresponding configuration one.

        :param ud_name: user-data key.

        :param conf_name: configuration key, If set to None, `value` should be
            provided.

        :param value: value to use if `conf_name` is None.
        """
        if value is None and conf_name is not None:
            value = self.conf.get(conf_name)
        if value is not None:
            self.cloud_config[ud_name] = value

    def _file_content(self, path, option_name):
        full_path = os.path.expanduser(path)
        try:
            with open(full_path) as f:
                content = f.read()
        except IOError, e:
            if e.args[0] == errno.ENOENT:
                raise ConfigPathNotFound(path, option_name)
            else:
                raise
        return content

    def set_list_of_paths(self, ud_name, conf_name):
        """Set a user-data option from its corresponding configuration one.

        The configuration option is a list of paths and the user-data option
        will be a list of each file content.

        :param ud_name: user-data key.

        :param conf_name: configuration key.
        """
        paths = self.conf.get(conf_name)
        if paths:
            contents = []
            for p in paths:
                contents.append(self._file_content(p, conf_name))
            self.set(ud_name, None, contents)

    def _key_from_path(self, path, option_name):
        """Infer user-data key from file name."""
        ssh_type, kind = ssh_infos_from_path(path)
        if ssh_type is None:
            raise ConfigValueError(option_name, path)
        return '%s_%s' % (ssh_type, kind)

    def set_ssh_keys(self):
        """Set the server ssh keys from a list of paths.

        Provided paths should respect some coding:

        - the base name should start with the ssh type of their key (rsa, dsa,
          ecdsa),

        - base names ending with '.pub' are for public keys, the others are for
          private keys.
        """
        key_paths = self.conf.get('vm.ssh_keys')
        if key_paths:
            ssh_keys = {}
            for p in key_paths:
                key = self._key_from_path(p, 'vm.ssh_keys')
                ssh_keys[key] = self._file_content(p, 'vm.ssh_keys')
            self.set('ssh_keys', None, ssh_keys)

    def set_apt_sources(self):
        sources = self.conf.get('vm.apt_sources')
        if sources:
            apt_sources = []
            for src in sources:
                # '|' should not appear in urls nor keys so it should be safe
                # to use it as a separator.
                parts = src.split('|')
                if len(parts) == 1:
                    apt_sources.append({'source': parts[0]})
                else:
                    # For PPAs, an additional GPG key should be imported in the
                    # guest.
                    apt_sources.append({'source': parts[0], 'keyid': parts[1]})
            self.cloud_config['apt_sources'] = apt_sources

    def append_cmd(self, cmd):
        cmds = self.cloud_config.get('runcmd', [])
        cmds.append(cmd)
        self.cloud_config['runcmd'] = cmds

    def _hook_script_path(self, user):
        return '~%s/setup_vm_post_install' % (user,)

    def _hook_content(self, option_name, user, hook_path, mode='0700'):
        # FIXME: Add more tests towards properly creating a tree on the guest
        # from a tree on the host. There seems to be three kind of items worth
        # caring about here: file content (output path, owner, chmod), file
        # (input and output paths, owner, chmod) and directory (path, owner,
        # chmod). There are also some subtle traps involved about when files
        # are created across various vm generations (one vm creates a dir, a mv
        # on top of that one doesn't, but still creates a file in this dir,
        # without realizing it can fail in a fresh vm). -- vila 2013-03-10
        host_path = self.conf.get(option_name)
        if host_path is None:
            return None
        fcontent = self._file_content(host_path, option_name)
        # Expand options in the provided content so we report better errors
        expanded_content = self.conf.expand_options(fcontent)
        # The following will generate an additional newline at the end of the
        # script. I can't think of a case where it matters and it makes this
        # code more robust (and/or simpler) if the script/file *doesn't* end up
        # with a proper newline.
        # FIXME: This may be worth fixing if we provide a more generic way to
        # create a remote tree. -- vila 2013-03-10
        hook_content = '''#!/bin/sh
cat >{__guest_path} <<'EOSETUPVMCONTENTREALLYUNIQUEDONTBREAKFORFUN'
{__fcontent}
EOSETUPVMCONTENTREALLYUNIQUEDONTBREAKFORFUN
chown {__user}:{__user} {__guest_path}
chmod {__mode} {__guest_path}
'''
        return hook_content.format(__user=user, __fcontent=expanded_content,
                                   __mode=mode,
                                   __guest_path=hook_path)

    def set_boot_hook(self):
        # FIXME: Needs a test ensuring we execute as root -- vila 2013-03-07
        hook_path = self._hook_script_path('root')
        content = self._hook_content('vm.root_script', 'root', hook_path)
        if content is not None:
            self.root_hook = content
            self.append_cmd(hook_path)

    def set_ubuntu_hook(self):
        # FIXME: Needs a test ensuring we execute as ubuntu -- vila 2013-03-07
        hook_path = self._hook_script_path('ubuntu')
        content = self._hook_content('vm.ubuntu_script', 'ubuntu', hook_path)
        if content is not None:
            self.ubuntu_hook = content
            self.append_cmd(['su', '-l', '-c', hook_path, 'ubuntu'])

    def set_launchpad_access(self):
        # FIXME: Needs a test that we can really access launchpad properly via
        # ssh. Can only be done as a real launchpad user and as such requires
        # cooperation :) I.e. Some configuration option set by the user will
        # trigger the test -- vila 2013-03-14
        lp_id = self.conf.get('vm.launchpad_id')
        if lp_id is None:
            return
        # Use the specified ssh key found in ~/.ssh as the private key. The
        # user is supposed to have uploaded the public one.
        local_path = os.path.join('~', '.ssh', '%s@setup_vm' % (lp_id,))
        # Force id_rsa or we'll need a .ssh/config to point to user@setup_vm
        # for .lauchpad.net.
        hook_path = '/home/ubuntu/.ssh/id_rsa'
        dir_path = os.path.dirname(hook_path)
        try:
            fcontent = self._file_content(local_path, 'vm.launchpad_id')
        except ConfigPathNotFound, e:
            e.msg = ('You need to create the {p} keypair and upload {p}.pub to'
                     ' launchpad.\n'
                     'See vm.launchpad_id in README.'.format(p=local_path))
            raise e
        # FIXME: ~Duplicated from _hook_content. -- vila 2013-03-10

        # FIXME: If this hook is executed before the ubuntu user is created we
        # need to chown/chmod ~ubuntu which is bad. This happens when a
        # -pristine vm is created and lead to GUI login failing because it
        # can't create any dir/file there. The fix is to only create a script
        # that will be executed via runcmd so it will run later and avoid the
        # issue. -- vila 2013-03-21
        hook_content = '''#!/bin/sh
mkdir -p {dir_path}
chown {user}:{user} ~ubuntu
chmod {dir_mode} ~ubuntu
chown {user}:{user} {dir_path}
chmod {dir_mode} {dir_path}
cat >{guest_path} <<'EOSETUPVMCONTENTREALLYUNIQUEDONTBREAKFORFUN'
{fcontent}
EOSETUPVMCONTENTREALLYUNIQUEDONTBREAKFORFUN
chown {user}:{user} {guest_path}
chmod {file_mode} {guest_path}
'''
        self.launchpad_hook = self.conf.expand_options(
            hook_content,
            env=dict(user='ubuntu', fcontent=fcontent,
                     file_mode='0400', guest_path=hook_path,
                     dir_mode='0700', dir_path=dir_path))
        self.append_cmd(['sudo', '-u', 'ubuntu',
                         'bzr', 'launchpad-login', lp_id])

    def set_uploaded_scripts(self):
        script_paths = self.conf.get('vm.uploaded_scripts')
        if not script_paths:
            return
        hook_path = '~ubuntu/setup_vm_uploads'
        bindir = self.conf.get('vm.uploaded_scripts.guest_dir')
        out = StringIO()
        out.write('''#!/bin/sh
cat >{hook_path} <<'EOSETUPVMCONTENTREALLYUNIQUEDONTBREAKFORFUN'
mkdir -p {bindir}
cd {bindir}
'''.format(**locals()))
        for path in script_paths:
            fcontent = self._file_content(path, 'vm.uploaded_scripts')
            expanded = self.conf.expand_options(fcontent)
            base = os.path.basename(path)
            # FIXME: ~Duplicated from _hook_content. -- vila 2012-03-15
            out.write('''cat >{base} <<'EOF{base}'
{expanded}
EOF{base}
chmod 0755 {base}
'''.format(**locals()))

        out.write('''EOSETUPVMCONTENTREALLYUNIQUEDONTBREAKFORFUN
chown {user}:{user} {hook_path}
chmod 0700 {hook_path}
'''.format(user='ubuntu',**locals()))
        self.uploaded_scripts_hook = out.getvalue()
        self.append_cmd(['su', '-l', '-c', hook_path, 'ubuntu'])

    def set_poweroff(self):
        # We want to shutdown properly after installing. This is safe to set
        # here as subsequent boots will ignore this setting, letting us use the
        # vm ;)
        if self.conf.get('vm.release') in ('precise', 'quantal'):
            # Curse cloud-init lack of compatibility
            self.append_cmd('halt')
        else:
            self.set('power_state', None, {'mode': 'poweroff'})

    def populate(self):
        # Common and non-configurable options
        if self.conf.get('vm.release') == 'precise':
            # Curse cloud-init lack of compatibility
            msg = 'setup_vm finished installing in $UPTIME seconds.'
        else:
            msg = 'setup_vm finished installing in ${uptime} seconds.'
        self.set('final_message', None, msg)
        self.set('manage_etc_hosts', None, True)
        self.set('chpasswd', None, dict(expire=False))
        # Configurable options
        self.set('password', 'vm.password')
        self.set_list_of_paths('ssh_authorized_keys', 'vm.ssh_authorized_keys')
        self.set_ssh_keys()
        self.set('apt_proxy', 'vm.apt_proxy')
        # Both user-data keys are set from the same config key, we don't
        # provide a finer access.
        self.set('apt_update', 'vm.update')
        self.set('apt_upgrade', 'vm.update')
        self.set_apt_sources()
        self.set('packages', 'vm.packages')
        self.set_launchpad_access()
        # uploaded scripts
        self.set_uploaded_scripts()
        # The commands executed before powering off
        self.set_boot_hook()
        self.set_ubuntu_hook()
        # This must be called last so previous commands (for precise and
        # quantal) can be executed before powering off
        self.set_poweroff()

    def add_boot_hook(self, parts, hook):
        if hook is not None:
            parts.append({'content': '#cloud-boothook\n' +  hook})

    def dump(self):
        parts = [{'content': '#cloud-config\n'
                  + yaml.safe_dump(self.cloud_config)}]
        self.add_boot_hook(parts, self.root_hook)
        self.add_boot_hook(parts, self.ubuntu_hook)
        self.add_boot_hook(parts, self.launchpad_hook)
        self.add_boot_hook(parts, self.uploaded_scripts_hook)
        # Wrap the lot into a cloud config archive
        return '#cloud-config-archive\n' + yaml.safe_dump(parts)


def vm_states(source=None):
    """A dict of states for vms indexed by name.

    :param source: A list of lines as produced by virsh list --all without
        decorations (header/footer).
    """
    if source is None:
        retcode, out, err = run_subprocess(['virsh', 'list', '--all'])
        # Get rid of header/footer
        source = out.splitlines()[2:-1]
    states = {}
    for line in source:
        caret_or_id, name, state = line.split(None, 2)
        states[name] = state
    return states


class VM(object):

    def __init__(self, conf):
        self.conf = conf
        self._config_dir = None

    def ensure_dir(self, path):
        try:
            os.mkdir(path)
        except OSError, e:
            # FIXME: Try to create the parent dir ?
            if e.errno == errno.EEXIST:
                pass
            else:
                raise

    def ensure_config_dir(self):
        if self._config_dir is None:
            # FIXME: expanduser is not tested
            self._config_dir = os.path.expanduser(
                self.conf.get('vm.config_dir'))
            self.ensure_dir(self._config_dir)

    def _ssh_keygen(self, key_path):
        ssh_type, kind = ssh_infos_from_path(key_path)
        path = os.path.expanduser(key_path) # Just in case
        if kind == 'private': # public will be generated at the same time
            run_subprocess(
                ['ssh-keygen', '-f', path, '-N', '', '-t', ssh_type,
                 '-C', self.conf.get('vm.name')])

    def ssh_keygen(self):
        self.ensure_config_dir()
        keys = self.conf.get('vm.ssh_keys')
        for key in keys:
            self._ssh_keygen(key)


class Kvm(VM):

    def __init__(self, conf):
        super(Kvm, self).__init__(conf)
        # Seed files
        self._meta_data_path = None
        self._user_data_path = None
        # Disk paths
        self._seed_path = None
        self._disk_image_path = None

        self._console_path = None

    def _download_in_cache(self, source_url, name, force=False):
        """Download ``name`` from ``source_url`` in ``vm.download_cache``.

        :param source_url: The url where the file to download is located

        :param name: The name of the file to download (also used as the name
            for the downloaded file).

        :param force: Remove the file from the cache if present.

        :return: False if the file is in the download cache, True if a download
            occurred.
        """
        source = urlutils.join(source_url, name)
        download_dir = self.conf.get('vm.download_cache')
        if not os.path.exists(download_dir):
            raise ConfigValueError('vm.download_cache', download_dir)
        target = os.path.join(download_dir, name)
        # FIXME: By default the download dir may be under root control, but if
        # a user chose to use a different one under his own control, it would
        # be nice to not require sudo usage. -- vila 2013-02-06
        if force:
            run_subprocess(['sudo', 'rm', '-f', target])
        if not os.path.exists(target):
            # FIXME: We do ask for a progress bar but it's not displayed
            # (run_subprocess capture both stdout and stderr) ! At least while
            # used interactively, it should. -- vila 2013-02-06
            run_subprocess(['sudo', 'wget', '--progress=dot:mega','-O',
                            target, source])
            return True
        else:
            return False

    def download_iso(self, force=False):
        """Download the iso to install the vm.

        :return: False if the iso is in the download cache, True if a download
            occurred.
        """
        return self._download_in_cache(self.conf.get('vm.iso_url'),
                                       self.conf.get('vm.iso_name'),
                                       force=force)

    def download_cloud_image(self, force=False):
        """Download the cloud image to install the vm.

        :return: False if the image is in the download cache, True if a
            download occurred.
        """
        return self._download_in_cache(self.conf.get('vm.cloud_image_url'),
                                       self.conf.get('vm.cloud_image_name'),
                                       force=force)

    def create_meta_data(self):
        self.ensure_config_dir()
        self._meta_data_path = os.path.join(self._config_dir, 'meta-data')
        with open(self._meta_data_path, 'w') as f:
            f.write(self.conf.get('vm.meta_data'))

    def create_user_data(self):
        ci_user_data = CIUserData(self.conf)
        ci_user_data.populate()
        self.ensure_config_dir()
        self._user_data_path = os.path.join(self._config_dir, 'user-data')
        with open(self._user_data_path, 'w') as f:
            f.write(ci_user_data.dump())

    def create_seed(self):
        if self._meta_data_path is None:
            self.create_meta_data()
        if self._user_data_path is None:
            self.create_user_data()
        images_dir = self.conf.get('vm.images_dir')
        seed_path = os.path.join(
            images_dir, self.conf.expand_options('{vm.name}.seed'))
        run_subprocess(
            # We create the seed in the ``vm.images_dir`` directory, so
            # ``sudo`` is required
            ['sudo',
             'genisoimage', '-output', seed_path, '-volid', 'cidata',
             '-joliet', '-rock', '-input-charset', 'default',
             '-graft-points',
             'user-data=%s' % (self._user_data_path,),
             'meta-data=%s' % (self._meta_data_path,),
             ])
        self._seed_path = seed_path

    def create_disk_image(self):
        raise NotImplementedError(self.create_disk_image)

    def _wait_for_install_with_seed(self):
        # The console is created by virt-install which requires sudo but creates
        # the file 0600 for libvirt-qemu. We give read access to all otherwise
        # 'tail -f' requires sudo and can't be killed anymore.
        run_subprocess(['sudo', 'chmod', '0644', self._console_path])
        # While `virt-install` is running, let's connect to the console
        console = FileMonitor(self._console_path)
        try:
            for line in console.parse():
# FIXME: We need some way to activate this dynamically (conf var defaulting to
# env var OR cmdline parameter ? -- vila 2013-02-11
#                print "read: [%s]" % (line,) # so useful for debug...
                pass
        except (ConsoleEOFError, CloudInitError), e:
            # FIXME: No test covers this path -- vila 2013-02-15
            err_lines = ['Suspicious line from cloud-init.\n',
                         '\t' + console.lines[-1],
                         'Check the configuration:\n']
            with open(self._meta_data_path) as f:
                err_lines.append('meta-data content:\n')
                err_lines.extend(f.readlines())
            with open(self._user_data_path) as f:
                err_lines.append('user-data content:\n')
                err_lines.extend(f.readlines())
            raise CommandError(console.cmd, console.proc.returncode,
                               '\n'.join(console.lines),
                               ''.join(err_lines))

    def install(self):
        # Create a kvm, relying on cloud-init to customize the base image.
        #  
        # There are two processes involvded here:
        # - virt-install creates the vm and boots it.
        # - progress is monitored via the console to detect cloud-final.
        #  
        # Once cloud-init has finished, the vm can be powered off.

        # FIXME: If the install doesn't finish after $time, emit a warning and
        # terminate self.install_proc.
        # FIXME: If we can't connect to the console, emit a warning and
        # terminate console and self.install_proc.
        # FIXME: If we don't receive anything on the console after $time2, emit
        # a warning and terminate console and self.install_proc.
        # -- vila 2013-02-07
        if self._seed_path is None:
            self.create_seed()
        if self._disk_image_path is None:
            self.create_disk_image()
        # FIXME: Install time is probably a good time to delete the
        # console. While it makes sense to accumulate for all runs for a given
        # install, keeping them without any limit nor roration is likely to
        # cause issues at some point... -- vila 2013-02-20
        self._console_path = os.path.join(
            self.conf.get('vm.images_dir'),
            '%s.console' % (self.conf.get('vm.name'),))
        run_subprocess(
            ['sudo', 'virt-install',
             # To ensure we're not bitten again by http://pad.lv/1157272 where
             # virt-install wrongly detect virtualbox. -- vila 2013-03-20
             '--connect', 'qemu:///system',
             # Without --noautoconsole, virt-install will relay the console,
             # that's not appropriate for our needs so we'll connect later
             # ourselves
             '--noautoconsole',
             # We define the console as a file so we can monitor the install
             # via 'tail -f'
             '--serial', 'file,path=%s' % (self._console_path,),
             '--network', self.conf.get('vm.network'),
             # Anticipate that we'll need a graphic card defined
             '--graphics', 'spice',
             '--name', self.conf.get('vm.name'),
             '--ram', self.conf.get('vm.ram_size'),
             '--vcpus', self.conf.get('vm.cpus'),
             '--disk', 'path=%s,format=qcow2' % (self._disk_image_path,),
             '--disk', 'path=%s' % (self._seed_path,),
             # We just boot, cloud-init will handle the installs we need
             '--boot', 'hd', '--hvm',
             ])
        self._wait_for_install_with_seed()
        # We've seen the console signaling halt, but the vm will need a bit
        # more time to get there so we help it a bit.
        if self.conf.get('vm.release') in ('precise', 'quantal'):
            # cloud-init doesn't implement power_state until raring and need a
            # gentle nudge.
            self.poweroff()
        vm_name = self.conf.get('vm.name')
        while True:
            state = vm_states()[vm_name]
            # We expect the vm's state to be 'in shutdown' but in some rare
            # occasions we may catch 'running' before getting 'in shutdown'.
            if state in ('in shutdown', 'running'):
                # Ok, querying the state takes time, this regulates the polling
                # enough that we don't need to sleep.
                continue
            elif state == 'shut off':
                # Good, we're done
                break
            # FIXME: No idea on how to test the following. Manually tested by
            # altering the expected state above and running 'selftest.py -v'
            # which errors out for test_install_with_seed and
            # test_install_backing. Also reproduced when 'running' wasn't
            # expected before 'in shutdown' -- vila 2013-02-19
            # Unexpected state reached, bad.
            raise SetupVmError('Something went wrong during {name} install\n'
                               'The vm ended in state: {state}\n'
                               'Check the console at {path}',
                               name=vm_name, state=state,
                               path=self._console_path)

    def poweroff(self):
        return run_subprocess(
            ['sudo', 'virsh', 'destroy', self.conf.get('vm.name')])

    def undefine(self):
        return run_subprocess(
            ['sudo', 'virsh', 'undefine', self.conf.get('vm.name'),
             '--remove-all-storage'])


class KvmFromCloudImage(Kvm):

    def create_disk_image(self, src_name=None, dst_name=None):
        """Create a disk image from a cloud one."""
        if src_name is None:
            src_name = self.conf.get('vm.cloud_image_name')
        if dst_name is None:
            dst_name = self.conf.expand_options('{vm.name}.qcow2')
        cloud_image_path = os.path.join(
            self.conf.get('vm.download_cache'), src_name)
        disk_image_path = os.path.join(
            self.conf.get('vm.images_dir'), dst_name)
        run_subprocess(
            ['sudo', 'qemu-img', 'convert',
             '-O', 'qcow2', cloud_image_path, disk_image_path])
        run_subprocess(
            ['sudo', 'qemu-img', 'resize',
             disk_image_path, self.conf.get('vm.disk_size')])
        self._disk_image_path = disk_image_path


class KvmFromBacking(Kvm):

    def create_disk_image(self, src_name=None, dst_name=None):
        """Create a disk image backed by an existing one."""
        backing_image_path = os.path.join(
            self.conf.get('vm.images_dir'),
            self.conf.expand_options('{vm.backing}'))
        disk_image_path = os.path.join(
            self.conf.get('vm.images_dir'),
            self.conf.expand_options('{vm.name}.qcow2'))
        run_subprocess(
            ['sudo', 'qemu-img', 'create', '-f', 'qcow2',
             '-b', backing_image_path, disk_image_path])
        run_subprocess(
            ['sudo', 'qemu-img', 'resize',
             disk_image_path, self.conf.get('vm.disk_size')])
        self._disk_image_path = disk_image_path


class ArgParser(argparse.ArgumentParser):
    """A parser for the setup_vm script."""

    def __init__(self):
        description = 'Set up virtual machines from a configuration file.'
        super(ArgParser, self).__init__(
            prog='setup_vm.py', description=description)
        self.add_argument(
            'name', help='Virtual machine section in the configuration file.')
        self.add_argument('--download', '-d', action="store_true",
                          help='Force download of the required image.')
        self.add_argument('--ssh-keygen', '-k', action="store_true",
                          help='Generate the ssh server keys (if any).')
        self.add_argument('--install', '-i', action="store_true",
                          help='Install the virtual machine.')

    def parse_args(self, args=None, out=None, err=None):
        """Parse arguments, overridding stdout/stderr if provided.

        Overridding stdout/stderr is provided for tests.

        :params args: Defaults to sys.argv[1:].

        :param out: Defaults to sys.stdout.

        :param err: Defaults to sys.stderr.
        """
        out_orig = sys.stdout
        err_orig = sys.stderr
        try:
            if out is not None:
                sys.stdout = out
            if err is not None:
                sys.stderr = err
            return super(ArgParser, self).parse_args(args)
        finally:
            sys.stdout = out_orig
            sys.stderr = err_orig



arg_parser = ArgParser()

class Command(object):

    def __init__(self, vm):
        self.vm = vm


class Download(Command):

    def run(self):
        # FIXME: what needs to be downloaded should depend on the type of the
        # vm (possibly errors if there is nothing to download). -- vila
        # 2013-02-06
        self.vm.download_cloud_image(force=True)


class SshKeyGen(Command):

    def run(self):
        self.vm.ssh_keygen()


class Install(Command):

    def run(self):
        vm_name = self.vm.conf.get('vm.name')
        state = vm_states().get(vm_name, None)
        if state == 'shut off':
            self.vm.undefine()
        elif state == 'running':
            raise SetupVmError('{name} is running', name=vm_name)
        # FIXME: The installation method may vary depending on the vm type.
        # -- vila 2013-02-06
        self.vm.install()


def build_commands(args=None, out=None, err=None):
    cmds = []
    if args is None:
        args = sys.argv[1:]

    ns = arg_parser.parse_args(args, out=out, err=err)

    conf = VmStack(ns.name)
    with_backing = conf.get('vm.backing')
    if with_backing is None:
        vm = KvmFromCloudImage(conf)
    else:
        vm = KvmFromBacking(conf)
    if ns.download:
        cmds.append(Download(vm))
    if ns.ssh_keygen:
        cmds.append(SshKeyGen(vm))
    if ns.install:
        cmds.append(Install(vm))
    return cmds


def run(args=None):
    cmds = build_commands(args)
    for cmd in cmds:
        try:
            cmd.run()
        except SetupVmError, e:
            # Stop on first error
            print 'ERROR: %s' % e
            exit(-1)


if __name__ == "__main__":
    run()
