import json
import logging
import os
import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import List, Dict
from uuid import uuid4

import src.python.approxeng.reimage.util

LOG = logging.getLogger('custom_image')


@dataclass
class MountPoint:
    """
    Represents a single mounted partition from an image, held within a :class:`ImageMount`
    """
    name: str
    fstype: str
    label: str
    uuid: str
    fsavail: str
    fsuse_percentage: str
    mount: Path


class ImageMount:
    """
    Context manager which mounts a disk image on entry, unmounting on exit. This requires elevated
    permissions to work properly otherwise it can't run the losetup and other commands.

    Within a context, this acts as an iterable containing partition labels, and these can be used
    as indices to retrieve a :class:`MountPoint` for each one, i.e. image['boot'] retrieves the
    mount point metadata for the boot volume on a typical Pi SD card image.
    """

    def __init__(self, image_filename: str, copy_image: str = None):
        """
        Create a new ImageMount

        :param image_filename:
            filename of the image to mount
        :param copy_image:
            if not None, creates a copy of the image at the specified path relative to the
            original and operates on that rather than the original image
        """
        self._image_path = Path(image_filename)
        if not self._image_path.is_file():
            raise ValueError(f'image file "{image_filename}" not found')
        if copy_image:
            copy_path = self._image_path.parent / copy_image
            LOG.debug(f'copying {self.image_path_string} to {copy_path.resolve()}')
            shutil.copy(src=self._image_path, dst=copy_path)
            LOG.debug(f'copied {self.image_path_string} to {copy_path.resolve()}')
            self._image_path = copy_path
        self.mounts: List[MountPoint] = []
        self._loop_device = None
        self._uuid = str(uuid4())
        self.by_label: Dict[str, MountPoint] = {}
        LOG.debug(f'created ImageMount for file="{self.image_path_string}"')

    @property
    def image_path_string(self) -> str:
        """
        String containing the resolved path of the image file
        """
        return str(self._image_path.resolve())

    def __getitem__(self, item):
        return self.by_label[item]

    def __iter__(self):
        return self.by_label.__iter__()

    def __enter__(self):
        # Create the loop device along with any per-partition devices
        LOG.info(f'mounting image {self.image_path_string} with uuid {self._uuid}')
        self._loop_device = str(subprocess.check_output(
            ['losetup', '--show', '-f', '-P', self.image_path_string]),
            'UTF-8').strip()

        # Find any partitions within this loop device
        p = Path(self._loop_device)
        LOG.debug(f'found loop device {str(p.resolve())}')

        # Get all the mount point names
        def find_mounts():
            for block_device in json.loads(subprocess.check_output(
                    ['lsblk', '-f', '--json']))['blockdevices']:
                if block_device['name'] == p.name:
                    for partition in block_device['children']:
                        yield MountPoint(name=partition['name'],
                                         fstype=partition['fstype'],
                                         label=partition['label'],
                                         uuid=partition['uuid'],
                                         fsavail=partition['fsavail'],
                                         fsuse_percentage=partition['fsuse%'],
                                         mount=Path(partition['mountpoint']))

        for partition_path in p.parent.glob(p.name.strip() + 'p*'):
            mount_path = f'/mnt/{self._uuid}-{partition_path.name}'
            subprocess.run(['mkdir', '-p', mount_path])
            LOG.debug(f'mkdir -p {mount_path}')
            subprocess.run(['mount', str(partition_path.resolve()), mount_path])
            LOG.debug(f'mount {str(partition_path.resolve())} {mount_path}')

        self.mounts = list(find_mounts())
        self.by_label = {mount.label: mount for mount in self.mounts}
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        for mount in self.mounts:
            # Unmount and delete any mount points
            mount_path_str = str(mount.mount.resolve())
            subprocess.run(['umount', mount_path_str])
            LOG.debug(f'umount {mount_path_str}')
            mount.mount.rmdir()
            LOG.debug(f'rmdir {mount_path_str}')
        subprocess.run(['losetup', '-d', self._loop_device])
        LOG.debug(f'losetup -d {self._loop_device}')
        self._loop_device = None
        self.mounts.clear()
        self.by_label.clear()
        LOG.info(f'unmounted image {self.image_path_string} with uuid {self._uuid}')

    def path(self, label, sub_path) -> Path:
        """
        Get the resolved path for the given label and subpath

        :param label:
            label of a partition within this disk image, i.e. 'rootfs'
        :param sub_path:
            sub path within this image, i.e. '/etc/passwd'
        :return:
            a Path object representing the mounted file path requested
        """
        if label not in self:
            raise ValueError(f'no volume with label {label} in {self.image_path_string}')
        return (self[label].mount / sub_path.strip('/')).resolve()

    def write_file(self, label: str, path: str, data: str = '', append: bool = False,
                   mode: int = util.mode('rw-r--r--'), uid=0, gid=0):
        """
        Write data to a file within a mounted partition

        :param label:
            partition label to use as the root
        :param path:
            path relative to that root
        :param data:
            string to write to the file
        :param append:
            false to write, true to append to an existing file
        :param mode:
            bitmask for file permissions, defaults to rw-r--r--
        :param uid:
            uid for file, defaults to 0 (root)
        :param gid:
            gid for file, defaults to 0 (root)
        """
        file_path = self.path(label, path)
        file_mode = 'a' if append else 'w'
        with open(file=file_path, mode=file_mode) as f:
            f.write(data)
            LOG.debug(f'written data to {file_path}')
        os.chmod(path=file_path, mode=mode)
        LOG.debug(f'set mode for {file_path} to {oct(mode)}')
        os.chown(path=file_path, uid=uid, gid=gid)
        LOG.debug(f'set ownership for {file_path} to (uid={uid}, gid={gid})')


class RaspberryPiOSImage(ImageMount):
    """
    Specialisation of ImageMount that expects a typical Raspberry Pi OS disk image with 'boot' and 'rootfs'
    partitions. Methods allow you to set up wifi, enable and configure SSH, set the host name, and copy
    any public SSH keys into a user within the image. This means you can take a standard image and customise
    it to the point where it will let you SSH in with public key auth from first boot.
    """

    def __init__(self, image_filename: str, copy_image: str = None):
        """
        Create within an active ImageMount context
        """
        super().__init__(image_filename, copy_image)
        self.users = None

    def __enter__(self):
        """
        Override the enter functionality to read the mappings from user name to user ID
        """
        super().__enter__()
        self.users = config_files.parse_etc_passwd(file_path=self.path(label='rootfs', sub_path='/etc/passwd'))
        return self

    def set_hostname(self, hostname: str):
        """
        Set the hostname, this writes to /etc/hosts and /etc/hostname and sets up everything needed
        for this Pi to be accessible at HOSTNAME.local
        """
        self.write_file(label='rootfs',
                        path='etc/hosts',
                        data=config_files.hosts_file(host_name=hostname))
        self.write_file(label='rootfs',
                        path='etc/hostname',
                        data=hostname)

    def enable_ssh(self):
        """
        Write an empty file called 'ssh' to the boot partition of the image, this will then enable
        SSH login
        """
        self.write_file(label='boot',
                        path='ssh')

    def configure_sshd(self, conf: config_files.SSHDConfig):
        """
        Configure SSHD, writes to /etc/ssh/sshd_config

        :param conf:
            a SSHDConfig object
        """
        self.write_file(label='rootfs',
                        path='/etc/ssh/sshd_config',
                        data=config_files.sshd_config(conf=conf),
                        mode=util.mode('rw-r--r--'))
        LOG.debug('written sshd configuration')

    def configure_wifi(self, networks: List[config_files.Network], country='GB'):
        """
        Configure wifi, writes to /etc/wpa_supplicant/wpa_supplicant.conf. Permissions will be set to
        root read / write only, no read access for other users.

        :param networks:
            a list of Network objects. Passphrases will be used to generate the HMAC
            PSK rather than included in the image in plaintext
        :param country:
            country code, defaulting to GB, for wireless regulations
        """
        self.write_file(label='rootfs',
                        path='etc/wpa_supplicant/wpa_supplicant.conf',
                        data=config_files.wpa_supplicant_file(networks=networks,
                                                              country=country),
                        mode=util.mode('rw-------'))

    def add_ssh_keys(self, user_name: str, key_paths: List[Path]):
        """
        Add records to the authorized_keys file to allow key exchange login

        :param user_name:
            user name in the image, this is the user for which you want to enable key based login
        :param key_paths:
            a list of Path objects to files containing keys, typically this is your id_rsa.pub or similar but
            it could be a custom set of public keys. Use e.g. /home/tom/.ssh/id_rsa.pub to allow the user 'tom'
            to log in to this image
        """
        user = self.users[user_name]
        ssh_path = self.path(label='rootfs', sub_path=user.home) / '.ssh'

        # Ensure that the .ssh directory exists, has the right mode, and belongs to the
        # appropriate user
        if not ssh_path.exists():
            os.mkdir(path=ssh_path, mode=util.mode('rwx------'))
            LOG.debug(f'created .ssh directory at {ssh_path}')
        else:
            os.chmod(path=ssh_path, mode=util.mode('rwx------'))
            LOG.debug(f'.ssh directory already exists at {ssh_path}')
        os.chown(path=ssh_path, uid=user.uid, gid=user.gid)

        # Read existing authorized keys file if present
        authorized_keys_path = ssh_path / 'authorized_keys'
        if authorized_keys_path.exists():
            with open(authorized_keys_path, 'r') as f:
                existing_keys = set([config_files.AuthorizedKey.from_string(line) for line in f.readlines()])
            LOG.debug(f'authorized_keys file exists, contains {len(existing_keys)} keys')
        else:
            existing_keys = set()
            LOG.debug('no authorized_keys file found')

        # Iterate over key paths, adding all keys to the existing keys set
        for key_path in key_paths:
            if key_path.exists():
                with open(key_path, 'r') as f:
                    keys = [config_files.AuthorizedKey.from_string(line) for line in f.readlines()]
                    existing_keys = existing_keys.union(keys)
                LOG.debug(f'adding keys from {key_path}, now have {len(existing_keys)} keys')
            else:
                raise ValueError(f'unable to locate key file {key_path}')

        # Write the existing keys back
        self.write_file(label='rootfs',
                        path=f'{user.home}/.ssh/authorized_keys',
                        data='\n'.join([str(key) for key in existing_keys]),
                        uid=user.uid,
                        gid=user.gid,
                        mode=util.mode('rw-------'))
        LOG.debug(f'wrote authorized key file {user.home}/.ssh/authorized_keys containing {len(existing_keys)} keys')
