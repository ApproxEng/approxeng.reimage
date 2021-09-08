"""
Contains methods to generate or parse the content of various OS configuration files. This isn't an exhaustive set,
but contains the code needed to cleanly manipulate those config files I need to change when setting up per-pi
disk images for my own networks
"""
import hashlib
from dataclasses import dataclass, field
from pathlib import Path
from typing import List, Dict, Optional


def hosts_file(host_name):
    """
    Build a string containing the /etc/hosts file

    :param host_name:
        hostname for the image
    """
    return (f'127.0.0.1       localhost\n'
            f'::1             localhost ip6-localhost ip6-loopback\n'
            f'ff02::1         ip6-allnodes\n'
            f'ff02::2         ip6-allrouters\n'
            f'\n'
            f'127.0.1.1       {host_name}')


@dataclass
class Network:
    """
    A single wifi network, room to add extra parameters here if needed in the future
    """
    ssid: str
    pass_phrase: str


def wpa_supplicant_file(networks: List[Network], country: str = 'GB'):
    """
    Build a string containing the contents of the /etc/wpa_supplicant/wpa_supplicant.conf file, this
    uses a generate HMAC PSK rather than the plain text of your pass phrase in the config, which is
    somewhat better practice

    :param networks:
        A list of Network objects
    :param country:
        Network region, defaults to 'GB'
    """

    def network_section(network: Network):
        """
        Calculate the PSK given an SSID and pass phrase
        """
        psk_bytes = hashlib.pbkdf2_hmac('sha1', network.pass_phrase.encode('UTF-8'),
                                        network.ssid.encode('UTF-8'), 4096, 32)
        psk = ''.join(['{:02x}'.format(x) for x in psk_bytes])
        assert len(psk) == 64
        return ('network={\n'
                f'        ssid="{network.ssid}"\n'
                f'        psk={psk}\n'
                '}')

    network_sections = '\n'.join(network_section(network) for network in networks)

    return (f'ctrl_interface=DIR=/var/run/wpa_supplicant GROUP=netdev\n'
            f'update_config=1\n'
            f'country={country}\n'
            f'{network_sections}')


@dataclass
class SSHDConfig:
    """
    sshd configuration, default values correspond to those used in the raspberry pi OS
    version. Probably don't want to change most of these, but it can be used e.g. to
    disable password based login in favour of key exchange.
    """
    port: int = 22
    address_family: str = 'any'
    listen_address: List[str] = field(default_factory=lambda: ['0.0.0.0', '::'])
    host_key: List[str] = field(default_factory=lambda: ['/etc/ssh/ssh_host_rsa_key',
                                                         '/etc/ssh/ssh_host_ecdsa_key',
                                                         '/etc/ssh/ssh_host_ed25519_key'])
    rekey_limit: str = 'default none'
    syslog_facility: str = 'AUTH'
    log_level: str = 'INFO'
    login_grace_time: str = '2m'
    permit_root_login: str = 'prohibit-password'
    strict_modes: bool = True
    max_auth_tries: int = 6
    max_sessions: int = 10
    pubkey_authentication: bool = True
    authorized_keys_file: str = '.ssh/authorized_keys .ssh/authorized_keys2'
    authorized_principals_file: str = 'none'
    authorized_keys_command: str = 'none'
    authorized_keys_command_user: str = 'nobody'
    host_based_authentication: bool = False
    ignore_user_known_hosts: bool = False
    ignore_rhosts: bool = True
    password_authentication: bool = True
    permit_empty_passwords: bool = False
    challenge_response_authentication: bool = False
    kerberos_authentication: bool = False
    kerberos_or_local_passwd: bool = True
    kerberos_ticket_cleanup: bool = True
    kerberos_get_afs_token: bool = False
    gssapi_authentication: bool = False
    gssapi_cleanup_credentials: bool = True
    gssapi_strict_acceptor_check: bool = True
    gssapi_key_exchange: bool = False
    use_pam: bool = True
    allow_agent_forwarding: bool = True
    allow_tcp_forwarding: bool = True
    gateway_ports: bool = False
    x11_forward: bool = True
    x11_display_offset: int = 10
    x11_use_localhost: bool = True
    permit_tty: bool = True
    print_motd: bool = False
    print_last_log: bool = True
    tcp_keep_alive: bool = True
    permit_user_environment: bool = False
    compression: str = 'delayed'
    client_alive_interval: int = 0
    client_alive_count_max: int = 3
    use_dns: bool = False
    pid_file: str = '/var/run/sshd.pid'
    max_startups: str = '10:30:100'
    permit_tunnel: bool = False
    chroot_directory: str = 'none'
    version_addendum: str = 'none'
    banner: str = 'none'
    accept_env: str = 'LANG LC_*'
    subsystem: str = 'sftp /usr/lib/openssh/sftp-server'


def sshd_config(conf: SSHDConfig) -> str:
    """
    File ready to write to /etc/ssh/sshd_config

    :param conf:
        a SSHConfig, these have sensible defaults
    :return:
        string ready to write to the config file
    """
    listen_addresses = '\n'.join([f'ListenAddress {address}' for address in conf.listen_address])
    host_keys = '\n'.join([f'HostKey {key}' for key in conf.host_key])

    def yn(value: bool):
        return 'yes' if value else 'no'

    return (f'Port {conf.port}\n'
            f'AddressFamily {conf.address_family}\n'
            f'{listen_addresses}\n'
            f'{host_keys}\n'
            f'RekeyLimit {conf.rekey_limit}\n'
            f'SyslogFacility {conf.syslog_facility}\n'
            f'LogLevel {conf.log_level}\n'
            f'LoginGraceTime {conf.login_grace_time}\n'
            f'PermitRootLogin {conf.permit_root_login}\n'
            f'StrictModes {yn(conf.strict_modes)}\n'
            f'MaxAuthTries {conf.max_auth_tries}\n'
            f'MaxSessions {conf.max_sessions}\n'
            f'PubkeyAuthentication {yn(conf.pubkey_authentication)}\n'
            f'AuthorizedKeysFile {conf.authorized_keys_file}\n'
            f'AuthorizedPrincipalsFile {conf.authorized_principals_file}\n'
            f'AuthorizedKeysCommand {conf.authorized_keys_command}\n'
            f'AuthorizedKeysCommandUser {conf.authorized_keys_command_user}\n'
            f'HostbasedAuthentication {yn(conf.host_based_authentication)}\n'
            f'IgnoreUserKnownHosts {yn(conf.ignore_user_known_hosts)}\n'
            f'IgnoreRhosts {yn(conf.ignore_rhosts)}\n'
            f'PasswordAuthentication {yn(conf.password_authentication)}\n'
            f'PermitEmptyPasswords {yn(conf.permit_empty_passwords)}\n'
            f'ChallengeResponseAuthentication {yn(conf.challenge_response_authentication)}\n'
            f'KerberosAuthentication {yn(conf.kerberos_authentication)}\n'
            f'KerberosOrLocalPasswd {yn(conf.kerberos_or_local_passwd)}\n'
            f'KerberosTicketCleanup {yn(conf.kerberos_ticket_cleanup)}\n'
            f'KerberosGetAFSToken {yn(conf.kerberos_get_afs_token)}\n'
            f'GSSAPIAuthentication {yn(conf.gssapi_authentication)}\n'
            f'GSSAPICleanupCredentials {yn(conf.gssapi_cleanup_credentials)}\n'
            f'GSSAPIStrictAcceptorCheck {yn(conf.gssapi_strict_acceptor_check)}\n'
            f'GSSAPIKeyExchange {yn(conf.gssapi_key_exchange)}\n'
            f'UsePAM {yn(conf.use_pam)}\n'
            f'AllowAgentForwarding {yn(conf.allow_agent_forwarding)}\n'
            f'AllowTcpForwarding {yn(conf.allow_tcp_forwarding)}\n'
            f'GatewayPorts {yn(conf.gateway_ports)}\n'
            f'X11Forwarding {yn(conf.x11_forward)}\n'
            f'X11DisplayOffset {conf.x11_display_offset}\n'
            f'X11UseLocalhost {yn(conf.x11_use_localhost)}\n'
            f'PermitTTY {yn(conf.permit_tty)}\n'
            f'PrintMotd {yn(conf.print_motd)}\n'
            f'PrintLastLog {yn(conf.print_last_log)}\n'
            f'TCPKeepAlive {yn(conf.tcp_keep_alive)}\n'
            f'PermitUserEnvironment {yn(conf.permit_user_environment)}\n'
            f'Compression {conf.compression}\n'
            f'ClientAliveInterval {conf.client_alive_interval}\n'
            f'ClientAliveCountMax {conf.client_alive_count_max}\n'
            f'UseDNS {yn(conf.use_dns)}\n'
            f'PidFile {conf.pid_file}\n'
            f'MaxStartups {conf.max_startups}\n'
            f'PermitTunnel {yn(conf.permit_tunnel)}\n'
            f'ChrootDirectory {conf.chroot_directory}\n'
            f'VersionAddendum {conf.version_addendum}\n'
            f'Banner {conf.banner}\n'
            f'AcceptEnv {conf.accept_env}\n'
            f'Subsystem {conf.subsystem}\n')


@dataclass(frozen=True)
class PosixUser:
    """
    A single record in a /etc/passwd file corresponding to a single user
    """
    name: str
    uid: int
    gid: int
    info: List[str]
    home: str
    shell: str

    @staticmethod
    def from_string(line):
        """
        Parse a row from the /etc/passwd file
        """
        parts = line.split(':')
        return PosixUser(name=parts[0],
                         uid=int(parts[2]),
                         gid=int(parts[3]),
                         info=parts[4].split(','),
                         home=parts[5],
                         shell=parts[6])


def parse_etc_passwd(file_path) -> Dict[str, PosixUser]:
    """
    Read a standard format passwd file and derive a dict of user name to PosixUser from it,
    returning it.

    :param file_path:
        Path to the passwd file
    :return:
        dict of user name to PosixUser data class
    """
    with open(file_path, 'r') as f:
        return {user.name: user
                for user in
                [PosixUser.from_string(line) for line in f.readlines()]}


def home_path(user: str) -> Path:
    """
    Convenience method to get the home directory in the parent machine (not the mounted image!) for the
    given user. This is used when finding paths to e.g. SSH keys to copy into the image's authorized_keys
    files.

    :param user:
        user name within the current parent machine
    :return:
        Path object representing the user's home directory
    """
    user = parse_etc_passwd(file_path=Path('/etc/passwd'))[user]
    return Path(user.home)


@dataclass(frozen=True)
class AuthorizedKey:
    """
    A single line from a .ssh/authorized_keys or .ssh/authorized_keys2 file, also the format used in .ssh/id_rsa.pub
    and similar. Can be used to enable SSH login by key exchange rather than passwords
    """
    options: Optional[str]
    key_type: str
    key: str
    comment: str

    def __post_init__(self):
        """
        Check that the key type is valid
        """
        if self.key_type not in ['ecdsa-sha2-nistp256', 'ecdsa-sha2-nistp384',
                                 'ecdsa-sha2-nistp521', 'ssh-ed25519',
                                 'ssh-dss', 'ssh-rsa']:
            raise ValueError(f'invalid key type {self.key_type}')

    @staticmethod
    def from_string(line):
        parts = line.split(' ')
        if len(parts) == 3:
            # Options part is, as you might expect, optional...
            return AuthorizedKey(options=None,
                                 key_type=parts[0],
                                 key=parts[1],
                                 comment=parts[2])
        elif len(parts) == 4:
            # Options part specified
            return AuthorizedKey(options=parts[0],
                                 key_type=parts[1],
                                 key=parts[2],
                                 comment=parts[3])
        else:
            raise ValueError(f'unable to parse line as key, line was "{line}"')

    def __repr__(self):
        if self.options:
            return ' '.join([self.options, self.key_type, self.key, self.comment])
        else:
            return ' '.join([self.key_type, self.key, self.comment])
