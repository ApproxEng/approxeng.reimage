from typing import Dict


def unit_file(description: str, exec_start: str, restart: str = 'on-failure',
              service_user: str = 'root', service_type: str = 'notify', wanted_by: str = 'default.target'):
    """
    Create a new systemd unit file. These can be either system level or user level. For more details there
    is a good and comprehensive overview at
    https://www.digitalocean.com/community/tutorials/how-to-use-systemctl-to-manage-systemd-services-and-units,
    or the underlying specification at https://www.freedesktop.org/software/systemd/man/systemd.unit.html

    :param description:
        Description of the unit, free text
    :param exec_start:
        Command to run when the service is started
    :param restart:
        Restart policy, defaults to 'on-failure'
    :param service_user:
        User to run the service as, defaults to 'root'
    :param service_type:
        Service type, defaults to 'notify'
    :param wanted_by:
        Determines when the service runs when installed, defaults to 'default.target'
    """
    unit = {'Unit': {'Description': description},
            'Service': {'ExecStart': exec_start,
                        'Environment': 'PYTHONUNBUFFERED=1',
                        'Restart': restart,
                        'Type': service_type,
                        'User': service_user},
            'Install': {'WantedBy': wanted_by}}

    def section(section_name: str, parameters: Dict[str, str]) -> str:
        return f'[{section_name}]\n' + '\n'.join([f'{key}={value}' for key, value in parameters.items()])

    return '\n\n'.join([section(section_name=key, parameters=value) for key, value in unit.items() if value])
