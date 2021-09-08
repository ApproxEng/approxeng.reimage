import re
import stat


def mode(mode_string: str) -> int:
    """
    Parse a mode string of the form similar to a linux ls output, i.e.
    'wr--r--r-' or 'wrx------'

    :param mode_string:
        Mode string used to set file permissions
    :return:
        int value to pass into the mode option of os.chmod(...)
    """
    if not re.match(r'^[r-][w-][x-][r-][w-][x-][r-][w-][x-]$', mode_string):
        raise ValueError(f'mode string must contain user, group, and world wrx / --- flags, was "{mode_string}"')
    masks = [(0, 'r', stat.S_IRUSR),
             (1, 'w', stat.S_IWUSR),
             (2, 'x', stat.S_IXUSR),
             (3, 'r', stat.S_IRGRP),
             (4, 'w', stat.S_IWGRP),
             (5, 'x', stat.S_IXGRP),
             (6, 'r', stat.S_IROTH),
             (7, 'w', stat.S_IWOTH),
             (8, 'x', stat.S_IXOTH)]
    mask = 0
    for index, flag, bit in masks:
        if mode_string[index] == flag:
            mask |= bit
    return mask
