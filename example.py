import logging

from elevate import elevate

from approxeng.reimage import RaspberryPiOSImage
from approxeng.reimage.config_files import home_path, SSHDConfig, Network

# Set up logging
logging.basicConfig(level=logging.DEBUG)

# Elevate to get root permissions
elevate(graphical=True)

# This will be used for the file name of the image, and the host name on the network
image_name = 'green'

# Copy the original image to 'green.img' and mount it to make modifications
with RaspberryPiOSImage(image_filename='/home/tom/shrink-image/image.img',
                        copy_image=f'{image_name}.img') as im:
    # Set host name, in this case the Pi will be accessible at green.local
    im.set_hostname(hostname=image_name)
    # Add a couple of wifi networks
    im.configure_wifi(networks=[Network(ssid='cyclonic', pass_phrase='blah blah blah'),
                                Network(ssid='cyclonic_IoT', pass_phrase='blah blah blah')],
                      country='GB')
    # Turn on SSH
    im.enable_ssh()
    # Copy public keys from 'tom' on the host machine to 'pi' in the image
    im.add_ssh_keys(user_name='pi', key_paths=[home_path(user='tom') / '.ssh/id_rsa.pub'])
    # Disable password based authentication now we have SSH keys set up
    im.configure_sshd(conf=SSHDConfig(use_pam=False,
                                      password_authentication=False,
                                      challenge_response_authentication=False))
