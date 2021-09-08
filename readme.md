# approxeng.reimage

Get with `pip install approxeng.reimage` (Python 3.7 or higher only). As this wraps command line tools to
actually mount and open the image files, it will only work on a Linux host.

Rewrite disk images programmatically:

* Optionally copy the disk image to keep your original files untouched
* Quick methods to
  * Enable SSH
  * Set up host name (`/etc/hosts` and `/etc/hostname`)
  * Configure `wpa_supplicant.conf` to add wifi networks
  * Copy SSH private keys from host machine into user `authorized_keys` to enable key based SSH logins
  * Configure `sshd`
* Utilities to quickly write to files in the SD card image, setting owner and permissions

Great if you need to manage a set of single board computers such as the Raspberry Pi, but don't want
to use the same image on each one (bad because things like hostname should really be unique), or 
manually edit files remotely (tedious). With this library you can quickly script production of whatever
disk images you need. For example...

```Python
from approxeng.reimage import RaspberryPiOSImage
from approxeng.reimage.config_files import home_path, SSHDConfig, Network

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

```
