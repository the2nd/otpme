# Installation instructions

## Install debian dependencies
apt-get install python3.11-venv gobjc++ python3-pybind11 python3-dev build-essential cmake gcc dbus-x11 freeradius freeradius-python3 libacl1-dev libnss-cache liboath0 liboath-dev libpcsclite1 libpq-dev libre2-9 libre2-dev libsystemd-dev pkg-config postgresql postgresql-server-dev-all pwgen pyflakes3 redis redis-server redis-tools libpcsclite-dev ykcs11 fuse3

### Disable installed services
systemctl stop redis  
systemctl disable redis  
systemctl stop postgresql  
systemctl disable postgresql  
systemctl stop freeradius  
systemctl disable freeradius  

## Install otpme

### Add otpme system user
useradd -r -U -d /var/lib/otpme otpme

### Enable nsswitch nsscache module
Edit /etc/nsswitch.conf and append 'cache' to the lines passwd, shadow and group.

### Create python venv
python3 -m venv /opt/otpme  
. /opt/otpme/bin/activate

### Install otpme and dependencies
pip3 install cython  
pip3 install otpme

## Copy configuration files
cp -a /opt/otpme/lib/python3.11/site-packages/etc/otpme /etc/  
cp -a /etc/otpme/otpme.conf.dist /etc/otpme/otpme.conf

### Edit /etc/otpme/otpme.conf
POSTGRES_PG_CTL_BIN="/usr/lib/postgresql/15/bin/pg_ctl"

### Create PYTHONPATH file with path to venv (e.g. /opt/otpme/lib/python3.11/site-packages/)
/etc/otpme/PYTHONPATH

## Init your otpme realm
otpme-realm --api -ddee --color-logs -f init --ca-key-len 2048 --site-key-len 2048 --node-key-len 2048 --dicts english,en-top10000,common-passwords,us-female,us-male,us-surnames,abbreviations-it --id-ranges "uidNumber:s:100000-200000,gidNumber:s:100000-200000" yourrealm.tld yoursite localhost 127.0.0.1  

Note: Scan the generated QRCode with the "Google Autenticator App" and note the PIN of the admin token.

## Start OTPme daemons
otpme-controld start

## Login with admin token
You need to input pin+otp.  
otpme-tool login

## Add optional U2F/fido2 attestation certificates from https://developers.yubico.com/FIDO/yubico-fido-ca-certs.txt.
wget https://developers.yubico.com/FIDO/yubico-fido-ca-1.pem  
wget https://developers.yubico.com/FIDO/yubico-fido-ca-2.pem  
otpme-site add_fido2_ca_cert yoursite yubico-fido-ca-1.pem  
otpme-site add_fido2_ca_cert yoursite yubico-fido-ca-2.pem  
otpme-realm config yourrealm.tld check_fido2_attestation_cert True  

## Disable gpg-agent (systemd) to use yubikey/GPG card with the PAM module.
systemctl --global mask --now gpg-agent.service gpg-agent.socket gpg-agent-ssh.socket gpg-agent-extra.socket gpg-agent-browser.socket  
