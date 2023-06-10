#!/bin/bash

useradd -r -U -d /var/lib/otpme otpme

apt-get install python3-scapy python3-systemd python3-fido2 python3-dev python3-pip libpq-dev libacl1-dev libre2-9 libre2-dev pkg-config git python3-jwt liboath0 liboath-dev redis redis-tools postgresql libnss-cache python3-pyotp pwgen python3-pylibmc libsystemd-dev freeradius

systemctl stop redis
systemctl disable redis
systemctl stop postgresql
systemctl disable postgresql
systemctl stop freeradius
systemctl disable freeradius

#pip3 install --index-url https://test.pypi.org/simple/ otpme
pip3 install otpme
#pip3 install .
#python3 setup.py build
#python3 setup.py install

mkdir /etc/otpme
cp -i /usr/local/lib/python3.9/dist-packages/etc/otpme/otpme.conf.dist /etc/otpme/otpme.conf
cp -a /usr/local/lib/python3.9/dist-packages/etc/otpme/schema /etc/otpme/
cp -a /usr/local/lib/python3.9/dist-packages/etc/bash_completion.d/otpme /etc/bash_completion.d/
