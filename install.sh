#!/bin/bash
set -e
DISTRIBUTION="$(lsb_release -i | cut -d ':' -f 2 | awk '{ print $1 }')"
RELEASE="$(lsb_release -r  | cut -d ':' -f 2 | awk '{ print $1 }')"

if [ "$DISTRIBUTION" == "Ubuntu" ] ; then
	echo "* Installing libsodium..."
	apt-get install libsodium23
	echo "* Installing python stuff..."
	apt-get -y update
	apt-get -y upgrade python3 python3-dev python3-pip
fi

if [ "$DISTRIBUTION" == "Ubuntu" ] ; then
	if [ "$RELEASE" == "20.04" ] ; then
		echo "* Installing libre2..."
		apt-get install -y libre2-5 libre2-dev pkg-config
	fi
fi

if [ "$DISTRIBUTION" == "Gentoo" ] ; then
	echo "* Installing libre2..."
	emerge dev-libs/re2
fi

if [ "$DISTRIBUTION" == "Debian" ] ; then
	echo "* Installing OTPme dependencies..."
	apt-get install -y git\
		git \
		pwgen \
		redis \
		python3-redis \
		libnss-cache \
		liboath-dev \
		postgresql \
		postgresql-server-dev-all \
		cython3 \
		python3-dogpile.cache \
		pyflakes3 \
		python3-ipaddr \
		python3-psutil \
		python3-tz \
		python3-paramiko \
		python3-pexpect \
		python3-prettytable \
		python3-openssl \
		python3-pylibacl \
		python3-ecdsa \
		python3-dnspython \
		python3-twisted \
		python3-progressbar \
		python3-netifaces \
		python3-passlib \
		python3-humanize \
		python3-cachetools \
		python3-future \
		python3-setproctitle \
		python3-jwt \
		python3-colorlog \
		python3-sqlalchemy \
		python3-daemon \
		python3-daemonize \
		python3-scapy \
		python3-pam \
		python3-termcolor \
		python3-fido2 \
		python3-pyscard \
		libpcsclite1 \
		yubikey-personalization \
		python3-ldap3
		#python3-sqlalchemy-utils

	if [ "$RELEASE" == "20.04" ] ; then
		#apt-get install -y python3-pycryptodome
		pip3 install pycryptodome
	fi
fi

if [ "$DISTRIBUTION" == "Gentoo" ] ; then
	echo "* Installing OTPme dependencies..."
	emerge dev-vcs/git \
		dev-python/future \
		dev-python/setproctitle \
		dev-python/ipaddr \
		dev-python/psutil \
		dev-python/pytz \
		dev-python/paramiko \
		dev-python/python-ldap \
		dev-python/pexpect \
		dev-python/prettytable \
		dev-python/pyopenssl \
		dev-python/pylibacl \
		dev-python/m2crypto \
		dev-python/ecdsa \
		dev-python/pyjwt \
		dev-python/twisted-core \
		app-admin/pwgen \
		sys-auth/libnss-cache \
		sys-auth/oath-toolkit \
		dev-python/progressbar \
		dev-python/passlib \
		dev-python/humanize \
		dev-python/qrcode \
		dev-python/cachetools \
		dev-python/python-magic \
		dev-python/netifaces

		echo "Installing pam-python..."
		cd /tmp
		wget http://netix.dl.sourceforge.net/project/pam-python/pam-python-1.0.5-1/pam-python-1.0.5.tar.gz
		tar xvfzp pam-python-1.0.5.tar.gz
		cd pam-python-1.0.5/src
		make -j 2
		make install
fi

echo "* Installing OTPme dependencies via pip3(1)..."
if [ "$DISTRIBUTION" == "Debian" ] ; then
	pip3 install ldaptor
	pip3 install arprequest
	pip3 install oath
	pip3 install cchardet
	pip3 install argon2
	pip3 install future
	#pip3 install xxhash
	pip3 install PyQRCode
	pip3 install posix-ipc
	pip3 install pysodium
	pip3 install bson
	pip3 install tinydb
	#pip3 install larch-pickle
	pip3 install python-magic
	pip3 install psycopg2
fi
if [ "$DISTRIBUTION" == "Gentoo" ] ; then
	pip3 install ldaptor
	pip3 install arprequest
	pip3 install oath
	pip3 install cchardet
	pip3 install argon2
	#pip3 install xxhash
	pip3 install pysodium
	pip3 install dnspython
fi

echo "* Installing pyre2..."
#pip3 install re2
#pip3 install re2 git+https://github.com/andreasvc/pyre2
#cd /tmp
#git clone https://github.com/andreasvc/pyre2
#cd pyre2
#python setup.py build
#python setup.py install
#cd /tmp
#rm -r /tmp/pyre2

echo "* Installing yubico python modules..."
if [ "$DISTRIBUTION" == "Ubuntu" ] ; then
	apt-get install -y python3-yubico yubikey-personalization
fi
if [ "$DISTRIBUTION" == "Gentoo" ] ; then
	pip3 install python-yubico
fi

echo "* Installing PyJWT..."
pip3 install PyJWT

echo "* Installing libusb, hidapi..."
if [ "$DISTRIBUTION" == "Ubuntu" ] ; then
	apt-get install -y libhidapi-dev libusb-dev libusb-1.0-0-dev libudev-dev
fi
if [ "$DISTRIBUTION" == "Gentoo" ] ; then
	emerge dev-libs/hidapi \
		dev-libs/libusb
fi
pip3 install hidapi
#pip3 install python3-u2flib-host

#echo "* Installing pyoath-toolkit..."
#pip3 install git+https://github.com/malept/pyoath-toolkit.git#egg=pyoath-toolkit

if ! id otpme > /dev/null 2>&1 ; then
	echo "* Adding OTPme user..."
	useradd -r -U -d /var/lib/otpme otpme
fi

# To use the OTPme PAM module e.g. with sddm (kubuntu display manager)
# you have to add the "sddm" user to the "otpme" group.
if [ "$DISTRIBUTION" == "Ubuntu" ] ; then
	if getent group sddm > /dev/null 2>&1 ; then
		echo "* Adding sddm user to otpme group..."
		gpasswd -a sddm otpme
	fi
fi

echo "* Installing OTPme..."
ln -sf /usr/local/otpme/otpme/command.py /usr/bin/otpme-accessgroup
ln -sf /usr/local/otpme/otpme/command.py /usr/bin/otpme-agent
ln -sf /usr/local/otpme/otpme/command.py /usr/bin/otpme-auth
ln -sf /usr/local/otpme/otpme/command.py /usr/bin/otpme-ca
ln -sf /usr/local/otpme/otpme/command.py /usr/bin/otpme-client
ln -sf /usr/local/otpme/otpme/command.py /usr/bin/otpme-controld
ln -sf /usr/local/otpme/otpme/command.py /usr/bin/otpme-group
ln -sf /usr/local/otpme/otpme/command.py /usr/bin/otpme-accessgroup
ln -sf /usr/local/otpme/otpme/command.py /usr/bin/otpme-host
ln -sf /usr/local/otpme/otpme/command.py /usr/bin/otpme-node
ln -sf /usr/local/otpme/otpme/command.py /usr/bin/otpme-realm
ln -sf /usr/local/otpme/otpme/command.py /usr/bin/otpme-role
ln -sf /usr/local/otpme/otpme/command.py /usr/bin/otpme-session
ln -sf /usr/local/otpme/otpme/command.py /usr/bin/otpme-site
ln -sf /usr/local/otpme/otpme/command.py /usr/bin/otpme-token
ln -sf /usr/local/otpme/otpme/command.py /usr/bin/otpme-tool
ln -sf /usr/local/otpme/otpme/command.py /usr/bin/otpme-unit
ln -sf /usr/local/otpme/otpme/command.py /usr/bin/otpme-user
ln -sf /usr/local/otpme/otpme/command.py /usr/bin/otpme-script
ln -sf /usr/local/otpme/otpme/command.py /usr/bin/otpme-policy
ln -sf /usr/local/otpme/otpme/command.py /usr/bin/otpme-dictionary
ln -sf /usr/local/otpme/otpme/command.py /usr/bin/otpme-resolver
ln -sf /usr/local/otpme/otpme/command.py /usr/bin/otpme-cluster
ln -sf /usr/local/otpme/otpme/command.py /usr/bin/otpme-pinentry
ln -sf /usr/local/otpme/otpme/command.py /usr/bin/otpme-get-authorized-keys

mkdir -p /etc/otpme
cp -a deploy/otpme.conf.dist /etc/otpme/otpme.conf
cp -a deploy/schema /etc/otpme/

# It's recommended to enable bash command completion
ln -sf /usr/local/otpme/bash_completion/otpme /etc/bash_completion.d/
