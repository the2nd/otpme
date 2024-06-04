#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import os
import sys
import shutil
from setuptools import setup
from setuptools import find_packages
from setuptools.command.develop import develop
from setuptools.command.install import install

#import otpme

package_directory = os.path.realpath(os.path.dirname(__file__))

def read_file(file_name):
    """ Read file content. """
    file_path = os.path.join(package_directory, file_name)
    try:
        file_content = open(file_path).read()
    except Exception as e:
        sys.stderr.write("Error reading file: %s: %s" % (file_path, e))


def get_files(file_path):
    """ Get list of files in directory. """
    files_dir = os.path.join(package_directory, file_path)
    file_names = os.listdir(files_dir)
    files = []
    for x in file_names:
        files.append(os.path.join(file_path, x))
    return files


class PostDevelopCommand(develop):
    """ Post-installation for development mode. """
    def run(self):
        develop.run(self)


class PostInstallCommand(install):
    """ Post-installation for installation mode. """
    def run(self):
        install.run(self)
        # Make sure we have a otpme.conf.
        otpme_conf = "/etc/otpme/otpme.conf"
        otpme_conf_dist = "%s.dist" % otpme_conf
        if os.path.exists(otpme_conf_dist):
            if not os.path.exists(otpme_conf):
                shutil.move(otpme_conf_dist, otpme_conf)


#install_requires = [
#                "service_identity",
#                "importlib-metadata",
#                "ipaddr>=2.1.10",
#                "psutil>=5.5.1",
#                "pytz>=2019.3",
#                "pexpect>=4.6.0",
#                "pycryptodomex>=3.7.3",
#                #"cryptography==3.3.2",
#                "cryptography",
#                #"cryptography<3.5",
#                #"pyOpenSSL>=0.13",
#                "pyOpenSSL>=0.15.1",
#                "pysodium>=0.7.10",
#                "pylibacl>=0.5.1",
#                "ecdsa>=0.10",
#                #"ecdsa>=0.13",
#                "dnspython>=1.15.0",
#                "Twisted>=13.2.0",
#                "progressbar>=2.3",
#                "passlib>=1.7.2",
#                "netifaces>=0.8",
#                "prettytable>=0.7.2",
#                "setproctitle>=1.1.10",
#                "paramiko>=1.16.0",
#                "arprequest>=0.3",
#                "scapy>=2.4.4",
#                "oath>=1.4.1",
#                "Cython>=0.20",
#                #"cchardet>=1.1.2",
#                "cchardet>=2.1.7",
#                "chardet>=3.0.4",
#                "argon2>=0.1.10",
#                "future>=0.15.2",
#                "Cython>=0.29.36",
#                "PyJWT==1.7.1",
#                "fido2==1.1.1",
#                "qrcode>=5.1",
#                "bson>=0.5.10",
#                # Improve tinydb performance.
#                "ujson>=5.7.0",
#                #"larch-pickle>=1.1.3",
#                "ldaptor>=21.2.0",
#                "humanize>=0.5.1",
#                "cachetools==5.3.1",
#                "posix-ipc>=1.0.5",
#                "tinydb>=4.5.2",
#                "psycopg2>=2.8.6",
#                "SQLAlchemy>=2.0.15",
#                "SQLAlchemy-Utils>=0.36.8",
#                "python-magic>=0.4.15",
#                "colorlog>=4.1.0",
#                #"python-daemon>=2.2.4",
#                #"python-u2flib-server>=5.0.0",
#                "redis>=3.3.11",
#                "pylibmc>=1.6.3",
#                "python-yubico>=1.3.3",
#                "daemonize>=2.4.7",
#                "dogpile.cache>=0.9.0",
#                "ldap3>=2.4.1",
#                "pycryptodome>=3.4.3",
#                #"pyoath-toolkit>=2.0.dev1",
#                "PyQRCode>=1.2.1",
#                #"pyotp>=2.8.0",
#                "pyre2>=0.3.6",
#                "lz4>=4.3.2",
#                #"re2>=0.2.22",
#                # Failes to install via pip.
#                #"systemd>=0.16.1",
#                "termcolor>=1.1.0",
#                "radius-eap-mschapv2-client>=1.0.6",
#                "pyrad>=2.4",
#                #"py-radius>=2.0.2.post1",
#
#                # apt-get install libffi-dev libssl-dev
#
#                # For use with U2F token (client site only).
#                #"hidapi>=0.7.99.post8",
#                #"python-u2flib-host>=3.0.0",
#            ]

#extras_require = {
#            'dev': [
#                    # Latest version in ubuntu 14.04.
#                    "Sphinx>=1.2.2",
#                    ],
#            'test': [
#                    # Latest version in ubuntu 14.04.
#                    "coverage>=3.7.1",
#                    ],
#            }

#scripts = [
#            'otpme/otpme.py',
#            #'bin/otpme-controld',
#         ]

#entry_points = {
#            'console_scripts': [
#                'otpme-cluster = otpme.command:otpme_commands',
#                'otpme-accessgroup = otpme.command:otpme_commands',
#                'otpme-agent = otpme.command:otpme_commands',
#                'otpme-auth = otpme.command:otpme_commands',
#                'otpme-ca = otpme.command:otpme_commands',
#                'otpme-client = otpme.command:otpme_commands',
#                'otpme-controld = otpme.command:otpme_commands',
#                'otpme-group = otpme.command:otpme_commands',
#                'otpme-host = otpme.command:otpme_commands',
#                'otpme-node = otpme.command:otpme_commands',
#                'otpme-realm = otpme.command:otpme_commands',
#                'otpme-role = otpme.command:otpme_commands',
#                'otpme-session = otpme.command:otpme_commands',
#                'otpme-site = otpme.command:otpme_commands',
#                'otpme-token = otpme.command:otpme_commands',
#                'otpme-tool = otpme.command:otpme_commands',
#                'otpme-unit = otpme.command:otpme_commands',
#                'otpme-user = otpme.command:otpme_commands',
#                'otpme-script = otpme.command:otpme_commands',
#                'otpme-policy = otpme.command:otpme_commands',
#                'otpme-dictionary = otpme.command:otpme_commands',
#                'otpme-resolver = otpme.command:otpme_commands',
#                'otpme-pinentry = otpme.command:otpme_commands',
#                'otpme-get-authorized-keys = otpme.command:otpme_commands',
#                ],
#            }

data_files = [
                ('/etc/otpme/',
                    [
                        'deploy/otpme.conf.dist',
                    ]
                ),
                ('/etc/otpme/schema',
                    get_files("deploy/schema/")
                ),
                ('/etc/otpme/dicts',
                    get_files("deploy/dicts/")
                ),
                ('/etc/otpme/scripts',
                    get_files("deploy/scripts/")
                ),
                ('/etc/otpme/radius',
                    get_files("deploy/radius/")
                ),
                ('/etc/bash_completion.d/',
                    [
                        'bash_completion/otpme',
                    ]
                ),
                ('/etc/otpme/deploy/pam/',
                    [
                        'deploy/pam/README',
                        'deploy/pam/otpme-auth',
                        'deploy/pam/otpme-account',
                        'deploy/pam/otpme-session',
                    ]
                ),
                ('/etc/otpme/deploy/pam/pam-python',
                    [
                        'deploy/pam/pam_otpme.py',
                        'deploy/pam/pam-python/README',
                    ]
                ),
                #('share/man/man1',
                #    [
                #        "man/otpme-controld.1",
                #        "man/otpme-tool.1",
                #  ]
                #),
                #('lib/otpme/freeradius',
                #    [
                #        "otpme/lib/freeradius/otpme.py",
                #    ],
                #),
            ]


#classifiers = [
#            # In future versions.
#            #"Framework :: Flask",
#            "Programming Language :: Python",
#            #otpme.__status__,
#            "License :: OSI Approved :: GNU General Public License v3 (GPLv3)",
#            "Topic :: Internet",
#            "Topic :: Security",
#            "Topic :: System :: Systems Administration :: Authentication/Directory",
#        ]


setup(
    #name=otpme.__project_name__,
    #version=otpme.__version__,
    #description=otpme.__project_description__,
    #license=otpme.__license__,
    #author=otpme.__author__,
    #author_email=otpme.__author_email__,
    #maintainer=otpme.__maintainer__,
    #maintainer_email=otpme.__maintainer_email__,
    #url=otpme.__project_url__,
    #keywords='OTP, U2F, fido2, two factor authentication, PAM, LDAP',

    packages=find_packages(),

    #scripts=scripts,
    data_files=data_files,
    #classifiers=classifiers,
    #entry_points=entry_points,
    #extras_require=extras_require,
    #install_requires=install_requires,
    include_package_data=True,
	package_data={
			'otpme': ['otpme/web/app/static/*', 'otpme/web/app/templates/*'],
		},
    zip_safe=False,
    #long_description=read_file('README.rst')

    # Run post install stuff.
    cmdclass={
        'develop': PostDevelopCommand,
        'install': PostInstallCommand,
    },
)
