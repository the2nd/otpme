# -*- coding: utf-8 -*-
# Copyright (C) 2014 the2nd <the2nd@otpme.org>
import os
import sys

try:
    if os.environ['OTPME_DEBUG_MODULE_LOADING'] == "True":
        print(_("Loading module: %s") % __name__)
except:
    pass

from otpme.lib import config
from otpme.lib.messages import message
from otpme.lib.messages import error_message

def gpg_applet(gpg_backup_file=None, gpg_restore_file=None):
    """ Setup yubikey GPG applet. """
    import signal
    import shutil
    import getpass
    from otpme.lib.gpg import utils as gpg

    from otpme.lib import cli
    from otpme.lib import stuff
    from otpme.lib import filetools
    from otpme.lib.smartcard.yubikey.yubikey import Yubikey

    def setup_yubikey(mode="82"):
        """ Setup yubikey for use with GnuPG"""
        status = True

        # Try to detect yubikey
        try:
            yk = Yubikey(autodetect=False)
        except Exception as e:
            message(_("Error loading yubikey class: %s") % e)
            return False

        #message(_("Setting yubikey mode to %s") % mode)
        #try:
        #    yk.set_mode(mode=mode)
        #except Exception as e:
        #    error_message(_("Error setting yubikey mode: %s") % e)
        #    status = False
        #cli.user_input("Please re-plug yubikey and press RETURN.")

        message("Resetting yubikey GPG applet...")
        # Try to reset yubikey GPG applet
        try:
            yk.reset_gpg()
        except Exception as e:
            error_message(_("Error resetting yubikey GPG applet: %s") % e)
            status = False

        if not status:
            return False

        cli.user_input("Please re-plug yubikey and press RETURN.")

        return True

    # Stuff we need to deploy the yubikey
    debug = False
    yubikey_mode = "82"
    yubikey_default_pin = "123456"
    yubikey_default_admin_pin = "12345678"
    pin_min_len = 8
    user_home = os.getenv("HOME")
    gpg_dir = "%s/.gnupg" % user_home
    gpg_sshcontrol_file = "%s/sshcontrol" % gpg_dir
    tmp_dir = "/dev/shm"
    gpg_tmp_home_dir = "%s/.gnupg" % tmp_dir
    system_user = config.system_user()

    pre_check_failed = False

    if stuff.get_pid(name='gpg-agent', user=system_user):
        error_message(_("Found a running gpg-agent. Please stop all gpg-agents "
                        "before continuing."))
        pre_check_failed = True

    if os.path.exists(gpg_dir):
        error_message(_("WARNING: GPG directory exists: %s") % gpg_dir)
        pre_check_failed = True

    if os.path.exists(gpg_tmp_home_dir):
        error_message(_("WARNING: Temporary GPG home directory exists: %s")
                        % gpg_tmp_home_dir)
        pre_check_failed = True

    if pre_check_failed:
        sys.exit(1)

    # Create temporary .gnupg directory and link it to users home
    filetools.create_dir(gpg_tmp_home_dir, user=config.system_user(), group=True, mode=0o700)
    os.symlink(gpg_tmp_home_dir, gpg_dir)

    def cleanup():
        """ Cleanup stuff """
        try:
            gpg.stop_agent()
        except:
            pass
        if os.path.islink(gpg_dir):
            os.unlink(gpg_dir)
        if os.path.exists(gpg_tmp_home_dir):
            shutil.rmtree(gpg_tmp_home_dir)

    def signal_handler(_signal, frame):
        """ handle signals """
        if _signal == 2:
            print("\nExiting on Ctrl+C")
        if _signal == 15:
            print("\nExiting on 'SIGTERM'.")
        cleanup()
        os._exit(0)

    # handle signals
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)

    if not config.force:
        message(_("WARNING!!!!!!! Resetting the yubikey GPG applet will "
                "destroy all GPG keys on it !!!!"))
        cli.user_input(_("Press Ctrl+C to abort or RETURN to continue: "))

    # Initialize yubikey GPG applet and set mode
    try:
        setup_yubikey(mode=yubikey_mode)
    except Exception as e:
        error_message(_("Yubikey initialization failed: %s") % e)
        cleanup()
        sys.exit(1)

    #user_real_name = "Peter Pan"
    #user_email = "peter@pan.local"
    #new_password = "12345678"
    #gpg_passphrase = new_password

    user_real_name = None
    user_email = None
    new_password = None
    gpg_passphrase = None

    if not gpg_restore_file:
        if not user_real_name:
            message("Please give you real name e.g. John Doe")
            user_real_name = cli.user_input('Real name: ')

        # Generate default backup file path
        if not gpg_backup_file:
            gpg_backup_file = "%s/%s.gpg" % (tmp_dir,
                                        user_real_name.replace(" ", "_"))

        # Check if backup file already exists
        if os.path.exists(gpg_backup_file):
            error_message(_("WARNING: GPG backup file exists: %s")
                            % gpg_backup_file)
            cleanup()
            sys.exit(1)

        if not user_email:
            user_email = cli.user_input('Mailaddress: ')

        if not new_password:
            new_password = cli.get_password(prompt='New token password: ', min_len=pin_min_len)

        if not gpg_passphrase:
            x = cli.user_input("Use token password to protect GPG backup file? (y/n) ")
            if x.lower() != "n":
                gpg_passphrase = new_password
            else:
                gpg_passphrase = cli.get_password(prompt="Backup password: ", min_len=pin_min_len)

        # Try to init GPG.
        try:
            master_key_id, \
            auth_key_id, \
            enc_key_id = gpg.init_gpg(user_real_name=user_real_name,
                                    user_email=user_email,
                                    passphrase=gpg_passphrase)
        except Exception as e:
            config.raise_exception()
            error_message(_("Error initializating GPG: %s") % e)
            cleanup()
            sys.exit(1)

        gpg.stop_agent()

        message("Starting gpg-agent...")
        try:
            ssh_agent_pid, \
            ssh_auth_sock, \
            gpg_agent_info = gpg.start_agent()
        except Exception as e:
            error_message(str(e))
            cleanup()
            sys.exit(1)

        # Try to backup new created GPG keys.
        try:
            gpg.create_backup(backup_file=gpg_backup_file,
                            passphrase=gpg_passphrase)
        except Exception as e:
            config.raise_exception()
            error_message(_("Error creating GPG backup: %s") % e)
            cleanup()
            sys.exit(1)

        gpg.stop_agent()

        # Clear gpg directory for restore.
        if os.path.exists(gpg_tmp_home_dir):
            shutil.rmtree(gpg_tmp_home_dir)
            filetools.create_dir(gpg_tmp_home_dir, user=config.system_user(), group=True, mode=0o700)

        message("Starting gpg-agent...")
        try:
            ssh_agent_pid, \
            ssh_auth_sock, \
            gpg_agent_info = gpg.start_agent()
        except Exception as e:
            error_message(str(e))
            cleanup()
            sys.exit(1)

    # Restore GPG backup.
    try:
        # If this is a restore use the restore file. If this is a
        # new token deployment use the backup file we created above.
        if gpg_restore_file:
            restore_file = gpg_restore_file
        else:
            restore_file = gpg_backup_file
        gpg.restore_backup(backup_file=restore_file,
                            passphrase=gpg_passphrase)
    except Exception as e:
        error_message(_("Error restoring GPG backup: %s") % e)
        cleanup()
        sys.exit(1)

    # When restoring from file we need to get
    # the restore file passphrase.
    if gpg_restore_file:
        # Get main key ID
        try:
            key_id = gpg.get_main_key_id()
        except Exception as e:
            error_message(_("Unable to get key ID from backup file: %s") % e)
            cleanup()
            sys.exit(1)
        # Try to get the right passphrase from user.
        while True:
            gpg_passphrase = getpass.getpass('Backup file passphrase: ')
            if gpg.verify_passphrase(key_id=key_id, passphrase=gpg_passphrase):
                break
            error_message("Wrong passphrase.")

        if not new_password:
            new_password = cli.get_password(prompt='New token password: ', min_len=pin_min_len)

    message("Setting token PIN...")
    try:
        gpg.change_sc_pin(old_pin=yubikey_default_pin,
                            new_pin=new_password,
                            admin_pin=False,
                            debug=debug)
    except Exception as e:
        error_message(_("Error changing token PIN: %s") % e)
        cleanup()
        sys.exit(1)

    message("Setting token admin PIN...")
    try:
        gpg.change_sc_pin(old_pin=yubikey_default_admin_pin,
                            new_pin=new_password,
                            admin_pin=True,
                            debug=debug)
    except Exception as e:
        error_message(_("Error changing token admin PIN: %s") % e)
        cleanup()
        sys.exit(1)

    # Try to get sub key keygrip to be shown to the user.
    try:
        sub_keygrip = gpg.get_sub_keygrip()
    except Exception as e:
        error_message(_("Unable to get keygrip: %s") % e)
        cleanup()
        sys.exit(1)

    # Try to move key to card.
    message("Writing keys to yubikey...")
    try:
        gpg.key_to_card(auth_key_id,
                        key_type="auth",
                        sc_admin_pin=new_password,
                        gpg_passphrase=gpg_passphrase,
                        debug=debug)
    except Exception as e:
        raise
        error_message(_("Failed to write GPG auth key to yubikey: %s") % e)
        cleanup()
        sys.exit(1)
    # Restart gpg agent to make key_to_card() work because it sends passwords
    # that are not required when the first key_to_card() was run.
    gpg.stop_agent()
    message("Starting gpg-agent...")
    try:
        ssh_agent_pid, \
        ssh_auth_sock, \
        gpg_agent_info = gpg.start_agent()
    except Exception as e:
        error_message(str(e))
        cleanup()
        sys.exit(1)
    try:
        gpg.key_to_card(enc_key_id,
                        key_type="encrypt",
                        sc_admin_pin=new_password,
                        gpg_passphrase=gpg_passphrase,
                        debug=debug)
    except Exception as e:
        raise
        error_message(_("Failed to write GPG encryption key to yubikey: %s") % e)
        cleanup()
        sys.exit(1)

    # Try to get ssh keygrip needed for sshcontrol
    # file (e.g. confirm key usage)
    try:
        ssh_keygrip = gpg.get_ssh_keygrip()
    except Exception as e:
        error_message(_("Unable to ssh get keygrip: %s") %e)
        cleanup()
        sys.exit(1)

    ## Remove main key from .gnupg directory
    #try:
    #    gpg.remove_main_key(key_id, debug=debug)
    #except Exception as e:
    #    error_message(_("Failed to remove main GPG key from ~/.gnupg: %s") % e)
    #    cleanup()
    #    sys.exit(1)

    # Stop gpg-agent.
    gpg.stop_agent()

    message("Starting gpg-agent...")
    try:
        ssh_agent_pid, \
        ssh_auth_sock, \
        gpg_agent_info = gpg.start_agent()
    except Exception as e:
        error_message(str(e))
        cleanup()
        sys.exit(1)

    # Try to get ssh public key of sub key on token
    ssh_public_key = gpg.get_ssh_public_key()

    # Stop gpg-agent.
    gpg.stop_agent()

    # Move clean .gnupg directory (without any private key)
    # to users home directory.
    if os.path.islink(gpg_dir):
        os.unlink(gpg_dir)
    shutil.move(gpg_tmp_home_dir, gpg_dir)

    # Writing keygrip to gpg sshcontrol file and enable confirmation
    # for ssh key usage.
    sshcontrol_file = open(gpg_sshcontrol_file, "w")
    sshcontrol_file.write("%s 0 confirm\n" % ssh_keygrip)
    sshcontrol_file.close()

    # Get sub key ID from keygrip
    sub_key_id = sub_keygrip[-8:]

    message("")
    message("Your yubikey is ready now")
    message("--------------------------")
    message("Master key ID:\t%s" % master_key_id)
    message("Sub key ID:\t%s" % sub_key_id)
    message("Sub Keygrip:\t%s" % sub_keygrip)
    message("SSH public key:\t%s" % ssh_public_key.replace("\n", ""))
    message("")
    if gpg_restore_file:
        message("Restore file:\t%s" % gpg_restore_file)
        message("")
    else:
        message("Key backup file:\t%s" % gpg_backup_file)
        message("")
        message(_("Please copy the backup file of your GPG keys to a secure "
                "(offline) medium NOW !!!!!!"))
        message(_("If you lose this file or forget the password your keys are "
                "lost !!!!"))
        if new_password == gpg_passphrase:
            message(_("Note: The backup file is secured with your token "
                    "password."))
        else:
            message(_("Note: The backup file is secured with the password you "
                    "entered before."))

    # Cleanup GPG stuff
    cleanup()

    return ssh_public_key
