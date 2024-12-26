#!/usr/bin/env python
# -*- coding: utf-8 -*-
# Copyright (C) 2014 the2nd <the2nd@otpme.org>
import os
import sys
import pwd
import stat
import time
import json
try:
    from PyQt4 import QtGui
except:
    class QtGui(object):
        __self__ = None
        class QDialog:
            __self__ = None
        class QSpinBox:
            __self__ = None
try:
    from PyQt4 import QtCore
except:
    class QtCore(object):
        pass

try:
    if os.environ['OTPME_DEBUG_MODULE_LOADING'] == "True":
        print(_("Loading module: %s") % __name__)
except:
    pass

try:
    q_string = QtCore.QString
except:
    q_string = str

try:
    _fromUtf8 = q_string.fromUtf8
except AttributeError:
    def _fromUtf8(s):
        return s

try:
    _encoding = QtGui.QApplication.UnicodeUTF8
    def _translate(context, text, disambig):
        return QtGui.QApplication.translate(context, text, disambig, _encoding)
except AttributeError:
    def _translate(context, text, disambig):
        return QtGui.QApplication.translate(context, text, disambig)

try:
    # Add OTPme dir to path.
    module_path = os.path.realpath(__file__)
    otpme_dir = os.path.dirname(module_path)
    otpme_dir = os.path.dirname(otpme_dir)
    otpme_dir = os.path.dirname(otpme_dir)
    otpme_dir = os.path.dirname(otpme_dir)
    sys.path.append(otpme_dir)
    from otpme.lib import config
    from otpme.lib import system_command
    # Set OTPme icon dir.
    icon_dir = os.path.join(otpme_dir, "otpme/icons")
    # Set own icons.
    icon_ok = _fromUtf8(os.path.join(icon_dir, "dialog-ok-apply.png"))
    icon_cancel = _fromUtf8(os.path.join(icon_dir, "dialog-cancel.png"))
    icon_window = _fromUtf8(os.path.join(icon_dir, "lock.png"))
    # Pinentry name.
    PINENTRY_NAME = "pinentry-otpme"
    basename = config.tool_name
except:
    PINENTRY_NAME = "pinentry-ng"
    basename = os.path.basename(sys.argv[0])
    icon_ok = QtGui.QStyle.SP_DialogApplyButton
    icon_cancel = QtGui.QStyle.SP_DialogCancelButton
    icon_window = QtGui.QStyle.SP_MessageBoxQuestion

try:
    from PyKDE4.kdeui import KIcon
    icon_ok = KIcon("dialog-ok-apply")
    icon_cancel = KIcon("dialog-cancel")
    icon_window = KIcon("object-locked")
    #icon_window = KIcon("emblem-locked")
except:
    class FakeClass(object):
        pass
    KIcon = FakeClass

def get_icon(style, icon):
    if isinstance(icon, q_string):
        x = QtGui.QIcon()
        x.addPixmap(QtGui.QPixmap(icon), QtGui.QIcon.Normal, QtGui.QIcon.Off)
    elif isinstance(icon, KIcon):
        x = icon
    elif isinstance(icon, object):
        x = style.standardIcon(icon)
    return x


def read_autoconfirm_file(autoconfirm_file):
    """ Read autoconfirm file. """
    expiry_data = {}
    if not os.path.exists(autoconfirm_file):
        return expiry_data
    # Make sure we only read files with sane permissions.
    owner_uid = os.stat(autoconfirm_file).st_uid
    user_uid = os.getuid()
    file_perm = oct(os.stat(autoconfirm_file)[stat.ST_MODE])
    file_perm = int(file_perm[-3:])
    # Check owner of file.
    if owner_uid != user_uid:
        file_owner = pwd.getpwuid(owner_uid).pw_name
        msg = ("Wrong owner of autoconfirm file: %s: %s\n"
                % (autoconfirm_file, file_owner))
        return expiry_data
    # Check file permissions.
    if file_perm != 600:
        msg = ("Wrong permissions of autoconfirm file: %s: %s\n"
                % (autoconfirm_file, file_perm))
        return expiry_data
    # Try to read autoconfirm file.
    try:
        fd = open(autoconfirm_file, "r")
        file_content = fd.read()
        fd.close()
    except Exception as e:
        msg = "Failed to read autoconfirm file: %s\n" % e
        sys.stderr.write(msg)
        sys.stderr.flush()
        return expiry_data
    try:
        expiry_data = json.loads(file_content)
    except Exception as e:
        msg = "Failed to load JSON data: %s\n" % e
        sys.stderr.write(msg)
        sys.stderr.flush()
    return expiry_data


def write_autoconfirm_file(autoconfirm_file, expiry_data):
    # Write JSON data to file.
    file_content = json.dumps(expiry_data)
    try:
        fd = open(autoconfirm_file, "w")
        fd.write(file_content)
        fd.close()
        os.chmod(autoconfirm_file, 0o600)
    except Exception as e:
        msg = "Failed to write autoconfirm expiry: %s\n" % e
        sys.stderr.write(msg)
        sys.stderr.flush()


def set_autoconfirm(autoconfirm_file, confirm_key, expiry,
    fallback=True, message_file=None):
    """ Write autoconfirm timestamp to file. """
    # Load autoconfirm file.
    expiry_data = read_autoconfirm_file(autoconfirm_file)
    # Set expiry in seconds.
    if confirm_key not in expiry_data:
        expiry_data[confirm_key] = {}
    expiry_data[confirm_key]['expiry'] = expiry
    expiry_data[confirm_key]['fallback'] = fallback
    expiry_data[confirm_key]['message_file'] = message_file
    # Write to file.
    write_autoconfirm_file(autoconfirm_file, expiry_data)


def get_autoconfirm(autoconfirm_file, confirm_key=None):
    """ Check if autoconfirmation is enabled for the given key. """
    fallback = True
    message_file = None
    if not os.path.exists(autoconfirm_file):
        return False, fallback, message_file
    # Load autoconfirm file.
    expiry_data = read_autoconfirm_file(autoconfirm_file)
    # Confirmation key "LOGIN" has highest priority before ALL.
    if "LOGIN" in expiry_data:
        confirm_key = "LOGIN"
    elif "ALL" in expiry_data:
        confirm_key = "ALL"
    if not confirm_key:
        confirm_key = "ALL"
    # Try to get autoconfirm expiry.
    try:
        autoconfirm_expiry = float(expiry_data[confirm_key]['expiry'])
    except:
        autoconfirm_expiry = 0.0
    # Try to get autoconfirm fallback setting.
    try:
        fallback = expiry_data[confirm_key]['fallback']
    except:
        pass
    # Try to get autoconfirm error file.
    try:
        message_file = expiry_data[confirm_key]['message_file']
    except:
        message_file = None
    # Check if autoconfirm has expired.
    if time.time() < autoconfirm_expiry:
        return True, fallback, message_file
    # Remove outdated expiry from file.
    try:
        expiry_data.pop(confirm_key)
    except:
        pass
    # Write to file.
    write_autoconfirm_file(autoconfirm_file, expiry_data)
    return False, fallback, message_file


def remove_autoconfirm(autoconfirm_file, confirm_key):
    """ Remove given autoconfirm key in file. """
    # Load autoconfirm file.
    expiry_data = read_autoconfirm_file(autoconfirm_file)
    # Set expiry in seconds.
    try:
        expiry_data.pop(confirm_key)
    except:
        pass
    # Write to file.
    write_autoconfirm_file(autoconfirm_file, expiry_data)


class MySpinBox(QtGui.QSpinBox):
    def focusInEvent(self, event):
        self.parentWidget().ui.ButtonAllow.setDefault(True)
        super(MySpinBox, self).focusInEvent(event)
    def focusOutEvent(self, event):
        self.parentWidget().ui.ButtonAllow.setDefault(False)
        super(MySpinBox, self).focusOutEvent(event)


class PinEntryDialog(object):
    def set_window_title(self, title):
        self.dialog.setWindowTitle(_translate("PinEntryConfirm", title, None))


class PinEntryAskPin(PinEntryDialog):
    def setupUi(self, dialog):
        global icon_ok
        global icon_window
        global icon_cancel
        self.dialog = dialog
        style = self.dialog.style()
        self.dialog.setObjectName(_fromUtf8("PinEntryAskPin"))
        self.dialog.resize(361, 162)
        self.dialog.setFocusPolicy(QtCore.Qt.TabFocus)
        icon_window = get_icon(style, icon_window)
        self.dialog.setWindowIcon(icon_window)
        self.labelPIN = QtGui.QLabel(self.dialog)
        self.labelPIN.setGeometry(QtCore.QRect(70, 40, 41, 31))
        self.labelPIN.setObjectName(_fromUtf8("labelPIN"))
        self.ButtonOk = QtGui.QPushButton(self.dialog)
        self.ButtonOk.setGeometry(QtCore.QRect(110, 100, 110, 41))
        icon_ok = get_icon(style, icon_ok)
        self.ButtonOk.setIcon(icon_ok)
        self.ButtonOk.setObjectName(_fromUtf8("ButtonOk"))
        self.ButtonCancel = QtGui.QPushButton(self.dialog)
        self.ButtonCancel.setGeometry(QtCore.QRect(230, 100, 110, 41))
        icon_cancel = get_icon(style, icon_cancel)
        self.ButtonCancel.setIcon(icon_cancel)
        self.ButtonCancel.setObjectName(_fromUtf8("ButtonCancel"))
        self.lineEditPIN = QtGui.QLineEdit(self.dialog)
        self.lineEditPIN.setGeometry(QtCore.QRect(110, 40, 231, 37))
        self.lineEditPIN.setEchoMode(QtGui.QLineEdit.Password)
        self.lineEditPIN.setObjectName(_fromUtf8("lineEditPIN"))

        self.labelIcon = QtGui.QLabel(self.dialog)
        self.labelIcon.setGeometry(QtCore.QRect(10, 20, 61, 61))
        self.labelIcon.setText(_fromUtf8(""))
        x = icon_window.pixmap(48, 48, QtGui.QIcon.Normal, QtGui.QIcon.Off)
        self.labelIcon.setPixmap(x)
        self.labelIcon.setObjectName(_fromUtf8("labelIcon"))

        # Set labels.
        self.set_prompt()
        self.ButtonOk.setText(_translate("PinEntryAskPin", "OK", None))
        self.ButtonCancel.setText(_translate("PinEntryAskPin", "Cancel", None))

        QtCore.QMetaObject.connectSlotsByName(self.dialog)
        self.dialog.setTabOrder(self.lineEditPIN, self.ButtonOk)
        self.dialog.setTabOrder(self.ButtonOk, self.ButtonCancel)

    def set_prompt(self, prompt="PIN:"):
        self.labelPIN.setText(_translate("PinEntryAskPin", prompt, None))


class PinEntryConfirm(PinEntryDialog):
    def setupUi(self, dialog):
        global icon_ok
        global icon_window
        global icon_cancel
        self.dialog = dialog
        style = self.dialog.style()
        self.dialog.setObjectName(_fromUtf8("PinEntryConfirm"))
        self.dialog.resize(491, 188)

        #sizePolicy = QtGui.QSizePolicy(QtGui.QSizePolicy.Expanding,
        #                                QtGui.QSizePolicy.Preferred)
        sizePolicy = QtGui.QSizePolicy(QtGui.QSizePolicy.MinimumExpanding,
                                        QtGui.QSizePolicy.Preferred)

        sizePolicy.setHorizontalStretch(0)
        sizePolicy.setVerticalStretch(0)
        sizePolicy.setHeightForWidth(self.dialog.sizePolicy().hasHeightForWidth())
        self.dialog.setSizePolicy(sizePolicy)

        self.dialog.setFocusPolicy(QtCore.Qt.TabFocus)
        icon_window = get_icon(style, icon_window)
        self.dialog.setWindowIcon(icon_window)
        #self.AutoconfirmSpinBox = QtGui.QSpinBox(self.dialog)
        self.AutoconfirmSpinBox = MySpinBox(self.dialog)
        self.AutoconfirmSpinBox.setGeometry(QtCore.QRect(250, 100, 61, 31))
        #self.AutoconfirmSpinBox.setFocusPolicy(QtCore.Qt.NoFocus)
        self.AutoconfirmSpinBox.setFocusPolicy(QtCore.Qt.TabFocus)
        self.AutoconfirmSpinBox.setObjectName(_fromUtf8("AutoconfirmSpinBox"))

        self.AllKeysCheckBox = QtGui.QCheckBox(self.dialog)
        self.AllKeysCheckBox.setGeometry(QtCore.QRect(150, 100, 71, 22))
        self.AllKeysCheckBox.setObjectName(_fromUtf8("AllKeysCheckBox"))
        self.AllKeysCheckBox.setText(_translate("PinEntryDialog", "all keys", None))

        self.labelText = QtGui.QLabel(self.dialog)
        self.labelText.setGeometry(QtCore.QRect(90, 10, 401, 81))
        self.labelText.setText(_fromUtf8(""))
        self.labelText.setWordWrap(True)
        self.labelText.setObjectName(_fromUtf8("labelText"))

        self.labelIcon = QtGui.QLabel(self.dialog)
        self.labelIcon.setGeometry(QtCore.QRect(10, 20, 71, 61))
        self.labelIcon.setText(_fromUtf8(""))
        x = icon_window.pixmap(48, 48, QtGui.QIcon.Normal, QtGui.QIcon.Off)
        self.labelIcon.setPixmap(x)
        self.labelIcon.setWordWrap(True)
        self.labelIcon.setObjectName(_fromUtf8("labelIcon"))

        self.AutoconfirmLabel = QtGui.QLabel(self.dialog)
        self.AutoconfirmLabel.setGeometry(QtCore.QRect(320, 100, 151, 23))
        self.AutoconfirmLabel.setObjectName(_fromUtf8("AutoconfirmLabel"))
        self.ButtonAllow = QtGui.QPushButton(self.dialog)
        self.ButtonAllow.setGeometry(QtCore.QRect(250, 140, 110, 39))
        icon_ok = get_icon(style, icon_ok)
        self.ButtonAllow.setIcon(icon_ok)
        self.ButtonAllow.setObjectName(_fromUtf8("ButtonAllow"))
        self.ButtonDeny = QtGui.QPushButton(self.dialog)
        self.ButtonDeny.setGeometry(QtCore.QRect(370, 140, 110, 39))
        icon_cancel = get_icon(style, icon_cancel)
        self.ButtonDeny.setIcon(icon_cancel)
        self.ButtonDeny.setObjectName(_fromUtf8("ButtonDeny"))

        # Set labels.
        self.set_text("")
        self.set_window_title(PINENTRY_NAME)
        self.ButtonDeny.setText(_translate("PinEntryConfirm", "Deny", None))
        self.ButtonAllow.setText(_translate("PinEntryConfirm", "Allow", None))
        self.AutoconfirmLabel.setText(_translate("PinEntryDialog", "Remember (Min.)", None))

        QtCore.QMetaObject.connectSlotsByName(self.dialog)
        self.dialog.setTabOrder(self.ButtonDeny, self.ButtonAllow)
        self.dialog.setTabOrder(self.ButtonAllow, self.AutoconfirmSpinBox)
        self.dialog.setTabOrder(self.AutoconfirmSpinBox, self.AllKeysCheckBox)

    def set_text(self, text):
        self.labelText.setText(_translate("PinEntryConfirm", text, None))

    def disable_autoconfirm(self):
        self.AutoconfirmSpinBox.setVisible(False)
        self.AllKeysCheckBox.setVisible(False)
        self.AutoconfirmLabel.setVisible(False)


class OTPmePinentry(QtGui.QDialog):
    def __init__(self, parent=None, title=PINENTRY_NAME,
        ask_pin=False, text=None, prompt="PIN:",
        disable_autoconfirm=False, autoconfirm_file=None):
        # Init widget.
        QtGui.QWidget.__init__(self, parent)

        if ask_pin:
            self.ui = PinEntryAskPin()
            self.pin = None
        else:
            self.ui = PinEntryConfirm()
            self.confirm = None

        self.ui.setupUi(self)
        self.ui.set_window_title(title)

        if disable_autoconfirm:
            self.ui.disable_autoconfirm()

        if ask_pin:
            self.ui.ButtonOk.clicked.connect(self.ok_button)
            self.ui.ButtonCancel.clicked.connect(self.cancel_button)
            self.ui.set_prompt(prompt)
        else:
            self.ui.ButtonAllow.clicked.connect(self.allow_button)
            self.ui.ButtonDeny.clicked.connect(self.deny_button)
            self.ui.set_text(text)
            self.autoconfirm_file = autoconfirm_file
            if not self.autoconfirm_file:
                self.ui.AutoconfirmSpinBox.setEnabled(False)

        self.show()

    def ok_button(self):
        self.pin = self.ui.lineEditPIN.text()
        self.close()

    def cancel_button(self):
        self.close()

    def allow_button(self):
        if self.autoconfirm_file:
            expiry = self.ui.AutoconfirmSpinBox.value()
            all_keys = self.ui.AllKeysCheckBox.isChecked()
            if all_keys:
                confirm_key = "ALL"
            else:
                confirm_key = str(self.ui.labelText.text())
            if not confirm_key:
                confirm_key = "ALL"
            autoconfirm_expiry = str(time.time() + (expiry * 60))
            set_autoconfirm(self.autoconfirm_file,
                            confirm_key,
                            autoconfirm_expiry)

        self.confirm = True
        self.close()

    def deny_button(self):
        self.confirm = False
        self.close()


def get_pin(title=PINENTRY_NAME, prompt="PIN:"):
    """ Get PIN from user. """
    app = QtGui.QApplication(sys.argv)
    pinentry = OTPmePinentry(title=title, ask_pin=True, prompt=prompt)
    app.exec_()
    return pinentry.pin


def ask_confirm(title=PINENTRY_NAME, text="Allow this?",
    disable_autoconfirm=False, autoconfirm_file=None):
    """ Ask user to confirm action. """
    app = QtGui.QApplication(sys.argv)
    pinentry = OTPmePinentry(title=title,
                            ask_pin=False,
                            text=text,
                            autoconfirm_file=autoconfirm_file,
                            disable_autoconfirm=disable_autoconfirm)
    app.exec_()
    return pinentry.confirm


def start_pinentry_wrapper(pinentry_bin, pinentry_opts,
    command_history, debug_log=None):
    """ Start original pinentry and send commands to it. """
    if debug_log:
        msg = ("Trying fallback to original pinentry program: %s\n"
                % " ".join(pinentry_bin))
        debug_log.write(msg)

    if pinentry_bin is None:
        if basename == "pinentry":
            pinentry_bin = "pinentry-qt4"
        else:
            pinentry_bin = "pinentry"

    command = [ pinentry_bin ]

    if pinentry_opts is not None:
        x_type = type(pinentry_opts)
        if x_type != list:
            msg = (_("Expected pinentry_opts as <list>. Got %s") % x_type)
            raise Exception(msg)
        command += pinentry_opts

    # Start original pinentry.
    proc = system_command.run(command, return_proc=True)
    # Read first line.
    proc.stdout.readline()

    while True:
        if len(command_history) > 0:
            line = "%s\n" % command_history[0]
            command_history.pop(0)
        else:
            try:
                line = sys.stdin.readline()
            except KeyboardInterrupt:
                break

        if not line or line == "\n":
            continue

        if debug_log:
            msg = ("Sending command to original pinentry: %s" % line)
            debug_log.write(msg)

        # Send line to pinentry.
        try:
            proc.stdin.write(line)
        except Exception as e:
            if debug_log:
                msg = ("Error sending command to original "
                        "pinentry: %s\n" % e)
                debug_log.write(msg)
            raise

        # Handle reply.
        if debug_log:
            debug_log.write("Reading reply from original pinentry...\n")

        try:
            r = proc.stdout.readline()
        except Exception as e:
            if debug_log:
                msg = ("Error reading reply from original "
                        "pinentry: %s\n" % e)
                debug_log.write(msg)
            raise

        reply = r
        while not r.lower().startswith("ok") \
        and not r.lower().startswith("err"):
            if debug_log:
                debug_log.write("Reading reply from original pinentry...\n")
            try:
                r = proc.stdout.readline()
            except Exception as e:
                if debug_log:
                    debug_log.write("Error reading reply from original "
                            "pinentry: %s\n" % e)
                raise
            if r == "":
                if debug_log:
                    debug_log.write("Error running original pinentry: %s"
                            % proc.stderr.read())
                sys.exit(1)
                break
            reply += r

        if len(command_history) == 0:
            try:
                sys.stdout.write(reply)
                sys.stdout.flush()
            except Exception as e:
                if line.lower() != "bye\n":
                    if debug_log:
                        msg = ("Error writing reply to stdout: %s\n" % line)
                        debug_log.write(msg)
                    raise

        if line.lower().startswith("bye ") or line.lower() == "bye\n":
            if reply.lower().startswith("ok "):
                break
        # Iteration sleep to prevent running wild if something goes wrong.
        time.sleep(0.01)


def run(title=PINENTRY_NAME, pin=None, pin_function=None,
    prompt="PIN:", text="", autoconfirm=False, autoconfirm_file=None,
    confirm_fallback=True, message_file=None, pin_fallback=True,
    wrapper=False, pinentry_bin=None, pinentry_opts=None, debug_file=None):
    """
    Start pinentry wrapper to send given PIN or get PIN via helper function.
    """
    debug_log = None
    if debug_file:
        debug_log = open(debug_file, "w")
        debug_log.write("Autoconfirmation enabled: %s\n" % autoconfirm)
        debug_log.flush()

    command_history = []
    # Text gpg sends when confirming key usage is requested.
    confirm_key_text = "An ssh process requested the use of key"
    # Text gpg sends when a specific card is requested.
    wrong_card_text = "Please remove the current card and insert the one with serial number:"

    # Set default display.
    try:
        display = os.environ['DISPLAY']
    except:
        display = ":0"
    os.environ['DISPLAY'] = str(display)

    # Print greeting.
    sys.stdout.write("OK Pleased to meet you\n")
    sys.stdout.flush()

    disable_autoconfirm = True
    while True:
        try:
            line = sys.stdin.readline()
        except KeyboardInterrupt:
            break

        command_history.append(line)
        command = line.rstrip()

        if not command:
            continue

        # Handle options.
        if command.startswith("OPTION "):
            x = command.split()
            command = x[0]
            x = " ".join(x[1:])
            x = x.split("=")
            option = x[0]
            value = "=".join(x[1:])
            if option == "default-prompt":
                prompt = value
            else:
                if debug_file:
                    debug_log.write("Ignoring option: %s=%s\n"
                                % (option, value))
                    debug_log.flush()
            sys.stdout.write("OK\n")
            sys.stdout.flush()
            continue

        # Handle command args.
        if " " in command:
            x = command.split()
            command = x[0]
            parameters = " ".join(x[1:])
            if command == "SETPROMPT":
                prompt = parameters
            elif command == "SETDESC":
                text = parameters.replace("%0A", "\n")
                if confirm_key_text in text:
                    disable_autoconfirm = False
                if wrong_card_text in text:
                    disable_autoconfirm = True
            elif command == "GETINFO" and parameters == "pid":
                msg = "D %s\n" % os.getpid()
                sys.stdout.write(msg)
                sys.stdout.flush()
            else:
                if debug_file:
                    debug_log.write("Ignoring command: %s %s\n"
                            % (command, parameters))
                    debug_log.flush()
            sys.stdout.write("OK\n")
            sys.stdout.flush()
            continue

        command = command.upper()

        if debug_file:
            debug_log.write("Received command: %s\n" % command)
            debug_log.flush()

        if command == "CONFIRM":
            status = False
            if autoconfirm_file:
                autoconfirm, \
                confirm_fallback, \
                message_file = get_autoconfirm(autoconfirm_file,
                                                confirm_key=text)

            if autoconfirm and not disable_autoconfirm:
                if debug_file:
                    debug_log.write("Doing autoconfirm.\n")
                    debug_log.flush()
                status = True

            elif confirm_fallback:
                if debug_file:
                    debug_log.write("Doing confirm.\n")
                    debug_log.flush()
                if wrapper:
                    start_pinentry_wrapper(pinentry_bin,
                                            pinentry_opts,
                                            command_history,
                                            debug_log=debug_log)
                    break
                # Try to get confirmation via pyQt.
                status = ask_confirm(title=title,
                                text=text,
                                autoconfirm_file=autoconfirm_file,
                                disable_autoconfirm=disable_autoconfirm)
                if debug_file:
                    debug_log.write("Confirm status: %s\n" % status)
                    debug_log.flush()

            elif message_file is not None:
                try:
                    fd = open(message_file, "w")
                    fd.write(text)
                    fd.close()
                except Exception as e:
                    msg = ("Failed to write to autoconfirm message file: "
                            "%s: %s" % (message_file, e))
                    sys.stderr.write(msg)
                    sys.stderr.flush()

            if status:
                sys.stdout.write("OK\n")
                sys.stdout.flush()
            else:
                sys.stdout.write("ERR 83886179 canceled\n")
                sys.stdout.flush()
            continue

        elif command == "GETPIN":
            if not pin:
                if pin_function:
                    if debug_file:
                        debug_log.write("Starting PIN function...\n")
                        debug_log.flush()
                    try:
                        pin = pin_function()
                    except Exception as e:
                        if debug_file:
                            debug_log.write("Exception in PIN function: %s\n"
                                    % e)
                            debug_log.flush()
                        break
                    if not pin:
                        if debug_file:
                            debug_log.write("No PIN received from PIN function.\n")
                            debug_log.flush()
            if not pin:
                if pin_fallback:
                    if wrapper:
                        start_pinentry_wrapper(pinentry_bin,
                                                pinentry_opts,
                                                command_history,
                                                debug_log=debug_log)
                        break
                    # Try to get pin via pyQt.
                    pin = get_pin(title=title, prompt=prompt)

            if pin:
                sys.stdout.write("D %s\n" % pin)
                sys.stdout.flush()
                sys.stdout.write("OK\n")
                sys.stdout.flush()
                pin = None
                continue
            else:
                if debug_file:
                    debug_log.write("Cancelling GETPIN action (pin_fallback=False)\n")
                    debug_log.flush()
                sys.stdout.write("ERR 83886179 canceled\n")
                sys.stdout.flush()
                continue

        elif command == "BYE":
            #sys.stdout.write("OK closing connection\n")
            #sys.stdout.flush()
            break

        else:
            msg = ("Ignoring unknown command: %s\n" % command)
            if debug_file:
                debug_log.write(msg)
                debug_log.flush()
            sys.stderr.write(msg)
            sys.stderr.flush()

    if debug_file:
        debug_log.close()


if __name__ == "__main__":
    debug_file = None
    #debug_file = "/tmp/test.log"
    user_uid = os.getuid()
    user_name = pwd.getpwuid(user_uid).pw_name
    tmp_dir = "/tmp/"
    file_name = "%s-%s" % (PINENTRY_NAME, user_name)
    autoconfirm_file = os.path.join(tmp_dir, file_name)
    run(title=PINENTRY_NAME,
        autoconfirm_file=autoconfirm_file,
        wrapper=True,
        debug_file=debug_file)
