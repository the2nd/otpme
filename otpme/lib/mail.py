# -*- coding: utf-8 -*-
# Copyright (C) 2014 the2nd <the2nd@otpme.org>
import os
import smtplib
from email.utils import formatdate
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

try:
    if os.environ['OTPME_DEBUG_MODULE_LOADING'] == "True":
        msg = _("Loading module: {module_name}")
        msg = msg.format(module_name=__name__)
        print(msg)
except Exception:
    pass

#from otpme.lib import config

from otpme.lib.exceptions import *

def send_mail(mail_from, mail_to, subject, message=None,
    html_message=None, server="127.0.0.1", port=587,
    starttls=False, username=None, password=None,
    force=False, timeout=30):
    """ Send mail via SMTP. """
    msg = MIMEMultipart()
    msg['From'] = mail_from
    msg['To'] = mail_to
    msg['Subject'] = subject
    msg["Date"] = formatdate(localtime=True)
    if message is not None:
        body = MIMEText(message, "plain")
    elif html_message is not None:
        body = MIMEText(html_message, "html")
    else:
        raise OTPmeException("Need <message> or <html_message>.")

    msg.attach(body)

    try:
        mailserver = smtplib.SMTP(server, port, timeout=timeout)
    except Exception as e:
        msg = _("Failed to connect to SMTP server: {e}")
        msg = msg.format(e=e)
        raise OTPmeException(msg) from e
    try:
        mailserver.ehlo()
    except Exception as e:
        msg = _("Failed to send EHLO to SMTP server: {e}")
        msg = msg.format(e=e)
        raise OTPmeException(msg) from e
    if starttls:
        try:
            mailserver.starttls()
        except Exception as e:
            msg = _("STARTTLS failed with SMTP server: {e}")
            msg = msg.format(e=e)
            raise OTPmeException(msg) from e
        # Re-identify via TLS.
        try:
            mailserver.ehlo()
        except Exception as e:
            msg = _("STARTTLS EHLO failed with SMTP server: {e}")
            msg = msg.format(e=e)
            raise OTPmeException(msg) from e
    if username and password:
        if not starttls and not force:
            msg = _("You should not send authentication information unencrypted. Please consider using starttls=True or use force=True to send username/password unencrypted.")
            raise OTPmeException(msg)
        mailserver.login(username, password)
    mailserver.sendmail(mail_from, mail_to, msg.as_string())
    mailserver.quit()
