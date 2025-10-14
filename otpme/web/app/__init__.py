# -*- coding: utf-8 -*-
# Copyright (C) 2014 the2nd <the2nd@otpme.org>
from flask import Flask
from flask_login import LoginManager
#from werkzeug.middleware.proxy_fix import ProxyFix

app = Flask(__name__,
        static_url_path='/static')
        #static_folder='app/static',
        #template_folder='otpme/web/app/templates')

#app.wsgi_app = ProxyFix(
#    app.wsgi_app, x_for=1, x_proto=1, x_host=1, x_prefix=1
#)

lm = LoginManager()
lm.init_app(app)

from otpme.web.app import views
