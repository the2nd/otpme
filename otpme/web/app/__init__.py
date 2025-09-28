# -*- coding: utf-8 -*-
# Copyright (C) 2014 the2nd <the2nd@otpme.org>
from flask import Flask
from flask_login import LoginManager


app = Flask(__name__,
        static_url_path='/static')
        #static_folder='app/static',
        #template_folder='otpme/web/app/templates')


lm = LoginManager()
lm.init_app(app)

from otpme.web.app import views
