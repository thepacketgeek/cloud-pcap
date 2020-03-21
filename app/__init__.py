#!/usr/bin/env python3

import datetime
import os
import random
import string
from typing import Optional

import click
from flask import Flask
from flask_bootstrap import Bootstrap
from flask_login import LoginManager
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate

from app import config
from app.pcap_helper import PcapHelper


BASE_DIR = os.environ.get("BASE_DIR", "/opt/flask-app")

app = Flask(__name__)
bootstrap = Bootstrap(app)

app.jinja_env.add_extension("chartkick.ext.charts")
app.config.from_object(config.Config)
app.jinja_env.filters["format_comma"] = lambda v: f"{v:,.0f}"


db = SQLAlchemy(app, session_options={"expire_on_commit": False})
migrate = Migrate(app, db, directory=os.path.join(BASE_DIR, "migrations"))

login_manager = LoginManager(app)
login_manager.session_protection = "strong"
login_manager.login_view = "login"


pcap = PcapHelper(BASE_DIR)


def log(level, description):
    log = m.Log(
        timestamp=datetime.datetime.now(), level=level.upper(), description=description,
    )
    db.session.add(log)
    db.session.commit()


from app import models as m
from app.routes import admin, web  # noqa


@app.shell_context_processor
def make_shell_context():
    return dict(
        app=app,
        db=db,
        User=m.User,
        UserRole=m.UserRole,
        Tag=m.Tag,
        TraceFile=m.TraceFile,
        Log=m.Log,
    )


@app.cli.command("create-admin")
@click.option("-p", "--password")
def create_admin(password: Optional[str] = None):
    """ Initialize App with default admin user """
    if password is None:
        password = "".join(random.choice(string.ascii_lowercase) for i in range(20))
        is_temp_password = True
    else:
        is_temp_password = False

    admin_user = m.User(
        username="admin",
        password=password,
        role=m.UserRole.ADMIN,
        token=m.get_uuid(),
        temp_password=is_temp_password,
    )
    db.session.add(admin_user)
    print(f"User {admin_user.username!r} added with password: {password!r}")
    db.session.commit()
