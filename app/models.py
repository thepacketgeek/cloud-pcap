#!/usr/bin/env python3
import secrets
from enum import Enum

from flask_login import UserMixin
from werkzeug.security import generate_password_hash, check_password_hash


from app import db


def get_uuid():
    return secrets.token_hex(16)


class UserRole(Enum):
    ADMIN = 0
    USER = 1

    def __str__(self) -> str:
        return self.name


class User(UserMixin, db.Model):
    __tablename__ = "users"

    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(64), unique=True, index=True)
    username = db.Column(db.String(64), unique=True, index=True)
    password_hash = db.Column(db.String(128))
    token = db.Column(db.String(64))
    role = db.Column(db.Enum(UserRole), default=UserRole.USER)
    temp_password = db.Column(db.Boolean())

    @property
    def password(self):
        raise AttributeError("password is not a readable attribute")

    @password.setter
    def password(self, password: str):
        self.password_hash = generate_password_hash(password)

    def verify_password(self, password: set):
        return check_password_hash(self.password_hash, password)

    def __repr__(self):
        return f"<User [{self.role}] {self.username!r}>"


tags = db.Table(
    "trace_tags",
    db.Column("tag_id", db.Integer, db.ForeignKey("tags.id"), primary_key=True),
    db.Column(
        "tracefiles_id", db.String(8), db.ForeignKey("tracefiles.id"), primary_key=True
    ),
)


class TraceFile(db.Model):
    __tablename__ = "tracefiles"

    id = db.Column(db.String(8), primary_key=True)
    name = db.Column(db.String(128), index=True)
    description = db.Column(db.Text())
    filename = db.Column(db.String(128))
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"))
    username = db.relationship("User")
    filesize = db.Column(db.Integer)  # Bytes
    filetype = db.Column(db.String(64))
    packet_count = db.Column(db.Integer)
    date_added = db.Column(db.DateTime)

    tags = db.relationship(
        "Tag",
        secondary=tags,
        lazy="subquery",
        backref=db.backref("tracefiles", lazy=True),
    )

    def __repr__(self):
        return f"<TraceFile {self.name!r}, filename: {self.filename!r}>"


class Tag(db.Model):
    __tablename__ = "tags"

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(64))

    def __repr__(self):
        num_files = len(self.tracefiles)
        return f"<Tag {self.name!r} files={num_files}>"


class Log(db.Model):
    __tablename__ = "logs"
    id = db.Column(db.Integer, primary_key=True)
    timestamp = db.Column(db.DateTime)
    level = db.Column(db.String)  # info, warning, error
    description = db.Column(db.String)

    def __repr__(self):
        return f"<Log [{self.level}]: {self.timestamp} - {self.description}>"
