#!/usr/bin/env python3

from flask_wtf import FlaskForm
from wtforms import (
    StringField,
    SubmitField,
    SelectField,
    PasswordField,
)
from wtforms.validators import (
    Required,
    StopValidation,
    Email,
    EqualTo,
)

from app import models as m


def optional_validation(form, field):
    if not field.data:
        field.errors[:] = []
        raise StopValidation()


class NonValidatingSelectField(SelectField):
    def pre_validate(self, form):
        pass


class AddUser(FlaskForm):
    username = StringField("Username", validators=[Required()])
    # email = StringField('Email Address', validators=[Email(), optional_validation])
    password = PasswordField("Temporary Password")
    role = SelectField("Role", choices=[(r.name.lower(), r.name) for r in m.UserRole])
    submit = SubmitField("Add")


class EditUser(FlaskForm):
    role = SelectField("Role", choices=[(r.name.lower(), r.name) for r in m.UserRole])
    submit = SubmitField("Save")


class EditTags(FlaskForm):
    tags = StringField("")
    submit = SubmitField("Save")


class LoginForm(FlaskForm):
    username = StringField("Username", validators=[Required()])
    password = PasswordField("Password", validators=[Required()])
    submit = SubmitField("Log In")


class ProfileForm(FlaskForm):
    email = StringField("Email Address", validators=[Email(), optional_validation],)
    current_password = PasswordField("Current Password")
    new_password1 = PasswordField("New Password", validators=[optional_validation],)
    new_password2 = PasswordField(
        "New Password Confirmation",
        validators=[
            optional_validation,
            EqualTo("new_password1", message="New passwords must match."),
        ],
    )
    submit = SubmitField("Save")


class TempPasswordForm(FlaskForm):
    temp_password = PasswordField("Temp Password")
    new_password1 = PasswordField("New Password", validators=[optional_validation],)
    new_password2 = PasswordField(
        "New Password Confirmation",
        validators=[
            optional_validation,
            EqualTo("new_password1", message="New passwords must match."),
        ],
    )
    submit = SubmitField("Save")
