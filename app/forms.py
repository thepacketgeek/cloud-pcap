#!/usr/bin/env python3

from flask_wtf import FlaskForm
from wtforms import (
    StringField,
    SubmitField,
    SelectField,
    PasswordField,
    TextAreaField,
    BooleanField,
    IntegerField,
)
from wtforms.validators import (
    Required,
    IPAddress,
    StopValidation,
    Email,
    EqualTo,
    NumberRange,
)


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
    role = SelectField("Role", choices=[("admin", "Admin"), ("user", "User")])
    submit = SubmitField("Add")


class EditUser(FlaskForm):
    role = SelectField("Role", choices=[("admin", "Admin"), ("user", "User")])
    submit = SubmitField("Save")


class EditTags(FlaskForm):
    tags = StringField("")
    submit = SubmitField("Save")


class LoginForm(FlaskForm):
    username = StringField("Username", validators=[Required()])
    password = PasswordField("Password", validators=[Required()])
    # remember_me = BooleanField('Keep me logged in')
    submit = SubmitField("Log In")


class ProfileForm(FlaskForm):
    email = StringField("Email Address", validators=[Email(), optional_validation])
    current_password = PasswordField("Current Password")
    new_password1 = PasswordField("New Password", validators=[optional_validation])
    new_password2 = PasswordField(
        "New Password Confirmation",
        validators=[
            optional_validation,
            EqualTo("new_password1", message=u"New passwords must match."),
        ],
    )
    submit = SubmitField("Save")


class TempPasswordForm(FlaskForm):
    temp_password = PasswordField("Temp Password")
    new_password1 = PasswordField("New Password", validators=[optional_validation])
    new_password2 = PasswordField(
        "New Password Confirmation",
        validators=[
            optional_validation,
            EqualTo("new_password1", message=u"New passwords must match."),
        ],
    )
    submit = SubmitField("Save")
