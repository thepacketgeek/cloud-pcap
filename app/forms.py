from flask.ext.wtf import Form
from wtforms import StringField, SubmitField, SelectField, PasswordField, TextAreaField, BooleanField, IntegerField
from wtforms.validators import Required, IPAddress, StopValidation, Email, EqualTo, NumberRange

def optional_validation(form, field):
  if not field.data:
    field.errors[:] = []
    raise StopValidation()

class NonValidatingSelectField(SelectField):
    def pre_validate(self, form):
        pass

class AddUser(Form):
    username = StringField('Username', validators=[Required()])
    # email = StringField('Email Address', validators=[Email(), optional_validation])
    password = PasswordField('Temporary Password')
    role = SelectField('Role', choices=[('admin','Admin'),('user', 'User')])
    submit = SubmitField('Add')

class EditUser(Form):
    role = SelectField('Role', choices=[('admin', 'Admin'), ('user', 'User')])
    submit = SubmitField('Save')

class EditTags(Form):
    tags = StringField('')
    submit = SubmitField('Save')

class LoginForm(Form):
    username = StringField('Username', validators=[Required()])
    password = PasswordField('Password', validators=[Required()])
    # remember_me = BooleanField('Keep me logged in')
    submit = SubmitField('Log In')

class ProfileForm(Form):
    email = StringField('Email Address', validators=[Email(), optional_validation])
    current_password = PasswordField('Current Password')
    new_password1 = PasswordField('New Password', validators=[optional_validation])
    new_password2 = PasswordField('New Password Confirmation', validators=[optional_validation, EqualTo('new_password1', message=u'New passwords must match.')])
    submit = SubmitField('Save')

class TempPasswordForm(Form):
    temp_password = PasswordField('Temp Password')
    new_password1 = PasswordField('New Password', validators=[optional_validation])
    new_password2 = PasswordField('New Password Confirmation', validators=[optional_validation, EqualTo('new_password1', message=u'New passwords must match.')])
    submit = SubmitField('Save')

class SanitizeForm(Form):
    sequential = BooleanField('Sequential Addressing (vs. Random)', default=True)
    ipv4_mask = IntegerField('IPv4 Mask', validators=[NumberRange(min=0, max=24)])
    ipv6_mask = IntegerField('IPv6 Mask', validators=[NumberRange(min=0, max=64)])
    mac_mask = IntegerField('MAC Mask', validators=[NumberRange(min=0, max=40)])
    start_ipv4 = StringField('IPv4 Starting Address')
    start_ipv6 = StringField('IPv6 Starting Address')
    start_mac = StringField('MAC Starting Address')
    submit = SubmitField('Sanitize')