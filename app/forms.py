from flask.ext.wtf import Form
from wtforms import StringField, SubmitField, SelectField, PasswordField, TextAreaField, BooleanField
from wtforms.validators import Required, IPAddress, StopValidation, Email, EqualTo

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