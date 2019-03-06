from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, BooleanField, SubmitField
from wtforms.validators import DataRequired, Length, Email, Regexp, EqualTo
from wtforms import ValidationError
from ..models import User


class LoginForm(FlaskForm):
    email = StringField('Email', validators=[DataRequired(), Length(1, 64), Email()])
    password = PasswordField('Password', validators=[DataRequired()])
    remember_me = BooleanField('Keep me logged in')
    submit = SubmitField('Login In')


class RegistrationForm(FlaskForm):
    email = StringField('Email', validators=[DataRequired(), Length(1, 64), Email()])
    username = StringField('Username', validators=[
        DataRequired(), Length(1, 64), Regexp('^[A-Za-z][A-Za-z0-9]*$', 0,
                                              'Usernames must have only letters, numbers, dots or underscores')
    ])
    password = PasswordField('Password', validators=[
        DataRequired(), EqualTo('password2', message='Password must match.')
    ])
    password2 = PasswordField('Confirm password', validators=[DataRequired()])
    submit = SubmitField('Register')

    def validate_email(self, field):
        if User.query.filter_by(email=field.data).first():
            raise ValidationError('Email already registered.')

    def validate_username(self, field):
        if User.query.filter_by(username=field.data).first():
            raise ValidationError('Username already in use.')


class ChangePassword(FlaskForm):
    old_password = PasswordField('Old password', validators=[DataRequired()])
    password = PasswordField('Password', validators=[
        DataRequired(), EqualTo('password2', message='Password must match.')
    ])
    password2 = PasswordField('Confirm password', validators=[DataRequired()])
    submit = SubmitField('Update Password')

    def validate_password(self, field):
        if field.data == self.old_password.data:
            raise ValidationError('The new password needs to be different from the original one.')


class ChangeEmail(FlaskForm):
    password = PasswordField('password', validators=[DataRequired()])
    email = StringField('New email', validators=[DataRequired(), Length(1, 64), Email()])
    submit = SubmitField('Update Email')

    def validate_email(self, field):
        if User.query.filter_by(email=field.data).first():
            raise ValidationError('Email already registered.')
        if field.data == self.email:
            raise ValidationError('The mail is the same as the original one.')

