from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import DataRequired, Email, Length, Regexp

class LoginForm(FlaskForm):
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired(), Length(min=6)])
    submit = SubmitField('Login')

class OTPForm(FlaskForm):
    email = StringField('Email', validators=[DataRequired(), Email()])
    otp = StringField('OTP', validators=[DataRequired(), Length(min=6, max=6)])
    submit = SubmitField('Verify')

class RegisterForm(FlaskForm):
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired(), Length(min=6)])
    phone = StringField('Phone no. (Please enter country code as well.)', validators=[DataRequired(), 
                                                                                    Regexp(r'^\+\d{1,3}\d{9,15}$', 
                                                                                           message="Invalid phone number. It must include a country code starting with '+'.")])
    submit = SubmitField('Get OTP through Email')