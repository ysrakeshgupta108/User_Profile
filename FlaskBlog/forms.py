from flask_wtf import FlaskForm
import wtforms
from wtforms.validators import DataRequired, Length, Email, EqualTo

class RegistrationForm(FlaskForm):
    username = wtforms.StringField("Username",
                                   validators=[DataRequired(),Length(min=2,max=20)])
    email = wtforms.StringField('Email', validators=[DataRequired(),Email()])
    password = wtforms.PasswordField('Password',validators=[DataRequired()])
    confirm_password = wtforms.PasswordField('Confirm Password',validators=[DataRequired(),EqualTo('password')])
    submit = wtforms.SubmitField('Sing UP!')

class LoginForm(FlaskForm):
    email = wtforms.EmailField('Email', validators=[DataRequired(),Email()])
    password = wtforms.PasswordField('Password',validators=[DataRequired()])
    remember = wtforms.BooleanField("Remember me")
    submit = wtforms.SubmitField('Login!')

class contactForm(FlaskForm):
    name = wtforms.StringField(label='Name', validators=[DataRequired()])
    email = wtforms.StringField(label='Email', validators=[
      DataRequired(), Email(granular_message=True)])
    message= wtforms.StringField(label='Message', validators=[
      DataRequired()])
    submit = wtforms.SubmitField(label="Log In")