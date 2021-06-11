import os
from dotenv import load_dotenv
from flask import Flask, render_template, request, redirect
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import InputRequired, Length, ValidationError
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user

load_dotenv()

app = Flask(__name__)

# app config
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY')
app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv('DATABASE_URI')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)

# init user login
login_manager = LoginManager()
login_manager.init_app(app)

# User model
class User(UserMixin, db.Model):
	id = db.Column(db.Integer, primary_key=True)
	username = db.Column(db.String(30), unique=True, nullable=False)
	password = db.Column(db.String(80), nullable=False)

# Register Form
class RegisterForm(FlaskForm):
	username = StringField('username', validators=[InputRequired(), Length(min=4, max=20, message='A username must be between 4 to 20 characters')])
	password = PasswordField('password', validators=[InputRequired(), Length(min=6, max=80, message='A password must be between 6 to 80 characters')])
	submit = SubmitField('Sign up')

# Login Form
class LoginForm(FlaskForm):
	username = StringField('username', validators=[InputRequired()])
	password = PasswordField('password', validators=[InputRequired()])
	submit = SubmitField('Login')

# load user 
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# register route
@app.route('/register', methods=['GET', 'POST'])
def register():
	form = RegisterForm()

	if form.validate_on_submit():
		new_user = User(username=form.username.data, password=form.password.data)
		try:
			db.session.add(new_user)
			db.session.commit()
			return 'register successfully'
		except:
			return 'Error while add user'
	
	return render_template('register.html', form=form)


@app.route('/login')
def login():
	form = LoginForm()

	return render_template('login.html', form=form)


if __name__ == '__main__':
	app.run(debug=True)


