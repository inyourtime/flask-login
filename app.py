import os
from dotenv import load_dotenv
from flask import Flask, render_template, request, redirect, url_for, flash, session
from flask_sqlalchemy import SQLAlchemy
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import DataRequired, Length, ValidationError, EqualTo
from werkzeug.security import generate_password_hash, check_password_hash

load_dotenv()

app = Flask(__name__)

# app config
app.config["SECRET_KEY"] = os.getenv("SECRET_KEY")
app.config["SQLALCHEMY_DATABASE_URI"] = os.getenv("DATABASE_URI")
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

db = SQLAlchemy(app)


# User model
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(30), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)


# Register Form
class RegisterForm(FlaskForm):
    username = StringField(
        "Create your username",
        validators=[
            DataRequired(),
            Length(
                min=4, max=20, message="A username must be between 4 to 20 characters"
            ),
        ],
    )
    password = PasswordField(
        "Create your password",
        validators=[
            DataRequired(),
            Length(
                min=6, max=20, message="A password must be between 6 to 20 characters"
            ),
        ],
    )
    confirm = PasswordField(
        "Confirm your password",
        validators=[
            DataRequired(),
            EqualTo('password', message='Password is not match')
        ]
    )
    submit = SubmitField("Register Now")

    def validate_username(self, username):
        existing_user_username = User.query.filter_by(username=username.data).first()
        if existing_user_username:
            raise ValidationError("That username already exist, please try again")


# Login Form
class LoginForm(FlaskForm):
    username = StringField("username", validators=[DataRequired()], render_kw={"placeholder": "Username"})
    password = PasswordField("password", validators=[DataRequired()], render_kw={"placeholder": "Password"})
    submit = SubmitField("Login")


# register route
@app.route("/register", methods=["GET", "POST"])
def register():
    form = RegisterForm()

    if form.validate_on_submit():
        password = generate_password_hash(form.password.data)
        # print(len(password))
        new_user = User(username=form.username.data, password=password)
        try:
            db.session.add(new_user)
            db.session.commit()
            return redirect(url_for('login'))
        except:
            return "Error while add user"

    return render_template("register.html", form=form)


@app.route("/login", methods=["GET", "POST"])
def login():
    form = LoginForm()

    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user and check_password_hash(user.password, form.password.data):
            session["user_id"] = user.id
            # flash("login success")
            return redirect(url_for('dashboard'))
        flash('Invalid login, Please try again', "invalid_login")
        return redirect(url_for('login'))
    
    if "user_id" in session:
        return redirect(url_for('dashboard'))
    
    return render_template("login.html", form=form)


@app.route('/dashboard')
def dashboard():
    if "user_id" in session:
        user_id = session["user_id"]
        user = User.query.filter_by(id=user_id).first()
        return render_template('dashboard.html', username=user.username)
    
    return redirect(url_for('login'))

@app.route('/logout')
def logout():
    session.pop("user_id", None)
    flash("Logout Successfully", "logout")
    return redirect(url_for('login'))

if __name__ == "__main__":
    app.run(debug=True)
