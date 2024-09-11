
from flask_login import LoginManager, login_user, login_required, logout_user
from flask import render_template, url_for, redirect, request, Blueprint, flash, session
from flask_mail import Message
from app import bcrypt, mail, login_manager, db
import random
import string
import time
from datetime import datetime, timedelta
from .models.user import Users
from .views.forms import LoginForm, OTPForm, RegisterForm

main_routes = Blueprint('main', __name__)


@login_manager.user_loader
def load_user(user_id):
    return Users.query.get(user_id)

@main_routes.route("/")
def welcome():
    session["Login message"] = None
    session["Register message"] = None
    session["Verification message"] = None
    return redirect(url_for("main.login_switch"))

@main_routes.route("/home")
@login_required
def home():
    return render_template("home.html")

@main_routes.route("/login", methods=['GET','POST'])
def login():
    form = LoginForm()

    message = None
    try:
        if session["Login message"]:
            message = session.get("Login message")
    except:
        pass


    if form.validate_on_submit():
        email = form.email.data
        password = form.password.data

        user = Users.query.filter_by(email=email).first()

        if user and bcrypt.check_password_hash(user.password, password):
            if user.verified:
                session["Login message"] = None
                login_user(user)
                return redirect(url_for('main.home'))
            else:
                session["Login message"] = 'Please verify your email first.'
                return redirect(url_for('main.login'))
        else:
            session["Login message"] = 'User Not Found. Please Register!'
            return redirect(url_for("main.login"))

    return render_template('login.html', form=form, messages=message)

def get_otp():
    otp = ''.join(random.choices(string.digits, k=6))
    timestamp = datetime.now()  # Current time
    return otp, timestamp

def send_otp_email(email, otp):
    msg = Message('Your OTP Code', sender='noreply@femo.com', recipients=[email])

    msg.body = f'Your OTP code is {otp} (Valid for only 5 minutes).\nIf you did not attempt to Register please click the following link:\n{url_for('main.unregister', email=email, _external=True)}'

    mail.send(msg)

@main_routes.route("/unregister/<email>")
def unregister(email):
    user = Users.query.filter_by(email=email).first()
    if user:
        db.session.delete(user)
        db.session.commit()
        session["Login message"] = "Account Deleted"
    return redirect(url_for("main.login"))


@main_routes.route("/register", methods=['GET', 'POST']) 
def register():
    form = RegisterForm()

    if form.validate_on_submit(): 
        email = form.email.data
        password = form.password.data
        hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')

        if Users.query.filter_by(email=email).first():
            session["Login message"] = 'Email address already registered. Please use a different one or log in.'
            return redirect(url_for('main.login')) 
        
        otp, create_time = get_otp()
        send_otp_email(email, otp)

        user = Users(email=email, password=hashed_password, otp=otp, create_time=create_time)
        db.session.add(user)
        db.session.commit()

        session["Verification message"] = 'A verification email has been sent. Please check your inbox.'
        return redirect(url_for('main.verify', email=email))
    return render_template('register.html', form=form, messages=None)

@main_routes.route("/verify/<email>", methods=['GET', 'POST'])
def verify(email):
    form = OTPForm(email=email)

    message = None
    try:
        if session["Verification message"]:
            message = session.get("Verification message")
    except:
        pass


    if form.validate_on_submit():
        new_otp = form.otp.data
        user = Users.query.filter_by(email=email).first()
        now = datetime.now()
        if (now - user.create_time) >= timedelta(minutes=5):
            session["Login message"] = "Your OTP has been Expired"
            session["Verification message"] = None
            return redirect(url_for("main.login"))

        if new_otp == user.otp:
            user.verified = True
            db.session.commit()
            session["Login message"] = "Verification Successful"
            session["Verification message"] = None
            return redirect(url_for("main.login"))
        else:
            session["verification message"] = "Incorrect OTP"
            return redirect(url_for('main.verify', email=email))
    return render_template("verify.html", email=email, form=form, messages=message)

@main_routes.route('/logout')
def logout():
    logout_user()
    session["Login message"] = None
    return redirect(url_for("main.login"))

@main_routes.route("/register_switch")
def register_switch():
    session["Register message"] = None
    return redirect(url_for("main.register"))


@main_routes.route("/login_switch")
def login_switch():
    session["Login message"] = None
    return redirect(url_for("main.login"))