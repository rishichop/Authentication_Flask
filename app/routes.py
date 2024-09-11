
from flask_login import LoginManager, login_user, login_required, logout_user
from flask import render_template, url_for, redirect, request, Blueprint, flash
from flask_mail import Message
from app import bcrypt, mail, login_manager, db
import random
import string
from .models.user import Users
from .views.forms import LoginForm, OTPForm

main_routes = Blueprint('main', __name__)

@login_manager.user_loader
def load_user(user_id):
    return Users.query.get(user_id)

@main_routes.route("/")
def welcome():
    return "Hello World!"

@main_routes.route("/home")
@login_required
def home():
    return render_template("home.html")

@main_routes.route("/login", methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')

        user = Users.query.filter_by(email=email).first()

        if user and bcrypt.check_password_hash(user.password, password):
            if user.verified:
                login_user(user)
                return redirect(url_for('main.home'))
            else:
                flash('Please verify your email first.', 'warning')
                return redirect(url_for('main.login'))
        else:
            flash('Login unsuccessful. Check email and password.', 'danger')
    return render_template('login.html', form=form)

def get_otp():
    otp = ''.join(random.choices(string.digits, k=6))
    return otp

def send_otp_email(email, otp):
    msg = Message('Your OTP Code', sender='noreply@femo.com', recipients=[email])
    msg.body = f'Your OTP code is {otp}.'
    mail.send(msg)

@main_routes.route("/register", methods=['GET', 'POST']) 
def register(): 
    if request.method == 'POST': 
        email = request.form.get('email') 
        password = request.form.get('password')
        hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')

        if Users.query.filter_by(email=email).first():
            flash('Email address already registered. Please use a different one or log in.', 'danger')
            return redirect(url_for('main.login')) 
        
        otp = get_otp()
        send_otp_email(email, otp)

        user = Users(email=email, password=hashed_password, otp=otp)
        db.session.add(user)
        db.session.commit()

        # token = user.get_reset_token()
        # send_verification_email(user, token)

        flash('A verification email has been sent. Please check your inbox.', 'info')
        return redirect(url_for('main.verify', email=email))
    return render_template('register.html')

@main_routes.route("/verify/<email>", methods=['GET', 'POST'])
def verify(email):
    if request.method == "POST":
        new_otp = request.form.get('otp')
        user = Users.query.filter_by(email=email).first()

        if new_otp == user.otp:
            user.verified = True
            db.session.commit()
            flash("Verification Successful", "info")
            return redirect(url_for("main.login"))
        else:
            flash("Please Try Again", 'warning')
    return render_template("verify.html", email=email)

@main_routes.route('/logout')
def logout():
    logout_user()
    return redirect(url_for("main.login"))