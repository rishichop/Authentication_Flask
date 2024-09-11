from flask_login import UserMixin
from app.utils import db

class Users(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(150), unique=True, nullable=False)
    password = db.Column(db.String(150), nullable=False)
    verified = db.Column(db.Boolean, default=False)
    otp = db.Column(db.String(6), nullable=False)

    def __repr__(self):
        return f"User('{self.username}', '{self.email}')"