from .config import Config
from flask import Flask
from .utils import db, mail, bcrypt, login_manager, migrate
from .routes import main_routes


def create_app():
    app = Flask(__name__)
    app.config.from_object(Config)

    db.init_app(app)
    bcrypt.init_app(app)
    mail.init_app(app)
    login_manager.init_app(app)

    app.register_blueprint(main_routes)

    with app.app_context():
        db.create_all()

    return app