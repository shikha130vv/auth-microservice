from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt


db = SQLAlchemy()
bcrypt = Bcrypt()

def create_app(config_file):
    app = Flask(__name__)
    app.config.from_pyfile(config_file)
    register_extensions(app)
    register_blueprints(app)
    return app, db


def register_extensions(app):
    db.init_app(app)
    bcrypt.init_app(app)

def register_blueprints(app):
    from project.auth import auth_blueprint
    app.register_blueprint(auth_blueprint)
