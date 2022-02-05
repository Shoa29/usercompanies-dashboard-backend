from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from flask_login import LoginManager

# Instantiate the Flask application with configurations
app = Flask(__name__)
app.config['SECURITY_PASSWORD_SALT'] = 'none'
app.config['FLASK_ADMIN_SWATCH'] = 'shoadevs'
app.config['SECRET_KEY'] = 'shoadevs'
app.config['SQLALCHEMY_DATABASE_URI'] = 'postgresql://postgres:dreams@localhost:5432/reveliolabs_dashboard'
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
app.config['USER_APP_NAME '] = "Revelio Labs Dashboard"
app.config['USER_ENABLE_EMAIL'] = False
app.config['USER_ENABLE_USERNAME'] = True
app.config['USER_EMAIL_SENDER_EMAIL'] = False



# Instantiate the database
db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
login_manager = LoginManager(app)

from . import routes