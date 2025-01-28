# app/extensions.py
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager
from flask_bcrypt import Bcrypt
import paypalrestsdk
from flask import current_app



db = SQLAlchemy()
login_manager = LoginManager()
bcrypt = Bcrypt()




def get_paypal_config():
    """Return PayPal configuration from current app context."""
    return {
        'mode': current_app.config['PAYPAL_MODE'],
        'client_id': current_app.config['PAYPAL_CLIENT_ID'],
        'client_secret': current_app.config['PAYPAL_CLIENT_SECRET'],
    }