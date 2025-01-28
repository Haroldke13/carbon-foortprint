import os
from flask import current_app
import paypalrestsdk
from flask_wtf.csrf import CSRFProtect

csrf = CSRFProtect()


def require_env(name):
    """Return environment variable `name`, or fail loudly if it is missing.

    Credentials are never hardcoded in this repository. An unset variable is a
    deployment error, so we raise instead of silently falling back to a default
    that might end up committed again.
    """
    value = os.environ.get(name)
    if not value:
        raise RuntimeError(
            "Required environment variable {0} is not set. "
            "Copy .env.example to .env and provide a value for {0}.".format(name)
        )
    return value


class Config:
    SECRET_KEY = require_env('SECRET_KEY')
    SQLALCHEMY_DATABASE_URI = os.getenv('DATABASE_URL', 'sqlite:///site.db')
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    CORS_HEADERS = 'Content-Type'

    # Stripe. Config key names are unchanged so existing call sites keep working.
    STRIPE_TEST_PUBLIC_KEY = require_env('STRIPE_TEST_PUBLIC_KEY')
    STRIPE_TEST_SECRET_KEY = require_env('STRIPE_TEST_SECRET_KEY')
    STRIPE_LIVE_SECRET_KEY = require_env('STRIPE_LIVE_SECRET_KEY')
    STRIPE_LIVE_PUBLISHABLE_KEY = require_env('STRIPE_LIVE_PUBLISHABLE_KEY')

    # PayPal
    PAYPAL_CLIENT_ID = require_env('PAYPAL_CLIENT_ID')
    PAYPAL_CLIENT_SECRET = require_env('PAYPAL_CLIENT_SECRET')
    PAYPAL_MODE = os.getenv('PAYPAL_MODE', 'sandbox')
