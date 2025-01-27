


from flask import Flask, render_template
from flask_wtf.csrf import CSRFProtect
from flask_cors import CORS
from flask_migrate import Migrate
import stripe
import paypalrestsdk
from .extensions import db, login_manager, bcrypt
from .routes import bp as main_bp
from flask_login import LoginManager
from .models import User 

def create_app():
    app = Flask(__name__)

    # Load configurations from config file
    app.config.from_object('config.Config')
    
    # Initialize extensions
    db.init_app(app)
    bcrypt.init_app(app)
    CSRFProtect(app)
    CORS(app)
    Migrate(app, db)
    
    # Initialize Flask-Login
    login_manager = LoginManager()
    login_manager.init_app(app)

    # Ensure the user is redirected to login if they aren't authenticated
    login_manager.login_view = 'auth.login'  # You can change this to your login route

    # Load the user from the database by their user ID
    @login_manager.user_loader
    def load_user(user_id):
        return User.query.get(int(user_id))
    
    # Initialize Stripe with the configuration
    stripe.api_key = app.config['STRIPE_LIVE_SECRET_KEY']

    # Initialize PayPal SDK with configuration
    paypalrestsdk.configure({
        'mode': 'sandbox',  # Change to 'live' for production
        'client_id': 'AdZ38dWwRg-vOQxAjv_ZAXDRp2K6xhm2w55BwnBVW8wH9jHKZKC3BYosJqqOZ1m0cs4z9U5yHc-IxefZ',
        'client_secret': 'EH3ywSuqZTBoUQP9HEEOTGH7UfjPR2eGs3eVWcl1qeb3bw1q_6Cs1RDPyd-Kfl4pB0gdswzR3iFFL2UD'
    })

    # Register blueprints
    app.register_blueprint(main_bp)

    with app.app_context():
        db.create_all()  # Create all tables

    # Error handlers
    register_error_handlers(app)

    return app


def register_error_handlers(app):
    @app.errorhandler(404)
    def not_found_error(error):
        return render_template('404.html'), 404

    @app.errorhandler(500)
    def internal_error(error):
            db.session.rollback()  # Rollback session to prevent issues on next DB call
            return render_template('500.html'), 500