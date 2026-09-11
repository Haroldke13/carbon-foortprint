"""Deployment entrypoint for carbon-foortprint.

Additive only — app.py, config.py and app/*.py are untouched. It builds the app
through the existing factory, moves the payment credentials off the hardcoded
literals and onto environment variables, and adds a /healthz probe.

The credential overrides work because every call site reads
`current_app.config[...]` at request time, so replacing the values after
create_app() is enough. They do NOT un-leak the literals that are already
committed to this repository: rotate at the provider. See DEPLOY.md section 1.

Run with:  gunicorn deploy_wsgi:app
"""

import os

import paypalrestsdk
import stripe

from app import create_app  # noqa: E402

app = create_app()


def _env(name):
    value = os.environ.get(name)
    return value if value else None


# --- Stripe -----------------------------------------------------------------
# app/__init__.py sets stripe.api_key from Config.STRIPE_LIVE_SECRET_KEY, and
# app/routes.py re-sets it per request from Config.STRIPE_TEST_PUBLIC_KEY.
# Both of those are hardcoded literals, so override both.
_stripe_secret = _env("STRIPE_SECRET_KEY")
if _stripe_secret:
    stripe.api_key = _stripe_secret
    app.config["STRIPE_LIVE_SECRET_KEY"] = _stripe_secret
    # routes.py assigns stripe.api_key = config['STRIPE_TEST_PUBLIC_KEY'] before
    # creating a PaymentIntent. A publishable key cannot authenticate that call,
    # so the secret key has to live here too until routes.py is corrected.
    app.config["STRIPE_TEST_PUBLIC_KEY"] = _stripe_secret

_stripe_publishable = _env("STRIPE_PUBLISHABLE_KEY")
if _stripe_publishable:
    app.config["STRIPE_LIVE_PUBLISHABLE_KEY"] = _stripe_publishable

# --- PayPal -----------------------------------------------------------------
_pp_id = _env("PAYPAL_CLIENT_ID")
_pp_secret = _env("PAYPAL_CLIENT_SECRET")
if _pp_id and _pp_secret:
    app.config["PAYPAL_CLIENT_ID"] = _pp_id
    app.config["PAYPAL_CLIENT_SECRET"] = _pp_secret
    paypalrestsdk.configure(
        {
            "mode": os.environ.get("PAYPAL_MODE", "sandbox"),
            "client_id": _pp_id,
            "client_secret": _pp_secret,
        }
    )

# --- health probe -----------------------------------------------------------
if "healthz" not in app.view_functions:

    @app.route("/healthz")
    def healthz():
        """Liveness probe. No database round trip and no payment API call."""
        return {"status": "ok"}, 200


if __name__ == "__main__":  # pragma: no cover - local smoke test only
    app.run(host="127.0.0.1", port=int(os.environ.get("PORT", 5761)))
