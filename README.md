# carbon-foortprint

A Flask app where a signed-in user records household carbon-emission figures and then pays a levy of
5% of the recorded emissions by card (Stripe) or PayPal.

> **Note on the repository name:** the correct spelling is **carbon-footprint**. The current repo
> name contains a typo (`foortprint`).

Live demo (Render, may be asleep or offline): <https://carbon-foortprint.onrender.com>

## What it actually does

- **Accounts** — register (username, email, password, location, household size, vehicle ownership,
  dietary preference), log in, view and edit profile. Flask-Login + bcrypt.
- **Record a footprint** (`/dashboard`) — a form capturing transport mode, distance, fuel type and
  consumption, electricity usage, water usage, food impact, and **total carbon emissions**.
- **Results** (`/results`) — lists the user's saved records and the total levy.
- **Payments** — Stripe PaymentIntents (`/pay_card`, `/stripe_payment/<id>`) and PayPal orders
  (`/pay_paypal`, `/paypal_return`, `/paypal_cancel`), with a `Payment` table recording amounts and
  payment-intent IDs.
- Custom 404 and 500 error pages.

### Important correction: it is not a calculator

The `carbon_emissions` value is **entered by the user** as a form field
(`CarbonFootprintForm.carbon_emissions`). The app does not derive emissions from the transport,
electricity, water or food inputs — those are stored but never used in any computation. The only
arithmetic is `levy = carbon_emissions * 0.05` (`CarbonFootprint.levy` in `app/models.py`, commented
in the source as "Example calculation"). Adding real emission factors is the obvious next step.

### M-Pesa is not implemented

`PaymentForm` offers an "M-Pesa Kenya" option and `app/routes.py` redirects to
`url_for('main.pay_mpesa', ...)`, **but no `pay_mpesa` route is defined**. Choosing M-Pesa raises a
`werkzeug.routing.BuildError`.

## Tech stack

- Python 3.12, Flask 3.1 (application factory in `app/__init__.py`, blueprint in `app/routes.py`)
- SQLAlchemy + Flask-Migrate/Alembic; database URL from `DATABASE_URL`, otherwise SQLite
- Flask-Login, Flask-Bcrypt, Flask-WTF (CSRF), Flask-Cors
- `stripe` and `paypalrestsdk` (PayPal in **sandbox** mode — see `app/extensions.py`)
- Gunicorn for deployment

`requirements.txt` also pins `yfinance`, `scikit-learn`, `statsmodels`, `matplotlib`, `plotly` and
`pandas`, none of which are imported by this application. They appear to have been copied from
another project and can be dropped.

## Setup

```bash
git clone https://github.com/Haroldke13/carbon-foortprint.git
cd carbon-foortprint
python3 -m venv venv && source venv/bin/activate
pip install -r requirements.txt
```

Initialise the database:

```bash
flask db init
flask db migrate
flask db upgrade
```

Run it:

```bash
flask run          # or: python app.py
```

Then open <http://127.0.0.1:5000>.

### Configuration

`config.py` reads `SECRET_KEY` and `SQLALCHEMY_DATABASE_URI` from the environment, but the Stripe and
PayPal keys are **hardcoded as class attributes** and are not overridable. You must edit `config.py`
(and `app/extensions.py`, which hardcodes the PayPal client ID/secret a second time) to use your own
keys. Moving these to `os.environ` is strongly recommended — see below.

Two of the Stripe constants are also misnamed: `STRIPE_TEST_PUBLIC_KEY` and
`STRIPE_TEST_SECRET_KEY` both hold `pk_live_…` values, and `/pay_card` sets
`stripe.api_key = STRIPE_TEST_PUBLIC_KEY` — a publishable key where a secret key is required, so the
card flow will fail with an authentication error.

## Security

🚨 **`config.py` contains a live Stripe secret key (`sk_live_…`), live publishable keys, and a PayPal
client secret, committed in plaintext to a public repository.** The PayPal secret is duplicated in
`app/extensions.py`, `app/paypal_client.py` and `app/routes.py`. **Revoke and rotate the Stripe and
PayPal credentials immediately**, then purge them from git history and move them to environment
variables.

An earlier version of this README claimed "secure handling of sensitive information using
environment variables". That was not true of the committed code.

There is no `.gitignore`; `app/__pycache__/*.pyc` files are committed.

## Status

**Prototype with a real payments integration attached.** Last commit January 2025. Auth, the record
form and the PayPal sandbox flow are wired up; emission calculation, the Stripe card path and M-Pesa
are not finished.

## Licence

The `LICENSE` file is **GPL-3.0**, not MIT — an earlier version of this README said MIT. Treat
`LICENSE` as authoritative, or replace it if MIT was the intent.
