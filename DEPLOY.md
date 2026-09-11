# Deploying `carbon-foortprint`

Flask + SQLAlchemy carbon-footprint calculator with user accounts, a dashboard,
offset "projects", and Stripe / PayPal payment flows.

(The repo name is misspelled — "foortprint". The subdomain is `carbon`.)

| Fact | Value |
|---|---|
| WSGI entrypoint | `deploy_wsgi:app` (calls `create_app()`, adds `/healthz`) |
| Listens on | `5761` inside the container |
| Suggested hostname | `carbon.harolditdata.uk` |
| Persistent state | SQLite at `/app/instance/site.db`, or Postgres via `DATABASE_URL` |
| Status | **blocked** — see section 1 |

---

## 1. STOP — leaked payment credentials

Four files carry hardcoded payment secrets, in a repository that is public:

| File | What is in it |
|---|---|
| `config.py` | `STRIPE_LIVE_SECRET_KEY = 'sk_live_…'`, three more `pk_live_…` values, `PAYPAL_CLIENT_ID`, `PAYPAL_CLIENT_SECRET` |
| `app/__init__.py` | the same PayPal client id and secret, passed to `paypalrestsdk.configure()` |
| `app/extensions.py` | the same pair again, in `get_paypal_config()` |
| `app/paypal_client.py` | the same pair again, as module-level `username` / `password` "example usage" |

Required before this app is reachable from the internet:

1. **Revoke and roll the Stripe secret key** in the Stripe dashboard. A key with
   an `sk_live_` prefix in a public git history must be treated as compromised
   whether or not it is currently valid.
2. **Rotate the PayPal app credentials.**
3. Replace all four sites with `os.environ[...]` and purge the values from git
   history (`git filter-repo` / BFG). Rotating alone is not enough — the old
   values stay in every clone.

`deploy_wsgi.py` (added by this pass) already routes the *runtime* values
through environment variables, so once you have new keys the app can use them
without editing source. That is a mitigation, not the fix: the literals are
still in the repo.

Also note `app/routes.py:211`:

```python
stripe.api_key = current_app.config['STRIPE_TEST_PUBLIC_KEY']
```

A *publishable* key cannot authenticate `PaymentIntent.create`. The payment path
has almost certainly never worked. `deploy_wsgi.py` papers over it by putting the
secret key in that config slot too, but the line should be corrected.

## 2. Environment variables

Every one of these is read at runtime from the code paths named.

| Variable | Required | Default | Read by | Notes |
|---|---|---|---|---|
| `SECRET_KEY` | **Yes** | `'<set SECRET_KEY in .env - value intentionally not documented>'` (hardcoded fallback in `config.py`) | `config.py` (`os.getenv`) | Signs sessions and Flask-WTF CSRF tokens. The fallback is public; rotate. `python -c "import secrets; print(secrets.token_hex(32))"` |
| `DATABASE_URL` | No, but recommended | `sqlite:///site.db` → `/app/instance/site.db` | `config.py` (`os.getenv`) | Any SQLAlchemy URL. For Postgres you must also add a driver (`psycopg2-binary`) to `requirements-deploy.txt` — it is not there, because the default is SQLite. |
| `STRIPE_SECRET_KEY` | Only if payments are used | hardcoded `sk_live_…` | `deploy_wsgi.py` → `stripe.api_key`, `STRIPE_LIVE_SECRET_KEY`, `STRIPE_TEST_PUBLIC_KEY` | Use a **test** key (`sk_test_…`) until you actually want to take money. |
| `STRIPE_PUBLISHABLE_KEY` | Only if payments are used | hardcoded `pk_live_…` | `deploy_wsgi.py` → `STRIPE_LIVE_PUBLISHABLE_KEY` | Safe to expose to the browser, unlike the secret key. |
| `PAYPAL_CLIENT_ID` | Only if payments are used | hardcoded | `deploy_wsgi.py` → config + `paypalrestsdk.configure()` | Used by `app/routes.py` via `get_access_token(...)`. |
| `PAYPAL_CLIENT_SECRET` | Only if payments are used | hardcoded | as above | |
| `PAYPAL_MODE` | No | `sandbox` | `deploy_wsgi.py` | `sandbox` or `live`. `app/paypal_client.py` hits `api-m.sandbox.paypal.com` regardless — that URL is hardcoded, so "live" mode is not actually reachable today. |
| `PORT` | No | `5761` | `Procfile` only | The Dockerfile binds 5761 unconditionally. |

`CORS_HEADERS` is set in `config.py` to a constant and `CORS(app)` is called with
no origin restriction — i.e. **all origins are allowed**. Tighten that before
exposing the app: `CORS(app, origins=["https://carbon.harolditdata.uk"])`.

## 3. Build and run

```bash
docker build -t carbon:latest .

docker volume create carbon_instance

docker run -d --name carbon \
  --restart unless-stopped \
  -v carbon_instance:/app/instance \
  -p 127.0.0.1:5761:5761 \
  --env-file /etc/harold/carbon.env \
  --memory 350m --cpus 0.5 \
  carbon:latest
```

`create_app()` runs `db.create_all()` on every start, so the schema appears on
first boot. There is no `migrations/` directory, which means **schema changes
are not migratable** — `create_all()` never alters an existing table. Add
Flask-Migrate properly (`flask db init`) before you put data you care about in
here.

The container is not `--read-only`: SQLite needs to write `site.db`, its `-wal`
and `-shm` companions into `/app/instance`. If you move to Postgres via
`DATABASE_URL`, add `--read-only --tmpfs /tmp` and drop the volume.

## 4. Dependencies

The build uses **`requirements-deploy.txt`**, added by this pass;
`requirements.txt` is untouched. The original is a `pip freeze` from a venv
shared with the stock-market project and pins yfinance, scikit-learn,
statsmodels, plotly, matplotlib, numpy, pandas and scipy — none of which appear
in a single import statement here. Dropping them takes roughly 700 MB off the
image.

## 5. Health check

`GET /healthz` → `{"status": "ok"}`, added by `deploy_wsgi.py`. No existing file
was modified. It performs no database query and no payment API call.

## 6. Cloudflare tunnel

```yaml
  - hostname: carbon.harolditdata.uk
    service: http://localhost:5761
```

Add this rule **after** the credentials are rotated, not before. Full config in
`/home/onyango/Projects/DEPLOYMENT_PLAN.md`.

## 7. Files added by the deployment pass

`Dockerfile`, `.dockerignore`, `Procfile`, `requirements-deploy.txt`,
`deploy_wsgi.py`, `DEPLOY.md`. No existing file was modified.
