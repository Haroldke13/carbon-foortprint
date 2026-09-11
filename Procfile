# create_app() calls db.create_all() at startup and this repo ships no
# migrations/ directory, so there is no release phase to run.
web: gunicorn --bind 0.0.0.0:${PORT:-5761} --workers 2 --threads 4 --timeout 60 --access-logfile - --error-logfile - deploy_wsgi:app
