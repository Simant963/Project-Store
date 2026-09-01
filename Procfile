release: flask --app app db upgrade
web: gunicorn --workers 3 --bind 0.0.0.0:$PORT app:app
