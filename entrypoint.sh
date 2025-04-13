#!/bin/sh

# Run database migrations
echo "Running database migrations..."
python manage.py makemigrations
python manage.py migrate

# Check if the superuser already exists
if [ "$(python manage.py shell -c 'from django.conf import settings; from django.apps import apps; User = apps.get_model(settings.AUTH_USER_MODEL); print(User.objects.filter(username="admin").exists())')" = "False" ]; then
    echo "Creating superuser..."
    python manage.py shell -c 'from django.contrib.auth import get_user_model; User = get_user_model(); User.objects.create_superuser("admin", "yash.garg@mobiloitte.com", "Admin@123")'
fi

# Run APScheduler in the background
echo "Starting APScheduler..."
python manage.py runapscheduler

# Start the Django server
echo "Starting Django development server..."
python manage.py runserver 0.0.0.0:8058
