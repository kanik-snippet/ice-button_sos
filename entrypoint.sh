#!/bin/bash

# Wait for DB
echo "Waiting for MySQL..."
while ! mysqladmin ping -h"db" -u"kanik-snippet" -p"Snippet@1" --silent; do
    sleep 1
done

echo "MySQL started"

# Migrate & Compile messages
python manage.py migrate
# python manage.py compilemessages

# Run APScheduler (if needed)
python manage.py runapscheduler &

# Create superuser if not exists
if [ "$(python manage.py shell -c 'from django.conf import settings; from django.apps import apps; User = apps.get_model(settings.AUTH_USER_MODEL); print(User.objects.filter(username='"'"'admin'"'"').exists())')" = "False" ]; then
    echo "Creating superuser..."
    python manage.py shell -c 'from django.conf import settings; from django.contrib.auth import get_user_model; User = get_user_model(); User.objects.create_superuser("admin", "yash.garg@mobiloitte.com", "Admin@123", is_verified=True, is_active=True, is_staff=True, is_superuser=True)'
fi

# Start app
exec "$@"
