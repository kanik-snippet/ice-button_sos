from django.db.models.signals import post_migrate
from django.dispatch import receiver
from datetime import timedelta
from .models import Plan

@receiver(post_migrate)
def create_default_plan(sender, **kwargs):
    """
    Automatically create a default 'standard' plan after migrations.
    """
    if sender.name == 'customadmin':  # Replace with your actual app name
        Plan.objects.get_or_create(
            name='Standard',
            defaults={
                'max_emails': 5,
                'max_phone_numbers': 5,
                'max_button': 1,
                'subscription_type': Plan.MONTHLY,
                'stream': True,
                'stream_length': timedelta(minutes=1, seconds=30),
                'cost': 0.00,
            },
        )
