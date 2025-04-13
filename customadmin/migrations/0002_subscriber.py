# Generated by Django 4.2.17 on 2024-12-23 08:59

import django.core.validators
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('customadmin', '0001_initial'),
    ]

    operations = [
        migrations.CreateModel(
            name='Subscriber',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('name', models.CharField(max_length=255)),
                ('email', models.EmailField(max_length=254, unique=True, validators=[django.core.validators.EmailValidator()])),
                ('status', models.CharField(choices=[('subscribed', 'Subscribed'), ('unsubscribed', 'Unsubscribed'), ('pending', 'Pending')], default='subscribed', max_length=50)),
                ('subscribed_at', models.DateTimeField(auto_now_add=True)),
                ('unsubscribed_at', models.DateTimeField(blank=True, null=True)),
            ],
            options={
                'indexes': [models.Index(fields=['email'], name='customadmin_email_a8f311_idx'), models.Index(fields=['status'], name='customadmin_status_0ce077_idx')],
            },
        ),
    ]
