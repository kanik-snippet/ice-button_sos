# Generated by Django 4.2.17 on 2025-01-04 06:55

from django.db import migrations


class Migration(migrations.Migration):

    dependencies = [
        ('customadmin', '0004_emailcontent_alter_subscriber_name'),
    ]

    operations = [
        migrations.DeleteModel(
            name='emailContent',
        ),
    ]
