# Generated by Django 4.2.17 on 2025-04-12 12:04

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('core', '0005_delete_tenant'),
    ]

    operations = [
        migrations.AddField(
            model_name='devicevideo',
            name='video_url',
            field=models.URLField(blank=True, null=True),
        ),
    ]
