# Generated by Django 4.2.17 on 2025-04-12 12:32

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('core', '0006_devicevideo_video_url'),
    ]

    operations = [
        migrations.AlterField(
            model_name='devicevideo',
            name='video_url',
            field=models.URLField(blank=True, max_length=1000, null=True),
        ),
    ]
