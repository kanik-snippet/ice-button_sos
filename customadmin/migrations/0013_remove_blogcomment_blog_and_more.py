# Generated by Django 4.2.17 on 2025-01-13 10:54

from django.db import migrations


class Migration(migrations.Migration):

    dependencies = [
        ('customadmin', '0012_alter_blogpost_category'),
    ]

    operations = [
        migrations.RemoveField(
            model_name='blogcomment',
            name='blog',
        ),
        migrations.RemoveField(
            model_name='blogpost',
            name='bulleted_points',
        ),
        migrations.RemoveField(
            model_name='blogpost',
            name='created_by',
        ),
        migrations.RemoveField(
            model_name='blogpost',
            name='extra_images',
        ),
        migrations.RemoveField(
            model_name='blogpost',
            name='quote_author',
        ),
        migrations.RemoveField(
            model_name='blogpost',
            name='tags',
        ),
        migrations.DeleteModel(
            name='FollowUs',
        ),
        migrations.RemoveField(
            model_name='profile',
            name='user',
        ),
        migrations.DeleteModel(
            name='BlogComment',
        ),
        migrations.DeleteModel(
            name='BlogImage',
        ),
        migrations.DeleteModel(
            name='BlogPost',
        ),
        migrations.DeleteModel(
            name='BulletedPoint',
        ),
        migrations.DeleteModel(
            name='Profile',
        ),
        migrations.DeleteModel(
            name='Tag',
        ),
    ]
