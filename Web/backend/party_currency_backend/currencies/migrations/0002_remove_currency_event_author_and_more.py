# Generated by Django 5.1.7 on 2025-03-31 21:43

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('currencies', '0001_initial'),
    ]

    operations = [
        migrations.RemoveField(
            model_name='currency',
            name='event_author',
        ),
        migrations.AddField(
            model_name='currency',
            name='currency_author',
            field=models.CharField(default='user', max_length=255),
        ),
    ]
