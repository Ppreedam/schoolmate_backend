# Generated by Django 5.1.4 on 2025-07-02 03:01

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('schoolmate_app', '0002_remove_section_class_id'),
    ]

    operations = [
        migrations.AddField(
            model_name='section',
            name='school_id',
            field=models.CharField(default='', max_length=100),
        ),
    ]
