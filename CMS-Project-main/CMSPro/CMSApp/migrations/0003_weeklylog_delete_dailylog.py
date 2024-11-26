# Generated by Django 5.1.3 on 2024-11-20 12:17

import django.db.models.deletion
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('CMSApp', '0002_user_address_user_phone_number'),
    ]

    operations = [
        migrations.CreateModel(
            name='WeeklyLog',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('date', models.DateField(auto_now_add=True)),
                ('units_completed', models.DecimalField(decimal_places=2, max_digits=5)),
                ('notes', models.TextField(blank=True, null=True)),
                ('crew', models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.CASCADE, to='CMSApp.crew')),
                ('job', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to='CMSApp.job')),
            ],
        ),
        migrations.DeleteModel(
            name='DailyLog',
        ),
    ]
