# Generated by Django 2.1 on 2020-09-10 18:21

import datetime
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('account', '0009_auto_20200909_2002'),
    ]

    operations = [
        migrations.AlterField(
            model_name='file',
            name='upload_time',
            field=models.DateTimeField(default=datetime.datetime(2020, 9, 10, 18, 21, 24, 652589)),
        ),
        migrations.AlterField(
            model_name='group',
            name='creat_time',
            field=models.DateTimeField(default=datetime.datetime(2020, 9, 10, 18, 21, 24, 652589)),
        ),
    ]
