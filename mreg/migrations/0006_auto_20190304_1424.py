# Generated by Django 2.1.7 on 2019-03-04 13:24

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('mreg', '0005_auto_20190226_0846'),
    ]

    operations = [
        migrations.AddField(
            model_name='host',
            name='updated_at',
            field=models.DateTimeField(auto_now=True),
        ),
        migrations.AddField(
            model_name='ipaddress',
            name='updated_at',
            field=models.DateTimeField(auto_now=True),
        ),
    ]
