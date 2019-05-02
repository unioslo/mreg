# Generated by Django 2.2 on 2019-04-11 12:27

from django.db import migrations
import netfields.fields


class Migration(migrations.Migration):

    dependencies = [
        ('mreg', '0003_auto_20190411_1052'),
    ]

    operations = [
        migrations.AlterModelOptions(
            name='network',
            options={'ordering': ('network',)},
        ),
        migrations.RemoveField(
            model_name='network',
            name='range',
        ),
        migrations.RemoveField(
            model_name='reversezone',
            name='range',
        ),
        migrations.AddField(
            model_name='network',
            name='network',
            field=netfields.fields.CidrAddressField(default=1, max_length=43, unique=True),
            preserve_default=False,
        ),
        migrations.AddField(
            model_name='reversezone',
            name='network',
            field=netfields.fields.CidrAddressField(blank=True, default=1, max_length=43, unique=True),
            preserve_default=False,
        ),
    ]