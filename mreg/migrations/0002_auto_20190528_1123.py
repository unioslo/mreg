# Generated by Django 2.2.1 on 2019-05-28 09:23

from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):

    dependencies = [
        ('mreg', '0001_initial'),
    ]

    operations = [
        migrations.AlterModelOptions(
            name='srv',
            options={'ordering': ('name', 'priority', 'weight', 'port', 'host')},
        ),
        migrations.AddField(
            model_name='srv',
            name='host',
            field=models.ForeignKey(db_column='host', default=1, on_delete=django.db.models.deletion.CASCADE, related_name='srvs', to='mreg.Host'),
            preserve_default=False,
        ),
        migrations.AlterUniqueTogether(
            name='srv',
            unique_together={('name', 'priority', 'weight', 'port', 'host')},
        ),
        migrations.RemoveField(
            model_name='srv',
            name='target',
        ),
    ]
