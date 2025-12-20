# Generated migration for adding multi-contact support and removing deprecated contact field

from django.db import migrations, models
import django.db.models.deletion


def migrate_contacts_forward(apps, schema_editor):
    """Migrate existing contact field data to HostContact model."""
    Host = apps.get_model('mreg', 'Host')
    HostContact = apps.get_model('mreg', 'HostContact')
    
    # Get all hosts with non-empty contact fields
    hosts_with_contacts = Host.objects.exclude(contact='').exclude(contact__isnull=True)
    
    # Create a mapping of email -> HostContact to avoid duplicates
    email_to_contact = {}
    
    for host in hosts_with_contacts:
        if host.contact:
            # Get or create HostContact for this email
            if host.contact not in email_to_contact:
                contact, _ = HostContact.objects.get_or_create(email=host.contact)
                email_to_contact[host.contact] = contact
            else:
                contact = email_to_contact[host.contact]
            
            # Add the contact to this host
            host.contacts.add(contact)


def migrate_contacts_backward(apps, schema_editor):
    """Migrate HostContact data back to contact field (best effort)."""
    Host = apps.get_model('mreg', 'Host')
    
    for host in Host.objects.all():
        contacts = host.contacts.all()
        if contacts.exists():
            # Take the first contact when reverting
            host.contact = contacts.first().email
            host.save()


class Migration(migrations.Migration):

    dependencies = [
        ('mreg', '0015_network_max_communities_and_more'),
    ]

    operations = [
        # Create HostContact model
        migrations.CreateModel(
            name='HostContact',
            fields=[
                ('id', models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('created_at', models.DateTimeField(auto_now_add=True)),
                ('updated_at', models.DateTimeField(auto_now=True)),
                ('email', models.EmailField(max_length=254, unique=True)),
            ],
            options={
                'db_table': 'host_contact',
            },
        ),
        # Add ManyToMany relationship
        migrations.AddField(
            model_name='host',
            name='contacts',
            field=models.ManyToManyField(
                blank=True,
                help_text='Contact email addresses for this host.',
                related_name='hosts',
                to='mreg.HostContact'
            ),
        ),
        # Migrate existing data from old contact field to new contacts
        migrations.RunPython(
            migrate_contacts_forward,
            migrate_contacts_backward,
        ),
        # Remove the deprecated contact field
        migrations.RemoveField(
            model_name='host',
            name='contact',
        ),
    ]
