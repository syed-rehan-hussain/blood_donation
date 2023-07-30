# Generated by Django 4.2.3 on 2023-07-30 12:13

import api.models
from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):

    dependencies = [
        ('api', '0013_donor_university'),
    ]

    operations = [
        migrations.RemoveField(
            model_name='donor',
            name='university',
        ),
        migrations.CreateModel(
            name='Donation',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('is_deleted', models.BooleanField(default=False)),
                ('created_at', models.DateTimeField(auto_now_add=True)),
                ('updated_at', models.DateTimeField(auto_now=True)),
                ('blood_group', models.CharField(blank=True, max_length=15, null=True)),
                ('quantity', models.CharField(blank=True, max_length=25, null=True)),
                ('report', models.FileField(upload_to=api.models.report_path)),
                ('donation_date', models.DateTimeField(blank=True)),
                ('expiry_date', models.DateTimeField(blank=True)),
                ('donor', models.ForeignKey(null=True, on_delete=django.db.models.deletion.CASCADE, related_name='donor', to='api.donor')),
                ('hospital_name', models.ForeignKey(null=True, on_delete=django.db.models.deletion.CASCADE, related_name='hospital', to='api.hospital')),
            ],
            options={
                'verbose_name': 'Donation',
                'verbose_name_plural': 'Donations',
                'db_table': 'Donation',
            },
        ),
    ]