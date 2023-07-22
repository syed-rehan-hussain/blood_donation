# Generated by Django 4.2.3 on 2023-07-22 04:18

from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):

    dependencies = [
        ('api', '0003_rename_address_user_address'),
    ]

    operations = [
        migrations.CreateModel(
            name='UniversityName',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('is_deleted', models.BooleanField(default=False)),
                ('created_at', models.DateTimeField(auto_now_add=True)),
                ('updated_at', models.DateTimeField(auto_now=True)),
                ('name', models.CharField(blank=True, max_length=150)),
            ],
            options={
                'verbose_name': 'UniversityName',
                'verbose_name_plural': 'UniversityNames',
                'db_table': 'UniversityName',
            },
        ),
        migrations.AlterField(
            model_name='user',
            name='no_of_donations',
            field=models.IntegerField(default=0),
        ),
        migrations.AlterField(
            model_name='user',
            name='university_name',
            field=models.ForeignKey(null=True, on_delete=django.db.models.deletion.CASCADE, related_name='university', to='api.universityname'),
        ),
    ]