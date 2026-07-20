from django.conf import settings
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('connections', '0002_sshsession_env_script'),
        migrations.swappable_dependency(settings.AUTH_USER_MODEL),
    ]

    operations = [
        migrations.CreateModel(
            name='GrantRequest',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('rights_type', models.CharField(choices=[('informix', 'Informix'), ('mysql', 'MySQL'), ('greenplum', 'Greenplum'), ('postgres', 'Postgres')], max_length=20)),
                ('granter_name', models.CharField(max_length=150)),
                ('jira_ticket', models.CharField(max_length=64)),
                ('requested_at', models.DateTimeField(auto_now_add=True)),
                ('portal_user', models.ForeignKey(null=True, on_delete=models.SET_NULL, to=settings.AUTH_USER_MODEL)),
            ],
            options={
                'ordering': ['-requested_at'],
            },
        ),
    ]
