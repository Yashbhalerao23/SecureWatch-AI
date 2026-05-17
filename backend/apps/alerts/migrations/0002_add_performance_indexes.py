# Generated migration for performance indexes

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('alerts', '0001_initial'),
    ]

    operations = [
        migrations.AddIndex(
            model_name='alert',
            index=models.Index(fields=['-created_at', 'severity'], name='alerts_alert_created_sev_idx'),
        ),
        migrations.AddIndex(
            model_name='alert',
            index=models.Index(fields=['status', '-created_at'], name='alerts_alert_status_created_idx'),
        ),
        migrations.AddIndex(
            model_name='alert',
            index=models.Index(fields=['severity', 'status'], name='alerts_alert_sev_status_idx'),
        ),
    ]
