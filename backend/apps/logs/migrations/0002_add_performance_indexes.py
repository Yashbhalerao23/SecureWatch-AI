# Generated migration for performance indexes

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('logs', '0001_initial'),
    ]

    operations = [
        migrations.AddIndex(
            model_name='log',
            index=models.Index(fields=['-timestamp', 'level'], name='logs_log_ts_level_idx'),
        ),
        migrations.AddIndex(
            model_name='log',
            index=models.Index(fields=['-timestamp', 'service'], name='logs_log_ts_service_idx'),
        ),
        migrations.AddIndex(
            model_name='log',
            index=models.Index(fields=['ip_address', '-timestamp'], name='logs_log_ip_ts_idx'),
        ),
        migrations.AddIndex(
            model_name='log',
            index=models.Index(fields=['ai_threat_detected', '-timestamp'], name='logs_log_threat_ts_idx'),
        ),
    ]
