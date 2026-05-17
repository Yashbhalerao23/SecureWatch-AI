"""Kafka consumer for security log analysis and alert production."""

import json
import logging
from django.conf import settings

try:
    from kafka import KafkaConsumer
except ImportError:
    KafkaConsumer = None

from apps.ai_engine.services import AIServiceEnhanced
from apps.alerts.models import Alert
from apps.logs.models import Log
from apps.logs.kafka import KafkaLogProducer

logger = logging.getLogger(__name__)


class AlertKafkaConsumer:
    """Consume security logs from Kafka and generate alerts."""

    def __init__(self):
        self.bootstrap_servers = settings.KAFKA_BOOTSTRAP_SERVERS.split(',')
        self.topic = settings.KAFKA_TOPIC_SECURITY_LOGS
        self.alert_topic = settings.KAFKA_TOPIC_ALERTS
        self.enabled = KafkaConsumer is not None and bool(self.bootstrap_servers)
        self.consumer = None
        self.producer = KafkaLogProducer()
        self.analysis_service = AIServiceEnhanced()

        if self.enabled:
            try:
                self.consumer = KafkaConsumer(
                    self.topic,
                    bootstrap_servers=self.bootstrap_servers,
                    auto_offset_reset='latest',
                    enable_auto_commit=True,
                    value_deserializer=lambda v: json.loads(v.decode('utf-8')),
                    consumer_timeout_ms=1000,
                )
                logger.info('Kafka consumer subscribed to %s', self.topic)
            except Exception as exc:
                logger.warning('Kafka consumer unavailable: %s', exc)
                self.enabled = False

    def consume(self):
        if not self.enabled:
            logger.warning('Kafka consumer disabled: no bootstrap servers or library available')
            return

        for message in self.consumer:
            try:
                self._process_message(message.value)
            except Exception as exc:
                logger.error('Error processing Kafka message: %s', exc)

    def _process_message(self, event_data):
        if not isinstance(event_data, dict):
            logger.warning('Skipping non-dict Kafka event: %s', type(event_data))
            return

        result = self.analysis_service.analyze_log(event_data)
        if result.get('threat_detected'):
            alert = self._create_alert_from_result(event_data, result)
            if alert:
                self.producer.send_alert({
                    'alert_id': alert.id,
                    'title': alert.title,
                    'severity': alert.severity,
                    'threat_type': alert.threat_type,
                    'created_at': alert.created_at.isoformat(),
                })

    def _create_alert_from_result(self, log_data, analysis_result):
        try:
            log = None
            if log_data.get('id'):
                log = Log.objects.filter(id=log_data.get('id')).first()

            alert = Alert.objects.create(
                title=analysis_result['title'],
                description=analysis_result['description'],
                severity=analysis_result['severity'],
                threat_type=analysis_result['threat_type'],
                ip_address=log.ip_address if log else log_data.get('ip_address'),
                source_log=log,
                recommendation=analysis_result.get('recommendations', ''),
            )
            return alert
        except Exception as exc:
            logger.error('Failed to create alert from Kafka analysis: %s', exc)
            return None
