"""Kafka producer utilities for log ingestion and audit events."""

import json
import logging

from django.conf import settings

logger = logging.getLogger(__name__)

try:
    from kafka import KafkaProducer
except ImportError:
    KafkaProducer = None


class KafkaLogProducer:
    """Produce ingestion, alert, and audit events to Kafka."""

    def __init__(self):
        self.bootstrap_servers = settings.KAFKA_BOOTSTRAP_SERVERS.split(',')
        self.enabled = KafkaProducer is not None and bool(self.bootstrap_servers)
        self.producer = None

        if self.enabled:
            try:
                self.producer = KafkaProducer(
                    bootstrap_servers=self.bootstrap_servers,
                    value_serializer=lambda v: json.dumps(v).encode('utf-8'),
                    retries=3,
                    linger_ms=5,
                )
                logger.info('Kafka producer initialized for %s', self.bootstrap_servers)
            except Exception as exc:
                logger.warning('Kafka producer unavailable: %s', exc)
                self.enabled = False

    def _send(self, topic, payload):
        if not self.enabled:
            logger.debug('Kafka producer disabled, skipping send to %s', topic)
            return False

        try:
            self.producer.send(topic, payload)
            self.producer.flush(timeout=10)
            return True
        except Exception as exc:
            logger.error('Failed to send message to Kafka topic %s: %s', topic, exc)
            return False

    def send_security_log(self, log_data):
        return self._send(settings.KAFKA_TOPIC_SECURITY_LOGS, log_data)

    def send_alert(self, alert_data):
        return self._send(settings.KAFKA_TOPIC_ALERTS, alert_data)

    def send_audit_event(self, audit_data):
        return self._send(settings.KAFKA_TOPIC_AUDIT_EVENTS, audit_data)
