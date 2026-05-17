"""
Windows Event Log Monitor for SecureWatch AI
"""

import win32evtlog
import win32evtlogutil
import win32security
import win32con
from datetime import datetime
import threading
import time
from django.utils import timezone
import os, django
import sys
base_dir = os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
sys.path.insert(0, base_dir)
os.environ['DJANGO_SETTINGS_MODULE'] = 'backend.config.settings'
django.setup()
from backend.apps.logs.models import Log
import logging

logger = logging.getLogger(__name__)

class WindowsLogMonitor:
    """Monitor Windows Event Logs in real-time"""
    
    CHANNELS = [
        'Security',
        'System', 
        'Application',
        'Microsoft-Windows-Sysmon/Operational',
        'Microsoft-Windows-PowerShell/Operational'
    ]
    
    def __init__(self):
        self.running = False
        self.threads = {}
    
    def start(self):
        """Start monitoring all channels"""
        self.running = True
        for channel in self.CHANNELS:
            thread = threading.Thread(target=self._monitor_channel, args=(channel,), daemon=True)
            thread.start()
            self.threads[channel] = thread
            logger.info(f"Started monitoring {channel}")
    
    def stop(self):
        """Stop all monitoring threads"""
        self.running = False
        for channel in self.threads:
            logger.info(f"Stopping monitor for {channel}")
    
    def _monitor_channel(self, channel):
        """Monitor single channel"""
        hand = win32evtlog.OpenEventLog(None, channel)
        flags = win32evtlog.EVENTLOG_BACKWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ
        
        try:
            flags |= win32evtlog.EVENTLOG_FORWARDS_READ
            hand = win32evtlog.OpenEventLog(None, channel)
            
            while self.running:
                events = win32evtlog.ReadEventLog(hand, flags, 0)
                
                for event in events:
                    try:
                        self._process_event(event, channel)
                    except Exception as e:
                        logger.error(f"Error processing event: {e}")
                
                time.sleep(1)  # Poll every second
                
        except Exception as e:
            logger.error(f"Error reading {channel}: {e}")
        finally:
            win32evtlog.CloseEventLog(hand)
    
    def _process_event(self, event, channel):
        """Process single Windows event"""
        try:
            # Get event details
            event_id = event.EventID
            timestamp = timezone.make_aware(event.TimeGenerated)
            level_map = {
                win32evtlog.EVENTLOG_SUCCESS: 'INFO',
                win32evtlog.EVENTLOG_ERROR_TYPE: 'ERROR',
                win32evtlog.EVENTLOG_WARNING_TYPE: 'WARNING',
                win32evtlog.EVENTLOG_AUDIT_SUCCESS: 'INFO',
                win32evtlog.EVENTLOG_AUDIT_FAILURE: 'WARNING'
            }
            level = level_map.get(event.EventType, 'INFO')
            
            # Try to get structured data
            message = event.StringInserts[0] if event.StringInserts else event.Message or "No message"
            
            # Basic parsing for common fields
            service = channel
            ip_address = "LOCALHOST"
            
            # Create log entry
            Log.objects.create(
                timestamp=timestamp,
                level=level,
                message=message[:1000],
                ip_address=ip_address,
                service=service,
                event_id=event_id,
                channel=channel,
                provider_name=event.SourceName or '',
                computer=event.ComputerName or '',
                raw_event_data={
                    'event_id': event_id,
                    'event_type': event.EventType,
                    'source': event.SourceName,
                    'computer': event.ComputerName,
                    'time_created': timestamp.isoformat(),
                    'channel': channel
                }
            )
            
        except Exception as e:
            logger.error(f"Failed to process Windows event: {e}")

# Global monitor instance
monitor = WindowsLogMonitor()

def start_windows_monitor():
    """Start the global monitor"""
    monitor.start()

if __name__ == '__main__':
    monitor = WindowsLogMonitor()
    monitor.start()
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        monitor.stop()

