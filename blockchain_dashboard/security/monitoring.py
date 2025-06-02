# blockchain_dashboard/security/monitoring.py
class SecurityMonitor:
    def __init__(self):
        self.alert_handlers = []
    
    def start_monitoring(self):
        """Start real-time security monitoring"""
        # Monitor coordinator security events
        threading.Thread(
            target=self.monitor_coordinator_security,
            daemon=True
        ).start()
        
        # Monitor Django security events
        threading.Thread(
            target=self.monitor_django_security,
            daemon=True
        ).start()
    
    def monitor_coordinator_security(self):
        """Monitor security events from coordinator"""
        while True:
            try:
                # Get security events from coordinator
                events = get_coordinator_security_events()
                
                for event in events:
                    self.handle_security_event(event)
                
                time.sleep(5)  # Check every 5 seconds
            except Exception as e:
                logger.error(f"Security monitoring error: {e}")
    
    def handle_security_event(self, event):
        """Handle security event"""
        # Create Django security alert
        alert = SecurityAlert.objects.create(
            alert_type=event['type'],
            severity=event['severity'],
            title=event['title'],
            description=event['description'],
            alert_data=event.get('data', {})
        )
        
        # Send real-time notification
        send_realtime_alert(alert)