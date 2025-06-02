# blockchain_dashboard/core/message_queue.py
import redis
import json
from django.conf import settings

class MessageQueue:
    def __init__(self):
        self.redis_client = redis.Redis(
            host=settings.REDIS_HOST,
            port=settings.REDIS_PORT,
            db=0
        )
    
    def publish_status_update(self, component, status):
        """Publish status update"""
        message = {
            'component': component,
            'status': status,
            'timestamp': time.time()
        }
        self.redis_client.publish('system_status', json.dumps(message))
    
    def subscribe_to_updates(self, callback):
        """Subscribe to status updates"""
        pubsub = self.redis_client.pubsub()
        pubsub.subscribe('system_status')
        
        for message in pubsub.listen():
            if message['type'] == 'message':
                data = json.loads(message['data'])
                callback(data)