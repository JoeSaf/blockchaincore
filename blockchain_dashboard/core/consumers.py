# blockchain_dashboard/core/consumers.py
import json
from channels.generic.websocket import AsyncWebsocketConsumer
from .utils import BlockchainSystemInterface

class SystemStatusConsumer(AsyncWebsocketConsumer):
    async def connect(self):
        await self.channel_layer.group_add("system_status", self.channel_name)
        await self.accept()
    
    async def disconnect(self, close_code):
        await self.channel_layer.group_discard("system_status", self.channel_name)
    
    async def receive(self, text_data):
        data = json.loads(text_data)
        if data['type'] == 'get_status':
            # Get real-time status
            blockchain_interface = BlockchainSystemInterface()
            status = blockchain_interface.get_system_status()
            
            await self.send(text_data=json.dumps({
                'type': 'status_update',
                'data': status
            }))