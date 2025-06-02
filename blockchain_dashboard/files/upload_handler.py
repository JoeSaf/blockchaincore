# blockchain_dashboard/files/upload_handler.py
class ProgressiveUploadHandler:
    def __init__(self, websocket_group):
        self.websocket_group = websocket_group
    
    async def handle_upload(self, file_data, user, database):
        """Handle upload with progress updates"""
        # Send progress updates
        await self.send_progress(0, "Starting upload...")
        
        # Security scan
        await self.send_progress(25, "Scanning for threats...")
        scan_result = await self.security_scan(file_data)
        
        # Upload to coordinator
        await self.send_progress(50, "Uploading to blockchain...")
        upload_result = await self.coordinator_upload(file_data, user, database)
        
        # Complete
        await self.send_progress(100, "Upload complete!")
        
        return upload_result
    
    async def send_progress(self, percent, message):
        """Send progress update via WebSocket"""
        await self.channel_layer.group_send(
            self.websocket_group,
            {
                'type': 'upload_progress',
                'percent': percent,
                'message': message
            }
        )