class DashboardWebSocket {
    constructor(username) {
        this.username = username;
        this.socket = null;
        this.reconnectAttempts = 0;
        this.maxReconnectAttempts = 5;
    }
    
    connect() {
        const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
        const wsUrl = `${protocol}//${window.location.host}/ws/dashboard/`;
        
        this.socket = new WebSocket(wsUrl);
        
        this.socket.onopen = (event) => {
            console.log('Dashboard WebSocket connected');
            this.reconnectAttempts = 0;
            this.requestStatusUpdate();
        };
        
        this.socket.onmessage = (event) => {
            const data = JSON.parse(event.data);
            this.handleMessage(data);
        };
        
        this.socket.onclose = (event) => {
            console.log('Dashboard WebSocket disconnected');
            this.handleReconnection();
        };
        
        this.socket.onerror = (error) => {
            console.error('WebSocket error:', error);
        };
    }
    
    handleMessage(data) {
        switch(data.type) {
            case 'status_update':
                this.updateSystemStatus(data.data);
                break;
            case 'activity_update':
                this.updateActivityFeed(data.data);
                break;
            case 'security_alert':
                this.handleSecurityAlert(data.data);
                break;
            case 'upload_progress':
                this.updateUploadProgress(data.data);
                break;
        }
    }
    
    updateSystemStatus(status) {
        // Update C++ Node status
        const cppStatus = status.cpp_node_connected ? 'success' : 'danger';
        const cppText = status.cpp_node_connected ? 'Connected' : 'Disconnected';
        
        document.getElementById('cpp-status').innerHTML = 
            `<span class="badge badge-${cppStatus}">${cppText}</span>`;
        
        // Update coordinator status
        const coordStatus = status.system_running ? 'success' : 'warning';
        const coordText = status.system_running ? 'Running' : 'Stopped';
        
        document.getElementById('coordinator-status-badge').innerHTML = 
            `<span class="badge badge-${coordStatus}">${coordText}</span>`;
        
        // Update metrics
        this.updateMetrics(status);
    }
    
    updateActivityFeed(activity) {
        const feed = document.getElementById('activity-feed');
        const timestamp = new Date().toLocaleTimeString();
        
        const activityItem = document.createElement('div');
        activityItem.className = 'activity-item';
        activityItem.innerHTML = `
            <span class="timestamp">${timestamp}</span>
            <span class="activity-text">${activity.message}</span>
        `;
        
        feed.insertBefore(activityItem, feed.firstChild);
        
        // Limit to 10 items
        while (feed.children.length > 10) {
            feed.removeChild(feed.lastChild);
        }
    }
    
    requestStatusUpdate() {
        if (this.socket && this.socket.readyState === WebSocket.OPEN) {
            this.socket.send(JSON.stringify({
                type: 'get_status'
            }));
        }
    }
}