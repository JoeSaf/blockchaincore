#!/usr/bin/env python3
"""
Prometheus metrics exporter for Blockchain Core
Optimized for Arch Linux deployment
"""

import time
import json
import logging
from typing import Dict, Any
from prometheus_client import start_http_server, Gauge, Counter, Histogram, Info
import psutil

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

class BlockchainMetricsExporter:
    def __init__(self, port: int = 9090):
        self.port = port
        self.blockchain_core = None
        
        # System metrics
        self.cpu_usage = Gauge('blockchain_cpu_usage_percent', 'CPU usage percentage')
        self.memory_usage = Gauge('blockchain_memory_usage_bytes', 'Memory usage in bytes')
        self.disk_usage = Gauge('blockchain_disk_usage_bytes', 'Disk usage in bytes')
        
        # Blockchain metrics
        self.blockchain_height = Gauge('blockchain_height', 'Current blockchain height')
        self.peer_count = Gauge('blockchain_peer_count', 'Number of connected peers')
        self.mempool_size = Gauge('blockchain_mempool_size', 'Number of pending transactions')
        self.blocks_total = Counter('blockchain_blocks_total', 'Total number of blocks processed')
        self.transactions_total = Counter('blockchain_transactions_total', 'Total number of transactions')
        
        # Network metrics
        self.messages_received = Counter('blockchain_messages_received_total', 'Total messages received')
        self.messages_sent = Counter('blockchain_messages_sent_total', 'Total messages sent')
        
        # Node info
        self.node_info = Info('blockchain_node_info', 'Static node information')
        
        # Initialize blockchain core
        self._init_blockchain()
    
    def _init_blockchain(self):
        """Initialize blockchain core connection"""
        try:
            import blockchain_core
            
            if hasattr(blockchain_core, 'NetworkedBlockchainCore'):
                self.blockchain_core = blockchain_core.NetworkedBlockchainCore()
                self.blockchain_core.enableP2PNetworking(False)  # Metrics only
                logger.info("Initialized NetworkedBlockchainCore")
            else:
                self.blockchain_core = blockchain_core.BlockchainCore.get_instance()
                logger.info("Initialized basic BlockchainCore")
                
            # Set static node info
            self.node_info.info({
                'version': getattr(blockchain_core, '__version__', '1.0.0'),
                'build_type': 'optimized' if hasattr(blockchain_core, 'NetworkedBlockchainCore') else 'basic',
                'platform': 'arch-linux'
            })
            
        except Exception as e:
            logger.error(f"Failed to initialize blockchain core: {e}")
            self.blockchain_core = None
    
    def collect_system_metrics(self):
        """Collect system resource metrics"""
        try:
            # CPU usage
            cpu_percent = psutil.cpu_percent(interval=1)
            self.cpu_usage.set(cpu_percent)
            
            # Memory usage
            memory = psutil.virtual_memory()
            self.memory_usage.set(memory.used)
            
            # Disk usage for blockchain data
            try:
                disk = psutil.disk_usage('/var/lib/blockchain')
                self.disk_usage.set(disk.used)
            except:
                disk = psutil.disk_usage('.')
                self.disk_usage.set(disk.used)
            
            logger.debug(f"System metrics - CPU: {cpu_percent}%, Memory: {memory.used}")
            
        except Exception as e:
            logger.error(f"Error collecting system metrics: {e}")
    
    def collect_blockchain_metrics(self):
        """Collect blockchain-specific metrics"""
        if not self.blockchain_core:
            return
            
        try:
            # Basic blockchain metrics
            if hasattr(self.blockchain_core, 'getChainLength'):
                chain_length = self.blockchain_core.getChainLength()
                self.blockchain_height.set(chain_length)
            elif hasattr(self.blockchain_core, 'get_chain_length'):
                chain_length = self.blockchain_core.get_chain_length()
                self.blockchain_height.set(chain_length)
            
            # Network metrics (if available)
            if hasattr(self.blockchain_core, 'getNetworkStatus'):
                status = self.blockchain_core.getNetworkStatus()
                
                self.peer_count.set(status.get('peer_count', 0))
                self.mempool_size.set(status.get('mempool_size', 0))
                
                # Network statistics
                network = status.get('network', {})
                if network:
                    self.messages_received._value._value = network.get('messages_received', 0)
                    self.messages_sent._value._value = network.get('messages_sent', 0)
            
            logger.debug(f"Blockchain metrics collected")
            
        except Exception as e:
            logger.error(f"Error collecting blockchain metrics: {e}")
    
    def start_server(self):
        """Start the Prometheus metrics server"""
        start_http_server(self.port)
        logger.info(f"Prometheus metrics server started on port {self.port}")
        
        while True:
            try:
                self.collect_system_metrics()
                self.collect_blockchain_metrics()
                time.sleep(15)  # Collect metrics every 15 seconds
                
            except KeyboardInterrupt:
                logger.info("Metrics collection stopped")
                break
            except Exception as e:
                logger.error(f"Error in metrics collection loop: {e}")
                time.sleep(5)

def main():
    import argparse
    
    parser = argparse.ArgumentParser(description='Blockchain Prometheus Exporter')
    parser.add_argument('--port', type=int, default=9090, help='Metrics server port')
    parser.add_argument('--log-level', default='INFO', help='Log level')
    
    args = parser.parse_args()
    
    # Set log level
    logging.getLogger().setLevel(getattr(logging, args.log_level.upper()))
    
    # Start exporter
    exporter = BlockchainMetricsExporter(args.port)
    exporter.start_server()

if __name__ == '__main__':
    main()
