# core/context_processors.py
from .utils import BlockchainSystemInterface

def blockchain_context(request):
    """Add blockchain system context to all templates"""
    try:
        blockchain_interface = BlockchainSystemInterface()
        system_status = blockchain_interface.get_system_status()
        
        return {
            'blockchain_status': system_status,
            'system_running': system_status.get('system_running', False),
            'node_connected': system_status.get('node_connected', False),
        }
    except Exception as e:
        return {
            'blockchain_status': {},
            'system_running': False,
            'node_connected': False,
        }