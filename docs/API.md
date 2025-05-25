# Blockchain Core API

## Python API

### Basic Usage

```python
from polymorphicblock_p2p import NetworkedBlockchain

# Create blockchain instance
blockchain = NetworkedBlockchain(p2p_port=8333)
blockchain.initialize()

# Start P2P networking
blockchain.start_network()

# Add bootstrap nodes
blockchain.add_bootstrap_node("127.0.0.1", 8334)

# Add blocks and transactions
blockchain.add_block({"data": "test"}, broadcast=True)
blockchain.add_transaction({"from": "alice", "to": "bob", "amount": 100})

# Get network status
status = blockchain.get_network_status()
print(f"Peers: {status['peer_count']}")
```

### Advanced Features

```python
# Event handling
def on_block_received(block):
    print(f"New block: {block['index']}")

blockchain.on_block_received(on_block_received)

# Manual block creation
blockchain.create_and_broadcast_block()

# Network synchronization
blockchain.request_sync()
```

## C++ API

Direct C++ usage (for advanced users):

```cpp
#include "blockchain_p2p_integration.hpp"

using namespace blockchain;

// Create networked blockchain
auto blockchain = std::make_unique<NetworkedBlockchainCore>(8333);
blockchain->initialize();

// Add custom block
json block_data = {{"test", "data"}};
blockchain->addBlock(block_data, true);

// Get network status
auto status = blockchain->getNetworkStatus();
```
