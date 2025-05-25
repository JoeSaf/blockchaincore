#!/usr/bin/env python3
"""Basic tests for blockchain core"""

import sys
import os
import time

def test_import():
    """Test that blockchain_core can be imported"""
    try:
        import blockchain_core
        print("✓ blockchain_core imported successfully")
        return True
    except ImportError as e:
        print(f"✗ Failed to import blockchain_core: {e}")
        return False

def test_basic_operations():
    """Test basic blockchain operations"""
    try:
        import blockchain_core
        
        # Get blockchain instance
        core = blockchain_core.BlockchainCore.get_instance()
        
        # Test chain length
        length = core.get_chain_length()
        print(f"✓ Chain length: {length}")
        
        # Test adding a block
        core.add_custom_block({"test": "data", "timestamp": time.time()})
        new_length = core.get_chain_length()
        
        if new_length > length:
            print("✓ Block addition successful")
            return True
        else:
            print("✗ Block addition failed")
            return False
            
    except Exception as e:
        print(f"✗ Basic operations failed: {e}")
        return False

def test_p2p_availability():
    """Test P2P functionality availability"""
    try:
        import blockchain_core
        
        if hasattr(blockchain_core, 'NetworkedBlockchainCore'):
            print("✓ P2P functionality available")
            
            # Test P2P core creation
            p2p_core = blockchain_core.NetworkedBlockchainCore(19999)
            print("✓ P2P core creation successful")
            return True
        else:
            print("⚠ P2P functionality not available")
            return True  # Not an error
            
    except Exception as e:
        print(f"✗ P2P test failed: {e}")
        return False

def main():
    print("Running Blockchain Core Tests")
    print("=" * 30)
    
    tests = [
        ("Import Test", test_import),
        ("Basic Operations", test_basic_operations),
        ("P2P Availability", test_p2p_availability),
    ]
    
    passed = 0
    total = len(tests)
    
    for name, test_func in tests:
        print(f"\nRunning {name}...")
        if test_func():
            passed += 1
    
    print(f"\nResults: {passed}/{total} tests passed")
    
    if passed == total:
        print("✓ All tests passed!")
        return 0
    else:
        print("✗ Some tests failed!")
        return 1

if __name__ == "__main__":
    sys.exit(main())
