**Comprehensive Blockchain P2P Network Project Prompt**

I'm building a decentralized blockchain file storage system for a school project with a 3-week deadline. I need help creating a complete C/C++ solution with the following specifications:

**System Architecture:**
```
┌─────────────────┐    ┌──────────────────┐    ┌─────────────────┐
│   CLI Client    │    │  Blockchain Core │    │  P2P Network    │
│   (Primary UI)  │◄──►│   (C/C++ Core)   │◄──►│   (C/C++ Net)   │
└─────────────────┘    └──────────────────┘    └─────────────────┘
         │                       │                       │
         └───────────────────────┼───────────────────────┘
                                 ▼
                    ┌──────────────────┐
                    │  Simple Web UI   │
                    │  (Optional HTTP) │
                    └──────────────────┘
```

**Core Requirements:**
1. **P2P Network Architecture**: True peer-to-peer network where the starting node, running PC, and any joining device becomes a network peer with full node capabilities
2. **File-Based Blockchain**: Blockchain specifically designed for file storage with hash-based integrity verification
3. **Advanced Security System**: 
   - Corrupted block detection via hash mismatches
   - Detection of chain integrity breaks (previous/next block hash mismatches)
   - Automatic infected block isolation and user data migration to new clean chain
   - Polymorphic chain reordering to prevent brute force attacks
4. **CLI-First Interface**: Primary interaction through command-line interface with real-time security alerts and chain status
5. **Simple Web Interface**: 
   - Basic HTML webpage with user login for registered users
   - File upload functionality for authenticated users
   - Chain viewing capabilities
   - Simple HTTP server (no Django complexity)

**Technical Stack:**
- Primary: C/C++ for blockchain core and P2P networking
- CLI interface for all operations
- Simple web server with HTML pages for login and file upload
- File-based storage system

**Key Features Needed:**
- Multi-node network discovery and peer management
- Block creation, validation, and chain synchronization
- Real-time security monitoring and infected block quarantine
- Automatic chain recovery and data preservation
- Network-wide consensus mechanism
- CLI commands for all blockchain operations
- User registration and authentication system
- Web-based file upload with user authentication

**What I Have:**
- Working C++ node code (will upload in next chat)
- Clear vision of the architecture
- 3-week development timeline

**What I Need Help With:**
- Integrating P2P networking with blockchain core
- Implementing the security detection and recovery system
- Building the polymorphic chain reordering mechanism
- Creating efficient peer synchronization protocols
- Designing the CLI interface for all operations
- Creating simple HTML login page and file upload interface
- Implementing user authentication for web interface

**Please ask me to upload my existing C++ node code so we can build upon it and create this complete decentralized blockchain system.**

