#!/usr/bin/env python3
"""
Unified Blockchain System Startup Manager
Coordinates C++ node, system coordinator, and Django dashboard
"""

import os
import sys
import time
import signal
import subprocess
import json
import argparse
import threading
from pathlib import Path
import psutil
import logging

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

class BlockchainSystemManager:
    def __init__(self, config_file="startup_config.json"):
        self.config = self.load_config(config_file)
        self.processes = {}
        self.running = False
        self.shutdown_event = threading.Event()
        
        # Setup signal handlers
        signal.signal(signal.SIGINT, self.signal_handler)
        signal.signal(signal.SIGTERM, self.signal_handler)
    
    def load_config(self, config_file):
        """Load startup configuration"""
        default_config = {
            "cpp_node": {
                "executable": "../blockchain_dashboard/../build/bin/blockchain_node",
                "enabled": True,
                "startup_delay": 3,
                "restart_on_failure": True
            },
            "coordinator": {
                "script": "system_coordinator.py",
                "enabled": True,
                "startup_delay": 2,
                "daemon_mode": True
            },
            "django": {
                "host": "0.0.0.0",
                "port": 8000,
                "enabled": True,
                "startup_delay": 1,
                "auto_migrate": True
            },
            "redis": {
                "enabled": True,
                "host": "localhost",
                "port": 6379
            },
            "monitoring": {
                "enabled": True,
                "check_interval": 10
            }
        }
        
        if os.path.exists(config_file):
            try:
                with open(config_file, 'r') as f:
                    config = json.load(f)
                # Merge with defaults
                for key, value in default_config.items():
                    if key not in config:
                        config[key] = value
                    elif isinstance(value, dict):
                        for subkey, subvalue in value.items():
                            if subkey not in config[key]:
                                config[key][subkey] = subvalue
                return config
            except Exception as e:
                logger.warning(f"Failed to load config: {e}, using defaults")
        
        # Save default config
        try:
            with open(config_file, 'w') as f:
                json.dump(default_config, f, indent=2)
        except Exception as e:
            logger.warning(f"Failed to save default config: {e}")
        
        return default_config
    
    def check_prerequisites(self):
        """Check system prerequisites"""
        logger.info("🔍 Checking system prerequisites...")
        
        # Check Python version
        if sys.version_info < (3, 8):
            logger.error("Python 3.8+ required")
            return False
        
        # Check required files
        required_files = [
            "manage.py",
            "system_coordinator.py"
        ]
        
        for file in required_files:
            if not os.path.exists(file):
                logger.error(f"Required file missing: {file}")
                return False
        
        # Check C++ executable
        if self.config["cpp_node"]["enabled"]:
            cpp_path = self.config["cpp_node"]["executable"]
            if not os.path.exists(cpp_path):
                logger.warning(f"C++ node executable not found: {cpp_path}")
                logger.warning("Will continue without C++ node")
                self.config["cpp_node"]["enabled"] = False
        
        # Check Redis if enabled
        if self.config["redis"]["enabled"]:
            if not self.check_redis():
                logger.warning("Redis not available, disabling real-time features")
                self.config["redis"]["enabled"] = False
        
        logger.info("✅ Prerequisites check completed")
        return True
    
    def check_redis(self):
        """Check if Redis is available"""
        try:
            import redis
            r = redis.Redis(
                host=self.config["redis"]["host"],
                port=self.config["redis"]["port"],
                socket_timeout=2
            )
            r.ping()
            return True
        except Exception:
            return False
    
    def start_cpp_node(self):
        """Start C++ blockchain node"""
        if not self.config["cpp_node"]["enabled"]:
            logger.info("C++ node disabled, skipping...")
            return True
        
        logger.info("🔗 Starting C++ blockchain node...")
        
        try:
            executable = self.config["cpp_node"]["executable"]
            
            # Check if already running
            if self.is_port_in_use(8080):
                logger.warning("Port 8080 already in use, C++ node may be running")
                return True
            
            self.processes['cpp_node'] = subprocess.Popen(
                [executable],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                universal_newlines=True
            )
            
            # Wait for startup
            time.sleep(self.config["cpp_node"]["startup_delay"])
            
            # Check if process is still running
            if self.processes['cpp_node'].poll() is None:
                logger.info("✅ C++ blockchain node started successfully")
                return True
            else:
                logger.error("❌ C++ node failed to start")
                return False
                
        except Exception as e:
            logger.error(f"Failed to start C++ node: {e}")
            return False
    
    def start_coordinator(self):
        """Start system coordinator"""
        if not self.config["coordinator"]["enabled"]:
            logger.info("System coordinator disabled, skipping...")
            return True
        
        logger.info("🔧 Starting system coordinator...")
        
        try:
            cmd = [sys.executable, self.config["coordinator"]["script"]]
            
            if self.config["coordinator"]["daemon_mode"]:
                cmd.append("--daemon")
            
            self.processes['coordinator'] = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                universal_newlines=True
            )
            
            # Wait for startup
            time.sleep(self.config["coordinator"]["startup_delay"])
            
            if self.processes['coordinator'].poll() is None:
                logger.info("✅ System coordinator started successfully")
                return True
            else:
                logger.error("❌ System coordinator failed to start")
                return False
                
        except Exception as e:
            logger.error(f"Failed to start coordinator: {e}")
            return False
    
    def start_django(self):
        """Start Django dashboard"""
        if not self.config["django"]["enabled"]:
            logger.info("Django dashboard disabled, skipping...")
            return True
        
        logger.info("🌐 Starting Django dashboard...")
        
        try:
            # Run migrations if enabled
            #if self.config["django"]["auto_migrate"]:
            #    logger.info("Running Django migrations...")
            #    migrate_result = subprocess.run([
            #        sys.executable, "manage.py", "migrate"
            #    ], capture_output=True, text=True)
                
            #    if migrate_result.returncode != 0:
            #       logger.warning(f"Migration warnings: {migrate_result.stderr}")
            
            # Start Django server
            host = self.config["django"]["host"]
            port = self.config["django"]["port"]
            
            self.processes['django'] = subprocess.Popen([
                sys.executable, "manage.py", "runserver", f"{host}:{port}"
            ], stdout=subprocess.PIPE, stderr=subprocess.PIPE, universal_newlines=True)
            
            # Wait for startup
            time.sleep(self.config["django"]["startup_delay"])
            
            if self.processes['django'].poll() is None:
                logger.info(f"✅ Django dashboard started at http://{host}:{port}")
                return True
            else:
                logger.error("❌ Django dashboard failed to start")
                return False
                
        except Exception as e:
            logger.error(f"Failed to start Django: {e}")
            return False
    
    def is_port_in_use(self, port):
        """Check if port is in use"""
        try:
            import socket
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                return s.connect_ex(('localhost', port)) == 0
        except Exception:
            return False
    
    def start_monitoring(self):
        """Start system monitoring"""
        if not self.config["monitoring"]["enabled"]:
            return
        
        logger.info("📊 Starting system monitoring...")
        
        def monitor():
            while not self.shutdown_event.is_set():
                try:
                    self.check_process_health()
                    time.sleep(self.config["monitoring"]["check_interval"])
                except Exception as e:
                    logger.error(f"Monitoring error: {e}")
        
        monitoring_thread = threading.Thread(target=monitor, daemon=True)
        monitoring_thread.start()
    
    def check_process_health(self):
        """Check health of all processes"""
        for name, process in self.processes.items():
            if process and process.poll() is not None:
                logger.warning(f"Process {name} has stopped unexpectedly")
                
                # Restart if configured
                if name == "cpp_node" and self.config["cpp_node"]["restart_on_failure"]:
                    logger.info(f"Attempting to restart {name}...")
                    if name == "cpp_node":
                        self.start_cpp_node()
    
    def start_all(self):
        """Start all system components"""
        logger.info("🚀 Starting Integrated Blockchain System...")
        print("=" * 60)
        print("🌟 INTEGRATED BLOCKCHAIN SYSTEM STARTUP")
        print("=" * 60)
        
        if not self.check_prerequisites():
            return False
        
        # Start components in order
        components = [
            ("C++ Node", self.start_cpp_node),
            ("Coordinator", self.start_coordinator),
            ("Django Dashboard", self.start_django)
        ]
        
        for name, start_func in components:
            if not start_func():
                logger.error(f"Failed to start {name}, aborting...")
                self.stop_all()
                return False
        
        # Start monitoring
        self.start_monitoring()
        
        self.running = True
        
        # Display summary
        self.display_startup_summary()
        
        logger.info("🎉 All systems started successfully!")
        return True
    
    def display_startup_summary(self):
        """Display startup summary"""
        print("\n🎉 SYSTEM STARTUP COMPLETE")
        print("=" * 40)
        
        # Display running services
        print("🔄 Running Services:")
        for name, process in self.processes.items():
            if process and process.poll() is None:
                pid = process.pid
                print(f"   ✅ {name.replace('_', ' ').title()}: PID {pid}")
        
        # Display access URLs
        if self.config["django"]["enabled"]:
            host = self.config["django"]["host"]
            port = self.config["django"]["port"]
            if host == "0.0.0.0":
                host = "localhost"
            print(f"\n🌐 Access URLs:")
            print(f"   Dashboard: http://{host}:{port}")
            print(f"   Admin: http://{host}:{port}/admin")
        
        if self.config["cpp_node"]["enabled"] and self.is_port_in_use(8080):
            print(f"   C++ Node API: http://localhost:8080")
        
        print(f"\n💡 Tips:")
        print("   • Press Ctrl+C to stop all services")
        print("   • Check logs in the console for any issues")
        print("   • Use --help for more startup options")
        print("=" * 40)
    
    def stop_all(self):
        """Stop all processes gracefully"""
        logger.info("🛑 Shutting down all systems...")
        self.shutdown_event.set()
        
        # Stop processes in reverse order
        stop_order = ['django', 'coordinator', 'cpp_node']
        
        for name in stop_order:
            if name in self.processes:
                process = self.processes[name]
                if process and process.poll() is None:
                    logger.info(f"Stopping {name}...")
                    try:
                        process.terminate()
                        # Wait for graceful shutdown
                        try:
                            process.wait(timeout=10)
                            logger.info(f"✅ {name} stopped gracefully")
                        except subprocess.TimeoutExpired:
                            logger.warning(f"Force killing {name}...")
                            process.kill()
                            process.wait()
                    except Exception as e:
                        logger.error(f"Error stopping {name}: {e}")
        
        self.running = False
        logger.info("✅ All systems stopped")
    
    def signal_handler(self, signum, frame):
        """Handle shutdown signals"""
        logger.info(f"Received signal {signum}, shutting down...")
        self.stop_all()
        sys.exit(0)
    
    def status(self):
        """Display system status"""
        print("\n📊 System Status")
        print("=" * 30)
        
        for name, process in self.processes.items():
            if process:
                if process.poll() is None:
                    # Process is running
                    try:
                        proc = psutil.Process(process.pid)
                        cpu = proc.cpu_percent()
                        memory = proc.memory_info().rss / 1024 / 1024  # MB
                        print(f"✅ {name}: Running (CPU: {cpu:.1f}%, Memory: {memory:.1f}MB)")
                    except:
                        print(f"✅ {name}: Running")
                else:
                    print(f"❌ {name}: Stopped (Exit code: {process.returncode})")
            else:
                print(f"⚪ {name}: Not started")
        
        # Check ports
        print(f"\n🔌 Port Status:")
        ports = [
            (8000, "Django Dashboard"),
            (8080, "C++ Node API"),
            (8333, "C++ Node P2P"),
            (6379, "Redis")
        ]
        
        for port, service in ports:
            status = "🟢 Open" if self.is_port_in_use(port) else "🔴 Closed"
            print(f"   Port {port} ({service}): {status}")
    
    def restart_component(self, component):
        """Restart a specific component"""
        logger.info(f"🔄 Restarting {component}...")
        
        # Stop component
        if component in self.processes:
            process = self.processes[component]
            if process and process.poll() is None:
                process.terminate()
                process.wait()
        
        # Restart component
        if component == "cpp_node":
            return self.start_cpp_node()
        elif component == "coordinator":
            return self.start_coordinator()
        elif component == "django":
            return self.start_django()
        else:
            logger.error(f"Unknown component: {component}")
            return False
    
    def run_interactive(self):
        """Run in interactive mode"""
        if not self.start_all():
            return False
        
        print(f"\n🎛️ Interactive Mode - Type 'help' for commands")
        
        try:
            while self.running:
                try:
                    command = input("blockchain> ").strip().lower()
                    
                    if command in ['exit', 'quit', 'q']:
                        break
                    elif command == 'help':
                        self.show_help()
                    elif command == 'status':
                        self.status()
                    elif command.startswith('restart'):
                        parts = command.split()
                        if len(parts) > 1:
                            self.restart_component(parts[1])
                        else:
                            print("Usage: restart <component>")
                    elif command == 'logs':
                        self.show_recent_logs()
                    elif command == '':
                        continue
                    else:
                        print(f"Unknown command: {command}")
                        print("Type 'help' for available commands")
                
                except EOFError:
                    break
                except KeyboardInterrupt:
                    break
        
        finally:
            self.stop_all()
        
        return True
    
    def show_help(self):
        """Show available commands"""
        print(f"\n📋 Available Commands:")
        print("   status           - Show system status")
        print("   restart <comp>   - Restart component (cpp_node, coordinator, django)")
        print("   logs            - Show recent logs")
        print("   help            - Show this help")
        print("   exit/quit/q     - Stop all services and exit")
    
    def show_recent_logs(self):
        """Show recent logs from processes"""
        print(f"\n📜 Recent Logs:")
        print("-" * 40)
        
        for name, process in self.processes.items():
            if process and process.poll() is None:
                print(f"\n{name.upper()}:")
                try:
                    # This is a simplified log view
                    print(f"   Process running (PID: {process.pid})")
                    print("   📝 Use 'tail -f blockchain_system.log' for detailed logs")
                except Exception as e:
                    print(f"   Error reading logs: {e}")


def main():
    """Main entry point"""
    parser = argparse.ArgumentParser(description="Blockchain System Startup Manager")
    parser.add_argument("--config", default="startup_config.json",
                       help="Configuration file path")
    parser.add_argument("--interactive", "-i", action="store_true",
                       help="Run in interactive mode")
    parser.add_argument("--status", action="store_true",
                       help="Show system status and exit")
    parser.add_argument("--stop", action="store_true",
                       help="Stop all running services")
    parser.add_argument("--daemon", "-d", action="store_true",
                       help="Run in daemon mode")
    parser.add_argument("--component", 
                       choices=["cpp_node", "coordinator", "django"],
                       help="Start only specific component")
    parser.add_argument("--verbose", "-v", action="store_true",
                       help="Enable verbose logging")
    
    args = parser.parse_args()
    
    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)
    
    manager = BlockchainSystemManager(args.config)
    
    if args.status:
        manager.status()
        return
    
    if args.stop:
        # Find and stop running processes
        print("🛑 Stopping blockchain system services...")
        # Implementation would find PIDs and stop them
        return
    
    if args.component:
        # Start only specific component
        if args.component == "cpp_node":
            success = manager.start_cpp_node()
        elif args.component == "coordinator":
            success = manager.start_coordinator()
        elif args.component == "django":
            success = manager.start_django()
        
        if success:
            print(f"✅ {args.component} started successfully")
            try:
                while True:
                    time.sleep(1)
            except KeyboardInterrupt:
                manager.stop_all()
        else:
            print(f"❌ Failed to start {args.component}")
            sys.exit(1)
        return
    
    # Normal startup
    if args.interactive:
        success = manager.run_interactive()
    else:
        success = manager.start_all()
        if success:
            try:
                # Keep running until interrupted
                while manager.running:
                    time.sleep(1)
            except KeyboardInterrupt:
                pass
            finally:
                manager.stop_all()
    
    sys.exit(0 if success else 1)


if __name__ == "__main__":
    main()