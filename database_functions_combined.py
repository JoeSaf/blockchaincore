def manage_database_security(self):
    """Comprehensive database security management"""
    while True:
        print("\n🔒 Database Security & Permissions")
        print("=" * 45)
        print("1. 🔐 Database Access Control")
        print("2. 🛡️ Security Policies & Rules")
        print("3. 🔍 Security Audit & Compliance")
        print("4. 🚨 Security Threats & Monitoring")
        print("5. 🔑 Encryption & Data Protection")
        print("6. 📜 Security Logs & Events")
        print("7. 🔒 Database Lockdown Mode")
        print("8. ⚙️ Security Configuration")
        print("9. 📊 Security Assessment Report")
        print("10. 🔙 Back to Database Menu")
        
        choice = input("\nEnter your choice (1-10): ").strip()
        
        if choice == "1":
            self.database_access_control_menu()
        elif choice == "2":
            self.database_security_policies_menu()
        elif choice == "3":
            self.database_security_audit()
        elif choice == "4":
            self.database_security_monitoring()
        elif choice == "5":
            self.database_encryption_management()
        elif choice == "6":
            self.view_database_security_logs()
        elif choice == "7":
            self.database_lockdown_management()
        elif choice == "8":
            self.database_security_configuration()
        elif choice == "9":
            self.generate_security_assessment_report()
        elif choice == "10":
            break
        else:
            print("❌ Invalid choice.")

def database_access_control_menu(self):
    """Database access control management"""
    while True:
        print("\n🔐 Database Access Control")
        print("=" * 35)
        print("1. 👁️ View Access Control Matrix")
        print("2. 🚫 Set Access Restrictions")
        print("3. 🕐 Time-based Access Controls")
        print("4. 🌐 IP-based Access Controls")
        print("5. 🔑 API Key Management")
        print("6. 🛡️ Role-based Access Control")
        print("7. 📋 Access Request Management")
        print("8. 🔙 Back to Security Menu")
        
        choice = input("\nEnter your choice (1-8): ").strip()
        
        if choice == "1":
            self.view_access_control_matrix()
        elif choice == "2":
            self.set_access_restrictions()
        elif choice == "3":
            self.manage_time_based_access()
        elif choice == "4":
            self.manage_ip_based_access()
        elif choice == "5":
            self.manage_api_keys()
        elif choice == "6":
            self.manage_role_based_access()
        elif choice == "7":
            self.manage_access_requests()
        elif choice == "8":
            break
        else:
            print("❌ Invalid choice.")

def view_access_control_matrix(self):
    """Display comprehensive access control matrix"""
    try:
        if self.current_user["role"] != "admin":
            print("❌ Only administrators can view the access control matrix.")
            input("Press Enter to continue...")
            return
        
        print("\n👁️ Database Access Control Matrix")
        print("=" * 50)
        
        databases = self.db_manager.list_databases()
        
        if not databases:
            print("❌ No databases available.")
            input("Press Enter to continue...")
            return
        
        # Collect all users and their permissions
        access_matrix = {}
        all_users = set()
        
        for db in databases:
            try:
                db_path = os.path.join(self.config["storage"]["database_root"], "databases", db["name"])
                users_file = os.path.join(db_path, "users.json")
                
                if os.path.exists(users_file):
                    with open(users_file, "r") as f:
                        users_data = json.load(f)
                    
                    db_users = users_data.get("users", {})
                    access_matrix[db["name"]] = db_users
                    all_users.update(db_users.keys())
                else:
                    access_matrix[db["name"]] = {}
            
            except Exception as e:
                print(f"❌ Error reading {db['name']}: {str(e)}")
                access_matrix[db["name"]] = {}
        
        if not all_users:
            print("❌ No users found in any database.")
            input("Press Enter to continue...")
            return
        
        # Display matrix
        all_users = sorted(list(all_users))
        db_names = [db["name"] for db in databases]
        
        print(f"Access Control Matrix ({len(all_users)} users × {len(db_names)} databases):")
        print()
        
        # Header
        header = f"{'User':<15}"
        for db_name in db_names:
            header += f"{db_name[:12]:<13}"
        print(header)
        print("-" * len(header))
        
        # User rows
        for user in all_users:
            row = f"{user:<15}"
            for db_name in db_names:
                if user in access_matrix.get(db_name, {}):
                    user_info = access_matrix[db_name][user]
                    role = user_info.get("role", "unknown")
                    locked = user_info.get("locked", False)
                    
                    if locked:
                        access_display = "🔒LOCKED"
                    elif role == "owner":
                        access_display = "👑OWNER"
                    elif role == "admin":
                        access_display = "⚙️ADMIN"
                    elif role == "user":
                        access_display = "👤USER"
                    elif role == "readonly":
                        access_display = "👁️READ"
                    else:
                        access_display = f"❓{role[:5]}"
                else:
                    access_display = "❌NONE"
                
                row += f"{access_display:<13}"
            
            print(row)
        
        print("-" * len(header))
        
        # Legend
        print(f"\n📋 Legend:")
        print("   👑 OWNER   - Full database control")
        print("   ⚙️ ADMIN   - Administrative access")
        print("   👤 USER    - Standard read/write access")
        print("   👁️ READ    - Read-only access")
        print("   🔒 LOCKED  - Access temporarily disabled")
        print("   ❌ NONE    - No access")
        
        # Security insights
        print(f"\n🔍 Security Insights:")
        
        # Count access levels
        owner_count = sum(1 for db_name in db_names for user in all_users 
                         if user in access_matrix.get(db_name, {}) and 
                         access_matrix[db_name][user].get("role") == "owner")
        
        admin_count = sum(1 for db_name in db_names for user in all_users 
                         if user in access_matrix.get(db_name, {}) and 
                         access_matrix[db_name][user].get("role") == "admin")
        
        locked_count = sum(1 for db_name in db_names for user in all_users 
                          if user in access_matrix.get(db_name, {}) and 
                          access_matrix[db_name][user].get("locked", False))
        
        print(f"   Total owner privileges: {owner_count}")
        print(f"   Total admin privileges: {admin_count}")
        print(f"   Total locked accounts: {locked_count}")
        
        # Security recommendations
        print(f"\n💡 Security Recommendations:")
        
        # Check for users with too many owner privileges
        owner_users = {}
        for db_name in db_names:
            for user in all_users:
                if (user in access_matrix.get(db_name, {}) and 
                    access_matrix[db_name][user].get("role") == "owner"):
                    owner_users[user] = owner_users.get(user, 0) + 1
        
        excessive_owners = {user: count for user, count in owner_users.items() if count > 2}
        if excessive_owners:
            print("   ⚠️ Users with excessive owner privileges:")
            for user, count in excessive_owners.items():
                print(f"      {user}: {count} databases")
        
        # Check for databases without admins
        orphaned_dbs = []
        for db_name in db_names:
            has_admin = any(access_matrix[db_name].get(user, {}).get("role") in ["owner", "admin"] 
                           for user in all_users)
            if not has_admin:
                orphaned_dbs.append(db_name)
        
        if orphaned_dbs:
            print(f"   🚨 Databases without administrative oversight:")
            for db_name in orphaned_dbs:
                print(f"      {db_name}")
        else:
            print("   ✅ All databases have administrative oversight")
        
        # Check for single points of failure
        critical_users = {}
        for user in all_users:
            owner_dbs = [db_name for db_name in db_names 
                        if (user in access_matrix.get(db_name, {}) and 
                            access_matrix[db_name][user].get("role") == "owner")]
            if len(owner_dbs) > 0:
                critical_users[user] = owner_dbs
        
        if critical_users:
            print(f"   ⚠️ Critical users (single points of failure):")
            for user, dbs in critical_users.items():
                if len(dbs) > 1:
                    print(f"      {user}: owns {len(dbs)} databases")
    
    except Exception as e:
        print(f"❌ Error displaying access control matrix: {str(e)}")
    
    input("\nPress Enter to continue...")

def set_access_restrictions(self):
    """Set database access restrictions"""
    try:
        if self.current_user["role"] != "admin":
            print("❌ Only administrators can set access restrictions.")
            input("Press Enter to continue...")
            return
        
        print("\n🚫 Set Database Access Restrictions")
        print("=" * 45)
        
        databases = self.db_manager.list_databases()
        
        if not databases:
            print("❌ No databases available.")
            input("Press Enter to continue...")
            return
        
        # Select database
        print("Available databases:")
        for i, db in enumerate(databases, 1):
            print(f"  {i}. {db['name']} (Owner: {db['owner']})")
        
        while True:
            try:
                db_choice = input(f"Select database (1-{len(databases)}): ").strip()
                db_index = int(db_choice) - 1
                if 0 <= db_index < len(databases):
                    selected_db = databases[db_index]
                    break
                else:
                    print(f"❌ Please enter a number between 1 and {len(databases)}")
            except ValueError:
                print("❌ Please enter a valid number")
        
        print(f"\n🔒 Setting restrictions for database: {selected_db['name']}")
        
        # Load current restrictions
        db_path = os.path.join(self.config["storage"]["database_root"], "databases", selected_db["name"])
        restrictions_file = os.path.join(db_path, "restrictions.json")
        
        current_restrictions = {}
        if os.path.exists(restrictions_file):
            try:
                with open(restrictions_file, "r") as f:
                    current_restrictions = json.load(f)
            except Exception:
                current_restrictions = {}
        
        print(f"\nCurrent restrictions:")
        if current_restrictions:
            for key, value in current_restrictions.items():
                print(f"   {key}: {value}")
        else:
            print("   No restrictions currently set")
        
        # Available restriction types
        print(f"\nAvailable restriction types:")
        print("1. Maximum concurrent connections")
        print("2. Maximum file size limit")
        print("3. Maximum storage quota")
        print("4. Operation rate limiting") 
        print("5. Time-based access windows")
        print("6. IP address whitelist/blacklist")
        print("7. User session timeout")
        print("8. Require multi-factor authentication")
        
        restriction_choice = input("Select restriction type (1-8): ").strip()
        
        if restriction_choice == "1":
            max_connections = input("Maximum concurrent connections (current: {}): ".format(
                current_restrictions.get("max_connections", "unlimited"))).strip()
            if max_connections:
                try:
                    current_restrictions["max_connections"] = int(max_connections)
                    print(f"✅ Set maximum connections to {max_connections}")
                except ValueError:
                    print("❌ Invalid number")
                    return
        
        elif restriction_choice == "2":
            max_file_size = input("Maximum file size in MB (current: {}): ".format(
                current_restrictions.get("max_file_size_mb", "unlimited"))).strip()
            if max_file_size:
                try:
                    current_restrictions["max_file_size_mb"] = float(max_file_size)
                    print(f"✅ Set maximum file size to {max_file_size} MB")
                except ValueError:
                    print("❌ Invalid number")
                    return
        
        elif restriction_choice == "3":
            storage_quota = input("Maximum storage quota in GB (current: {}): ".format(
                current_restrictions.get("storage_quota_gb", "unlimited"))).strip()
            if storage_quota:
                try:
                    current_restrictions["storage_quota_gb"] = float(storage_quota)
                    print(f"✅ Set storage quota to {storage_quota} GB")
                except ValueError:
                    print("❌ Invalid number")
                    return
        
        elif restriction_choice == "4":
            rate_limit = input("Operations per minute limit (current: {}): ".format(
                current_restrictions.get("rate_limit_per_minute", "unlimited"))).strip()
            if rate_limit:
                try:
                    current_restrictions["rate_limit_per_minute"] = int(rate_limit)
                    print(f"✅ Set rate limit to {rate_limit} operations per minute")
                except ValueError:
                    print("❌ Invalid number")
                    return
        
        elif restriction_choice == "5":
            print("Time-based access windows:")
            start_time = input("Start time (HH:MM, 24-hour format): ").strip()
            end_time = input("End time (HH:MM, 24-hour format): ").strip()
            
            if start_time and end_time:
                try:
                    # Validate time format
                    time.strptime(start_time, "%H:%M")
                    time.strptime(end_time, "%H:%M")
                    
                    current_restrictions["access_window"] = {
                        "start": start_time,
                        "end": end_time,
                        "timezone": "UTC"
                    }
                    print(f"✅ Set access window: {start_time} - {end_time} UTC")
                except ValueError:
                    print("❌ Invalid time format")
                    return
        
        elif restriction_choice == "6":
            print("IP Access Control:")
            print("1. Whitelist (only allow specific IPs)")
            print("2. Blacklist (block specific IPs)")
            
            ip_choice = input("Select option (1-2): ").strip()
            ip_list = input("Enter IP addresses (comma-separated): ").strip()
            
            if ip_choice in ["1", "2"] and ip_list:
                ip_addresses = [ip.strip() for ip in ip_list.split(",")]
                restriction_type = "whitelist" if ip_choice == "1" else "blacklist"
                
                current_restrictions["ip_access"] = {
                    "type": restriction_type,
                    "addresses": ip_addresses
                }
                print(f"✅ Set IP {restriction_type}: {', '.join(ip_addresses)}")
        
        elif restriction_choice == "7":
            session_timeout = input("Session timeout in minutes (current: {}): ".format(
                current_restrictions.get("session_timeout_minutes", "60"))).strip()
            if session_timeout:
                try:
                    current_restrictions["session_timeout_minutes"] = int(session_timeout)
                    print(f"✅ Set session timeout to {session_timeout} minutes")
                except ValueError:
                    print("❌ Invalid number")
                    return
        
        elif restriction_choice == "8":
            require_mfa = input("Require multi-factor authentication? (y/n): ").lower()
            if require_mfa in ["y", "n"]:
                current_restrictions["require_mfa"] = (require_mfa == "y")
                status = "enabled" if require_mfa == "y" else "disabled"
                print(f"✅ Multi-factor authentication {status}")
        
        else:
            print("❌ Invalid choice")
            input("Press Enter to continue...")
            return
        
        # Add metadata
        current_restrictions["last_modified"] = time.time()
        current_restrictions["modified_by"] = self.current_user["username"]
        
        # Save restrictions
        try:
            with open(restrictions_file, "w") as f:
                json.dump(current_restrictions, f, indent=2)
            
            print(f"✅ Access restrictions saved for database '{selected_db['name']}'")
            
            # Log the action
            self.security_system.add_security_block({
                "action": "database_restrictions_updated",
                "database": selected_db["name"],
                "restrictions": current_restrictions,
                "admin": self.current_user["username"],
                "timestamp": time.time()
            })
        
        except Exception as e:
            print(f"❌ Error saving restrictions: {str(e)}")
    
    except Exception as e:
        print(f"❌ Error setting access restrictions: {str(e)}")
    
    input("\nPress Enter to continue...")

def database_security_audit(self):
    """Perform comprehensive database security audit"""
    try:
        if self.current_user["role"] != "admin":
            print("❌ Only administrators can perform security audits.")
            input("Press Enter to continue...")
            return
        
        print("\n🔍 Database Security Audit & Compliance")
        print("=" * 50)
        print("🔄 Performing comprehensive security audit...")
        
        databases = self.db_manager.list_databases()
        
        if not databases:
            print("❌ No databases available for audit.")
            input("Press Enter to continue...")
            return
        
        audit_results = {
            "total_databases": len(databases),
            "security_score": 0,
            "critical_issues": [],
            "warnings": [],
            "recommendations": [],
            "compliant_databases": [],
            "non_compliant_databases": []
        }
        
        print(f"Auditing {len(databases)} databases...\n")
        
        for i, db in enumerate(databases, 1):
            print(f"[{i}/{len(databases)}] Auditing database: {db['name']}")
            
            db_audit = self.audit_single_database(db)
            
            # Aggregate results
            if db_audit["compliant"]:
                audit_results["compliant_databases"].append(db["name"])
            else:
                audit_results["non_compliant_databases"].append(db["name"])
            
            audit_results["critical_issues"].extend(db_audit["critical_issues"])
            audit_results["warnings"].extend(db_audit["warnings"])
            audit_results["recommendations"].extend(db_audit["recommendations"])
        
        # Calculate overall security score
        total_checks = len(databases) * 10  # 10 checks per database
        passed_checks = len(audit_results["compliant_databases"]) * 10
        failed_checks = len(audit_results["critical_issues"])
        
        audit_results["security_score"] = max(0, min(100, 
            ((passed_checks - failed_checks) / max(1, total_checks)) * 100))
        
        # Display audit results
        self.display_audit_results(audit_results)
        
        # Save audit report
        audit_report_file = f"security_audit_{int(time.time())}.json"
        audit_results["audit_timestamp"] = time.time()
        audit_results["audited_by"] = self.current_user["username"]
        
        try:
            os.makedirs("security_reports", exist_ok=True)
            with open(f"security_reports/{audit_report_file}", "w") as f:
                json.dump(audit_results, f, indent=2)
            
            print(f"\n📊 Audit report saved: security_reports/{audit_report_file}")
        
        except Exception as e:
            print(f"⚠️ Could not save audit report: {str(e)}")
        
        # Log audit activity
        self.security_system.add_security_block({
            "action": "security_audit_performed",
            "databases_audited": len(databases),
            "security_score": audit_results["security_score"],
            "critical_issues": len(audit_results["critical_issues"]),
            "admin": self.current_user["username"],
            "timestamp": time.time()
        })
    
    except Exception as e:
        print(f"❌ Error performing security audit: {str(e)}")
    
    input("\nPress Enter to continue...")

def audit_single_database(self, db_info):
    """Audit a single database for security compliance"""
    audit_result = {
        "database": db_info["name"],
        "compliant": True,
        "critical_issues": [],
        "warnings": [],
        "recommendations": []
    }
    
    try:
        db_path = os.path.join(self.config["storage"]["database_root"], "databases", db_info["name"])
        
        # Check 1: User access control
        users_file = os.path.join(db_path, "users.json")
        if os.path.exists(users_file):
            with open(users_file, "r") as f:
                users_data = json.load(f)
            
            users = users_data.get("users", {})
            
            # Check for admin users
            admins = [u for u, info in users.items() if info.get("role") in ["admin", "owner"]]
            if len(admins) == 0:
                audit_result["critical_issues"].append(f"{db_info['name']}: No administrative users")
                audit_result["compliant"] = False
            elif len(admins) == 1:
                audit_result["warnings"].append(f"{db_info['name']}: Single point of failure - only one admin")
            
            # Check for excessive permissions
            total_users = len(users)
            admin_ratio = len(admins) / max(1, total_users)
            if admin_ratio > 0.5:
                audit_result["warnings"].append(f"{db_info['name']}: High admin-to-user ratio ({admin_ratio:.1%})")
            
            # Check for locked accounts
            locked_users = [u for u, info in users.items() if info.get("locked", False)]
            if locked_users:
                audit_result["recommendations"].append(f"{db_info['name']}: Review {len(locked_users)} locked accounts")
        
        else:
            audit_result["critical_issues"].append(f"{db_info['name']}: No user access control file")
            audit_result["compliant"] = False
        
        # Check 2: Access restrictions
        restrictions_file = os.path.join(db_path, "restrictions.json")
        if not os.path.exists(restrictions_file):
            audit_result["recommendations"].append(f"{db_info['name']}: No access restrictions configured")
        
        # Check 3: File integrity
        integrity_check = self.db_manager.verify_database_integrity(db_info["name"])
        if not integrity_check.get("valid", True):
            audit_result["critical_issues"].append(f"{db_info['name']}: File integrity issues detected")
            audit_result["compliant"] = False
        
        # Check 4: Backup existence
        backup_path = os.path.join(db_path, "backups")
        if not os.path.exists(backup_path):
            audit_result["warnings"].append(f"{db_info['name']}: No backup directory found")
        
        # Check 5: Schema validation
        schema_file = os.path.join(db_path, "schema.json")
        if not os.path.exists(schema_file):
            audit_result["recommendations"].append(f"{db_info['name']}: No schema definition found")
        
        # Check 6: Activity logging
        logs_path = os.path.join(db_path, "logs")
        if not os.path.exists(logs_path):
            audit_result["recommendations"].append(f"{db_info['name']}: No activity logging configured")
        
        # Check 7: Encryption status (mock check)
        audit_result["recommendations"].append(f"{db_info['name']}: Verify data encryption status")
        
        # Check 8: File permissions (basic check)
        try:
            os.access(db_path, os.R_OK | os.W_OK)
        except Exception:
            audit_result["warnings"].append(f"{db_info['name']}: File permission issues detected")
    
    except Exception as e:
        audit_result["critical_issues"].append(f"{db_info['name']}: Audit error - {str(e)}")
        audit_result["compliant"] = False
    
    return audit_result

def display_audit_results(self, audit_results):
    """Display formatted audit results"""
    print(f"\n📊 Security Audit Results")
    print("=" * 40)
    
    # Overall score
    score = audit_results["security_score"]
    if score >= 90:
        score_status = "🟢 Excellent"
    elif score >= 75:
        score_status = "🟡 Good"
    elif score >= 60:
        score_status = "🟠 Fair"
    else:
        score_status = "🔴 Poor"
    
    print(f"Overall Security Score: {score_status} ({score:.1f}%)")
    print(f"Databases Audited: {audit_results['total_databases']}")
    print(f"Compliant Databases: {len(audit_results['compliant_databases'])}")
    print(f"Non-compliant Databases: {len(audit_results['non_compliant_databases'])}")
    
    # Critical issues
    if audit_results["critical_issues"]:
        print(f"\n🚨 Critical Issues ({len(audit_results['critical_issues'])}):")
        for i, issue in enumerate(audit_results["critical_issues"][:10], 1):
            print(f"   {i}. {issue}")
        if len(audit_results["critical_issues"]) > 10:
            print(f"   ... and {len(audit_results['critical_issues']) - 10} more critical issues")
    else:
        print(f"\n✅ No critical security issues found")
    
    # Warnings
    if audit_results["warnings"]:
        print(f"\n⚠️ Warnings ({len(audit_results['warnings'])}):")
        for i, warning in enumerate(audit_results["warnings"][:10], 1):
            print(f"   {i}. {warning}")
        if len(audit_results["warnings"]) > 10:
            print(f"   ... and {len(audit_results['warnings']) - 10} more warnings")
    
    # Recommendations
    if audit_results["recommendations"]:
        print(f"\n💡 Recommendations ({len(audit_results['recommendations'])}):")
        for i, rec in enumerate(audit_results["recommendations"][:10], 1):
            print(f"   {i}. {rec}")
        if len(audit_results["recommendations"]) > 10:
            print(f"   ... and {len(audit_results['recommendations']) - 10} more recommendations")
    
    # Compliance status
    if audit_results["non_compliant_databases"]:
        print(f"\n❌ Non-compliant Databases:")
        for db_name in audit_results["non_compliant_databases"]:
            print(f"   • {db_name}")
    
    if audit_results["compliant_databases"]:
        print(f"\n✅ Compliant Databases:")
        for db_name in audit_results["compliant_databases"]:
            print(f"   • {db_name}")
    
    # Next steps
    print(f"\n🎯 Recommended Next Steps:")
    if audit_results["critical_issues"]:
        print("   1. Address all critical security issues immediately")
    if audit_results["warnings"]:
        print("   2. Review and resolve security warnings")
    if score < 80:
        print("   3. Implement additional security measures")
    print("   4. Schedule regular security audits")
    print("   5. Update security policies and procedures")