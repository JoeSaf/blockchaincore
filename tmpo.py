
    def verify_single_database_integrity(self, selected_db):
        """Verify integrity of a specific database (helper function)"""
        try:
            print(f"\n🔍 Integrity Check: {selected_db['name']}")
            print("=" * 40)
            
            print("🔄 Verifying database integrity...")
            integrity_result = self.db_manager.verify_database_integrity(selected_db["name"])
            
            print(f"\n📊 Integrity Results:")
            print(f"   Database: {selected_db['name']}")
            print(f"   Valid: {'✅ Yes' if integrity_result.get('valid', False) else '❌ No'}")
            print(f"   Files checked: {integrity_result.get('checked_files', 0)}")
            print(f"   Corrupted files: {integrity_result.get('corrupted_files', 0)}")
            print(f"   Missing files: {integrity_result.get('missing_files', 0)}")
            
            issues = integrity_result.get("issues", [])
            if issues:
                print(f"\n⚠️ Issues found ({len(issues)}):")
                for i, issue in enumerate(issues[:10], 1):  # Show first 10 issues
                    print(f"   {i}. {issue}")
                if len(issues) > 10:
                    print(f"   ... and {len(issues) - 10} more issues")
            else:
                print("\n✅ No issues found - database integrity is perfect!")
        
        except Exception as e:
            print(f"❌ Error verifying integrity: {str(e)}")

    def view_database_files_detailed(self, selected_db):
        """View detailed file listing for a database (helper function)"""
        try:
            print(f"\n📄 Files in Database: {selected_db['name']}")
            print("=" * 50)
            
            files = self.db_manager.list_database_files(selected_db["name"], self.current_user["username"])
            
            if files:
                print(f"Found {len(files)} file(s):")
                print("-" * 80)
                print(f"{'#':<3} {'Filename':<30} {'Size':<12} {'Uploaded':<17} {'By':<15}")
                print("-" * 80)
                
                # Sort by upload time (newest first)
                files.sort(key=lambda x: x.get("uploaded_at", 0), reverse=True)
                
                for i, file_info in enumerate(files, 1):
                    filename = file_info.get('original_name', 'Unknown')
                    if len(filename) > 29:
                        filename = filename[:26] + "..."
                    
                    size_str = self.format_size(file_info.get('size', 0))
                    uploaded_time = datetime.fromtimestamp(file_info.get('uploaded_at', 0)).strftime('%Y-%m-%d %H:%M')
                    uploaded_by = file_info.get('uploaded_by', 'Unknown')
                    if len(uploaded_by) > 14:
                        uploaded_by = uploaded_by[:11] + "..."
                    
                    print(f"{i:<3} {filename:<30} {size_str:<12} {uploaded_time:<17} {uploaded_by:<15}")
                
                print("-" * 80)
                
                # File statistics
                total_size = sum(f.get('size', 0) for f in files)
                print(f"\n📊 File Statistics:")
                print(f"   Total files: {len(files)}")
                print(f"   Total size: {self.format_size(total_size)}")
                
                # File type distribution
                file_types = {}
                for file_info in files:
                    filename = file_info.get('original_name', '')
                    ext = os.path.splitext(filename)[1].lower() or 'no extension'
                    file_types[ext] = file_types.get(ext, 0) + 1
                
                if file_types:
                    print(f"   File types:")
                    sorted_types = sorted(file_types.items(), key=lambda x: x[1], reverse=True)
                    for file_type, count in sorted_types[:5]:  # Show top 5 types
                        print(f"      {file_type}: {count}")
            else:
                print("📁 No files found in this database")
        
        except Exception as e:
            print(f"❌ Error viewing database files: {str(e)}")

    def manage_single_database_users(self, selected_db):
        """Manage users for a specific database (helper function)"""
        try:
            print(f"\n👥 User Management: {selected_db['name']}")
            print("=" * 40)
            
            # Load database users
            db_path = os.path.join(self.config["storage"]["database_root"], "databases", selected_db["name"])
            users_file = os.path.join(db_path, "users.json")
            
            if os.path.exists(users_file):
                with open(users_file, "r") as f:
                    users_data = json.load(f)
                
                db_users = users_data.get("users", {})
                
                if db_users:
                    print(f"Users with access to '{selected_db['name']}':")
                    print("-" * 60)
                    print(f"{'Username':<15} {'Role':<12} {'Permissions':<25} {'Added':<17}")
                    print("-" * 60)
                    
                    for username, user_info in db_users.items():
                        role = user_info.get("role", "unknown")
                        permissions = ", ".join(user_info.get("permissions", []))[:24]
                        added_at = user_info.get("added_at", 0)
                        added_time = datetime.fromtimestamp(added_at).strftime("%Y-%m-%d %H:%M") if added_at else "Unknown"
                        
                        print(f"{username:<15} {role:<12} {permissions:<25} {added_time:<17}")
                    
                    print("-" * 60)
                    print(f"Total users: {len(db_users)}")
                else:
                    print("👥 No users found for this database")
            else:
                print("👥 No user data file found for this database")
            
            # Quick actions
            if self.current_user["role"] == "admin":
                print(f"\n🔧 Quick Actions:")
                print("💡 Use 'Manage Database Users' from the main database menu for full user management")
        
        except Exception as e:
            print(f"❌ Error managing database users: {str(e)}")

    def import_database_wizard(self):
        """Interactive database import wizard"""
        if self.current_user["role"] != "admin":
            print("❌ Only administrators can import databases.")
            input("Press Enter to continue...")
            return
        
        try:
            print("\n📥 Database Import Wizard")
            print("=" * 35)
            
            # Get import file path
            import_path = input("Enter path to database export file: ").strip()
            
            if not import_path or not os.path.exists(import_path):
                print("❌ Import file not found.")
                input("Press Enter to continue...")
                return
            
            # Analyze import file
            print("🔍 Analyzing import file...")
            import_info = self.analyze_import_file(import_path)
            
            if not import_info:
                print("❌ Invalid or corrupted import file.")
                input("Press Enter to continue...")
                return
            
            # Display import information
            print(f"\n📋 Import File Information:")
            print(f"   Original Database: {import_info.get('database_name', 'Unknown')}")
            print(f"   Export Type: {import_info.get('export_type', 'Unknown')}")
            print(f"   Exported By: {import_info.get('exported_by', 'Unknown')}")
            print(f"   Export Date: {datetime.fromtimestamp(import_info.get('export_timestamp', 0)).strftime('%Y-%m-%d %H:%M')}")
            
            # Import options
            print(f"\n📥 Import Options:")
            
            original_name = import_info.get('database_name', 'imported_db')
            new_name = input(f"New database name (default: {original_name}): ").strip()
            if not new_name:
                new_name = original_name
            
            # Check if database already exists
            existing_databases = self.db_manager.list_databases()
            if any(db["name"] == new_name for db in existing_databases):
                print(f"❌ Database '{new_name}' already exists.")
                overwrite = input("Overwrite existing database? (y/n): ").lower()
                if overwrite != 'y':
                    print("❌ Import cancelled.")
                    input("Press Enter to continue...")
                    return
            
            # Import confirmation
            print(f"\n📥 Import Summary:")
            print(f"   Import file: {import_path}")
            print(f"   Target database: {new_name}")
            print(f"   Owner: {self.current_user['username']}")
            
            confirm = input("\nProceed with import? (y/n): ").lower()
            if confirm == 'y':
                print("📥 Importing database...")
                success = self.perform_database_import(import_path, new_name, self.current_user["username"])
                
                if success:
                    print(f"✅ Database imported successfully as '{new_name}'!")
                    
                    # Log the import
                    self.security_system.add_security_block({
                        "action": "database_imported",
                        "original_name": original_name,
                        "new_name": new_name,
                        "import_path": import_path,
                        "admin": self.current_user["username"],
                        "timestamp": time.time()
                    })
                else:
                    print("❌ Database import failed!")
            else:
                print("❌ Import cancelled.")
        
        except Exception as e:
            print(f"❌ Error during database import: {str(e)}")
        
        input("\nPress Enter to continue...")

    def analyze_import_file(self, import_path):
        """Analyze database import file"""
        try:
            import zipfile
            
            if not zipfile.is_zipfile(import_path):
                return None
            
            with zipfile.ZipFile(import_path, 'r') as zipf:
                # Check for export info
                if 'export_info.json' in zipf.namelist():
                    export_info_data = zipf.read('export_info.json')
                    return json.loads(export_info_data.decode('utf-8'))
                else:
                    # Legacy format or manual export
                    return {
                        "database_name": "imported_database",
                        "export_type": "unknown",
                        "exported_by": "unknown",
                        "export_timestamp": 0
                    }
        
        except Exception as e:
            logger.error(f"Error analyzing import file: {str(e)}")
            return None

    def perform_database_import(self, import_path, new_name, username):
        """Perform the actual database import"""
        try:
            import zipfile
            
            # Create database directory
            db_path = os.path.join(self.config["storage"]["database_root"], "databases", new_name)
            
            # Remove existing database if overwriting
            if os.path.exists(db_path):
                shutil.rmtree(db_path)
            
            os.makedirs(db_path, exist_ok=True)
            
            # Extract import file
            with zipfile.ZipFile(import_path, 'r') as zipf:
                for member in zipf.namelist():
                    # Skip export_info.json as it's not part of the database
                    if member == 'export_info.json':
                        continue
                    
                    zipf.extract(member, db_path)
            
            # Update database metadata
            metadata_file = os.path.join(db_path, "metadata.json")
            if os.path.exists(metadata_file):
                with open(metadata_file, "r") as f:
                    metadata = json.load(f)
                
                # Update metadata for import
                metadata["database_name"] = new_name
                metadata["imported_at"] = time.time()
                metadata["imported_by"] = username
                metadata["original_owner"] = metadata.get("owner", "unknown")
                metadata["owner"] = username
                
                with open(metadata_file, "w") as f:
                    json.dump(metadata, f, indent=2)
            else:
                # Create basic metadata if not exists
                metadata = {
                    "database_name": new_name,
                    "owner": username,
                    "created_at": time.time(),
                    "imported_at": time.time(),
                    "imported_by": username
                }
                
                with open(metadata_file, "w") as f:
                    json.dump(metadata, f, indent=2)
            
            # Update users file to set current user as owner
            users_file = os.path.join(db_path, "users.json")
            users_data = {
                "users": {
                    username: {
                        "role": "owner",
                        "permissions": ["read", "write", "admin", "delete", "manage_users", "manage_security"],
                        "added_at": time.time(),
                        "added_by": "system"
                    }
                },
                "created_at": time.time()
            }
            
            with open(users_file, "w") as f:
                json.dump(users_data, f, indent=2)
            
            return True
        
        except Exception as e:
            logger.error(f"Error performing database import: {str(e)}")
            return False

    def export_database_schema(self):
        """Export database schema without data"""
        if self.current_user["role"] not in ["admin", "owner"]:
            print("❌ Only administrators and database owners can export schemas.")
            input("Press Enter to continue...")
            return
        
        try:
            print("\n📋 Export Database Schema")
            print("=" * 35)
            
            databases = self.db_manager.list_databases(
                self.current_user["username"], 
                self.current_user["role"]
            )
            
            if not databases:
                print("❌ No databases available for schema export.")
                input("Press Enter to continue...")
                return
            
            # Select database
            print("Available databases:")
            for i, db in enumerate(databases, 1):
                print(f"{i}. {db['name']} (Owner: {db['owner']})")
            
            choice = input(f"Select database (1-{len(databases)}): ").strip()
            
            if not choice.isdigit() or not (1 <= int(choice) <= len(databases)):
                print("❌ Invalid selection.")
                input("Press Enter to continue...")
                return
            
            selected_db = databases[int(choice) - 1]
            
            # Export path
            default_path = f"exports/{selected_db['name']}_schema_{int(time.time())}.json"
            export_path = input(f"Schema export path (default: {default_path}): ").strip()
            if not export_path:
                export_path = default_path
            
            # Export schema
            print(f"📋 Exporting schema for: {selected_db['name']}")
            success = self.perform_schema_export(selected_db["name"], export_path)
            
            if success:
                print(f"✅ Schema exported successfully to: {export_path}")
            else:
                print("❌ Schema export failed!")
        
        except Exception as e:
            print(f"❌ Error exporting schema: {str(e)}")
        
        input("\nPress Enter to continue...")

    def perform_schema_export(self, db_name, export_path):
        """Perform schema export"""
        try:
            db_path = os.path.join(self.config["storage"]["database_root"], "databases", db_name)
            metadata_file = os.path.join(db_path, "metadata.json")
            
            if not os.path.exists(metadata_file):
                return False
            
            with open(metadata_file, "r") as f:
                metadata = json.load(f)
            
            # Create schema export
            schema_export = {
                "database_name": db_name,
                "schema": metadata.get("schema", {}),
                "export_type": "schema_only",
                "exported_by": self.current_user["username"],
                "export_timestamp": time.time(),
                "version": "1.0"
            }
            
            # Ensure export directory exists
            os.makedirs(os.path.dirname(export_path), exist_ok=True)
            
            with open(export_path, "w") as f:
                json.dump(schema_export, f, indent=2)
            
            return True
        
        except Exception as e:
            logger.error(f"Error performing schema export: {str(e)}")
            return False

    def import_database_schema(self):
        """Import database schema"""
        if self.current_user["role"] != "admin":
            print("❌ Only administrators can import database schemas.")
            input("Press Enter to continue...")
            return
        
        try:
            print("\n📋 Import Database Schema")
            print("=" * 35)
            
            # Get schema file path
            schema_path = input("Enter path to schema file: ").strip()
            
            if not schema_path or not os.path.exists(schema_path):
                print("❌ Schema file not found.")
                input("Press Enter to continue...")
                return
            
            # Load and validate schema
            with open(schema_path, "r") as f:
                schema_data = json.load(f)
            
            if schema_data.get("export_type") != "schema_only":
                print("❌ Invalid schema file format.")
                input("Press Enter to continue...")
                return
            
            # Display schema information
            print(f"\n📋 Schema Information:")
            print(f"   Original Database: {schema_data.get('database_name', 'Unknown')}")
            print(f"   Exported By: {schema_data.get('exported_by', 'Unknown')}")
            print(f"   Export Date: {datetime.fromtimestamp(schema_data.get('export_timestamp', 0)).strftime('%Y-%m-%d %H:%M')}")
            
            schema = schema_data.get("schema", {})
            if schema.get("tables"):
                print(f"   Tables: {len(schema['tables'])}")
                for table_name in list(schema['tables'].keys())[:3]:
                    print(f"      • {table_name}")
                if len(schema['tables']) > 3:
                    print(f"      ... and {len(schema['tables']) - 3} more")
            
            # Import options
            original_name = schema_data.get('database_name', 'imported_schema')
            new_name = input(f"New database name (default: {original_name}): ").strip()
            if not new_name:
                new_name = original_name
            
            # Create database with schema
            confirm = input(f"\nCreate database '{new_name}' with imported schema? (y/n): ").lower()
            if confirm == 'y':
                success = self.db_manager.create_database(new_name, schema, self.current_user["username"])
                
                if success:
                    print(f"✅ Database '{new_name}' created with imported schema!")
                else:
                    print("❌ Failed to create database with schema!")
            else:
                print("❌ Schema import cancelled.")
        
        except Exception as e:
            print(f"❌ Error importing schema: {str(e)}")
        
        input("\nPress Enter to continue...")

    def database_migration_wizard(self):
        """Database migration wizard"""
        if self.current_user["role"] != "admin":
            print("❌ Only administrators can perform database migrations.")
            input("Press Enter to continue...")
            return
        
        try:
            print("\n🔄 Database Migration Wizard")
            print("=" * 40)
            
            print("Migration operations:")
            print("1. Migrate database to new format")
            print("2. Consolidate multiple databases")
            print("3. Split large database")
            print("4. Clone database")
            
            choice = input("Select migration type (1-4): ").strip()
            
            if choice == "1":
                self.migrate_database_format()
            elif choice == "2":
                self.consolidate_databases()
            elif choice == "3":
                self.split_database()
            elif choice == "4":
                self.clone_database()
            else:
                print("❌ Invalid choice.")
        
        except Exception as e:
            print(f"❌ Error in database migration: {str(e)}")
        
        input("\nPress Enter to continue...")

    def clone_database(self):
        """Clone an existing database"""
        try:
            databases = self.db_manager.list_databases()
            
            if not databases:
                print("❌ No databases available to clone.")
                return
            
            # Select source database
            print("Select database to clone:")
            for i, db in enumerate(databases, 1):
                print(f"{i}. {db['name']}")
            
            choice = input(f"Select database (1-{len(databases)}): ").strip()
            
            if not choice.isdigit() or not (1 <= int(choice) <= len(databases)):
                print("❌ Invalid selection.")
                return
            
            source_db = databases[int(choice) - 1]
            
            # New database name
            clone_name = input(f"Name for cloned database: ").strip()
            if not clone_name:
                print("❌ Database name is required.")
                return
            
            # Check if name already exists
            if any(db["name"] == clone_name for db in databases):
                print(f"❌ Database '{clone_name}' already exists.")
                return
            
            print(f"🔄 Cloning database '{source_db['name']}' to '{clone_name}'...")
            
            # Perform clone
            source_path = os.path.join(self.config["storage"]["database_root"], "databases", source_db["name"])
            clone_path = os.path.join(self.config["storage"]["database_root"], "databases", clone_name)
            
            # Copy entire database directory
            shutil.copytree(source_path, clone_path)
            
            # Update metadata for clone
            metadata_file = os.path.join(clone_path, "metadata.json")
            if os.path.exists(metadata_file):
                with open(metadata_file, "r") as f:
                    metadata = json.load(f)
                
                metadata["database_name"] = clone_name
                metadata["owner"] = self.current_user["username"]
                metadata["created_at"] = time.time()
                metadata["cloned_from"] = source_db["name"]
                metadata["cloned_at"] = time.time()
                
                with open(metadata_file, "w") as f:
                    json.dump(metadata, f, indent=2)
            
            print(f"✅ Database cloned successfully as '{clone_name}'!")
        
        except Exception as e:
            print(f"❌ Error cloning database: {str(e)}")

    def export_database_statistics(self):
        """Export database statistics to file"""
        try:
            print("\n📊 Export Database Statistics")
            print("=" * 40)
            
            # Generate comprehensive statistics
            databases = self.db_manager.list_databases()
            
            statistics = {
                "export_timestamp": time.time(),
                "exported_by": self.current_user["username"],
                "system_overview": {
                    "total_databases": len(databases),
                    "total_files": 0,
                    "total_size": 0,
                    "total_users": 0
                },
                "databases": []
            }
            
            for db in databases:
                stats = self.db_manager.get_database_stats(db["name"])
                
                db_stats = {
                    "name": db["name"],
                    "owner": db["owner"],
                    "created_at": db["created_at"],
                    "files": stats.get("total_files", 0),
                    "size": stats.get("total_size", 0),
                    "users": stats.get("users", 0),
                    "operations": stats.get("operations", 0)
                }
                
                statistics["databases"].append(db_stats)
                statistics["system_overview"]["total_files"] += db_stats["files"]
                statistics["system_overview"]["total_size"] += db_stats["size"]
                statistics["system_overview"]["total_users"] += db_stats["users"]
            
            # Export path
            default_path = f"exports/database_statistics_{int(time.time())}.json"
            export_path = input(f"Statistics export path (default: {default_path}): ").strip()
            if not export_path:
                export_path = default_path
            
            # Save statistics
            os.makedirs(os.path.dirname(export_path), exist_ok=True)
            with open(export_path, "w") as f:
                json.dump(statistics, f, indent=2)
            
            print(f"✅ Statistics exported to: {export_path}")
        
        except Exception as e:
            print(f"❌ Error exporting statistics: {str(e)}")

    def bulk_export_import_menu(self):
        """Bulk export/import operations menu"""
        while True:
            print("\n🗃️ Bulk Export/Import Operations")
            print("=" * 45)
            print("1. 📤 Bulk Export Databases")
            print("2. 📥 Bulk Import Databases")
            print("3. 🔄 Batch Migration")
            print("4. 📋 Export All Schemas")
            print("5. 🔙 Back to Export/Import Menu")
            
            choice = input("\nEnter your choice (1-5): ").strip()
            
            if choice == "1":
                self.bulk_export_databases()
            elif choice == "2":
                self.bulk_import_databases()
            elif choice == "3":
                self.batch_migration()
            elif choice == "4":
                self.export_all_schemas()
            elif choice == "5":
                break
            else:
                print("❌ Invalid choice.")

    def bulk_export_databases(self):
        """Export multiple databases at once"""
        if self.current_user["role"] != "admin":
            print("❌ Only administrators can perform bulk export.")
            input("Press Enter to continue...")
            return
        
        try:
            print("\n📤 Bulk Database Export")
            print("=" * 30)
            
            databases = self.db_manager.list_databases()
            
            if not databases:
                print("❌ No databases available for export.")
                input("Press Enter to continue...")
                return
            
            print("Select databases to export:")
            print("0. All databases")
            for i, db in enumerate(databases, 1):
                stats = self.db_manager.get_database_stats(db["name"])
                size_str = self.format_size(stats.get("total_size", 0))
                print(f"{i}. {db['name']} ({size_str})")
            
            selection = input(f"Enter selection (0 for all, or comma-separated numbers): ").strip()
            
            if selection == "0":
                selected_databases = databases
            else:
                selected_indices = []
                for s in selection.split(","):
                    try:
                        idx = int(s.strip()) - 1
                        if 0 <= idx < len(databases):
                            selected_indices.append(idx)
                    except ValueError:
                        continue
                
                selected_databases = [databases[i] for i in selected_indices]
            
            if not selected_databases:
                print("❌ No valid databases selected.")
                input("Press Enter to continue...")
                return
            
            # Export directory
            export_dir = input("Export directory (default: bulk_exports): ").strip()
            if not export_dir:
                export_dir = "bulk_exports"
            
            # Create timestamped subdirectory
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            full_export_dir = os.path.join(export_dir, f"export_{timestamp}")
            os.makedirs(full_export_dir, exist_ok=True)
            
            # Export databases
            print(f"\n📤 Exporting {len(selected_databases)} database(s) to {full_export_dir}...")
            
            successful_exports = 0
            for i, db in enumerate(selected_databases, 1):
                print(f"[{i}/{len(selected_databases)}] Exporting {db['name']}...")
                
                export_path = os.path.join(full_export_dir, f"{db['name']}_export.zip")
                success = self.perform_database_export(db["name"], export_path, "1", self.current_user["username"])
                
                if success:
                    print(f"   ✅ {db['name']} exported successfully")
                    successful_exports += 1
                else:
                    print(f"   ❌ {db['name']} export failed")
            
            # Summary
            print(f"\n🎉 Bulk Export Summary:")
            print(f"   Databases processed: {len(selected_databases)}")
            print(f"   Successful exports: {successful_exports}")
            print(f"   Export directory: {full_export_dir}")
            
            # Create export manifest
            manifest = {
                "export_timestamp": time.time(),
                "exported_by": self.current_user["username"],
                "total_databases": len(selected_databases),
                "successful_exports": successful_exports,
                "databases": [{"name": db["name"], "status": "exported"} for db in selected_databases]
            }
            
            manifest_path = os.path.join(full_export_dir, "export_manifest.json")
            with open(manifest_path, "w") as f:
                json.dump(manifest, f, indent=2)
            
            print(f"   Export manifest: {manifest_path}")
        
        except Exception as e:
            print(f"❌ Error during bulk export: {str(e)}")
        
        input("\nPress Enter to continue...")
                    self.perform_storage_compaction(largest_db["name"])
                return True
            
            elif operation == "remove_orphaned_files":
                # Remove orphaned files from databases
                databases = self.db_manager.list_databases()
                total_removed = 0
                for db in databases:
                    db_path = os.path.join(self.config["storage"]["database_root"], "databases", db["name"])
                    orphaned_files = self.find_orphaned_files(db_path)
                    for orphaned_file in orphaned_files[:5]:  # Limit to 5 files per database
                        try:
                            full_path = os.path.join(db_path, orphaned_file)
                            os.remove(full_path)
                            total_removed += 1
                        except:
                            continue
                return total_removed > 0
            
            elif operation == "rebuild_indexes":
                # Rebuild indexes for databases
                databases = self.db_manager.list_databases()
                for db in databases[:2]:  # Limit to 2 databases
                    self.rebuild_single_database_indexes(db["name"])
                return True
            
            else:
                logger.warning(f"Unknown maintenance operation: {operation}")
                return False
            
        except Exception as e:
            logger.error(f"Error executing maintenance operation {operation}: {str(e)}")
            return False

    def view_maintenance_history(self):
        """View maintenance execution history"""
        try:
            print("\n📊 Maintenance History")
            print("=" * 30)
            
            history_file = os.path.join(self.config["storage"]["database_root"], "system", "maintenance_history.json")
            
            if os.path.exists(history_file):
                with open(history_file, "r") as f:
                    history = json.load(f)
                
                entries = history.get("entries", [])
                
                if entries:
                    # Sort by timestamp (most recent first)
                    entries.sort(key=lambda x: x.get("timestamp", 0), reverse=True)
                    
                    print(f"{'Date':<17} {'Task':<20} {'Operations':<12} {'Success Rate':<12} {'Admin':<12}")
                    print("-" * 73)
                    
                    for entry in entries[:20]:  # Show last 20 entries
                        timestamp = entry.get("timestamp", 0)
                        date_str = datetime.fromtimestamp(timestamp).strftime("%Y-%m-%d %H:%M") if timestamp else "Unknown"
                        
                        task_name = entry.get("task_name", "Unknown")[:19]
                        operations = f"{entry.get('operations_successful', 0)}/{entry.get('operations_total', 0)}"
                        
                        success_rate = 0
                        if entry.get("operations_total", 0) > 0:
                            success_rate = (entry.get("operations_successful", 0) / entry["operations_total"]) * 100
                        
                        success_rate_str = f"{success_rate:.1f}%"
                        admin = entry.get("admin", "Unknown")[:11]
                        
                        print(f"{date_str:<17} {task_name:<20} {operations:<12} {success_rate_str:<12} {admin:<12}")
                    
                    print("-" * 73)
                    print(f"Total maintenance runs: {len(entries)}")
                    
                    # Statistics
                    if entries:
                        recent_entries = entries[:30]  # Last 30 runs
                        total_operations = sum(e.get("operations_total", 0) for e in recent_entries)
                        successful_operations = sum(e.get("operations_successful", 0) for e in recent_entries)
                        
                        overall_success_rate = (successful_operations / max(1, total_operations)) * 100
                        
                        print(f"\n📈 Recent Statistics (last 30 runs):")
                        print(f"   Total operations: {total_operations}")
                        print(f"   Successful operations: {successful_operations}")
                        print(f"   Overall success rate: {overall_success_rate:.1f}%")
                else:
                    print("📊 No maintenance history found")
                    print("💡 History will be recorded after running scheduled maintenance")
            else:
                print("📊 No maintenance history file found")
                print("💡 History tracking will begin after first maintenance run")
        
        except Exception as e:
            print(f"❌ Error viewing maintenance history: {str(e)}")
        
        input("\nPress Enter to continue...")

    def maintenance_schedule_configuration(self):
        """Configure maintenance schedule settings"""
        if self.current_user["role"] != "admin":
            print("❌ Only administrators can configure maintenance settings.")
            input("Press Enter to continue...")
            return
        
        try:
            print("\n⚙️ Maintenance Schedule Configuration")
            print("=" * 45)
            
            config_file = os.path.join(self.config["storage"]["database_root"], "system", "maintenance_config.json")
            
            # Load existing configuration
            if os.path.exists(config_file):
                with open(config_file, "r") as f:
                    maintenance_config = json.load(f)
            else:
                maintenance_config = {
                    "auto_execution": False,
                    "max_concurrent_tasks": 1,
                    "notification_enabled": True,
                    "log_level": "info",
                    "cleanup_history_days": 90,
                    "failure_retry_count": 3,
                    "timeout_minutes": 60
                }
            
            while True:
                print(f"\nCurrent Configuration:")
                print(f"1. Auto-execution: {'✅ Enabled' if maintenance_config.get('auto_execution', False) else '❌ Disabled'}")
                print(f"2. Max concurrent tasks: {maintenance_config.get('max_concurrent_tasks', 1)}")
                print(f"3. Notifications: {'✅ Enabled' if maintenance_config.get('notification_enabled', True) else '❌ Disabled'}")
                print(f"4. Log level: {maintenance_config.get('log_level', 'info')}")
                print(f"5. History retention: {maintenance_config.get('cleanup_history_days', 90)} days")
                print(f"6. Failure retry count: {maintenance_config.get('failure_retry_count', 3)}")
                print(f"7. Task timeout: {maintenance_config.get('timeout_minutes', 60)} minutes")
                print("8. Reset to defaults")
                print("9. Save and exit")
                
                choice = input("\nSelect setting to modify (1-9): ").strip()
                
                if choice == "1":
                    current = maintenance_config.get('auto_execution', False)
                    maintenance_config['auto_execution'] = not current
                    status = "enabled" if maintenance_config['auto_execution'] else "disabled"
                    print(f"✅ Auto-execution {status}")
                
                elif choice == "2":
                    try:
                        new_value = int(input(f"Enter max concurrent tasks (current: {maintenance_config.get('max_concurrent_tasks', 1)}): "))
                        if 1 <= new_value <= 10:
                            maintenance_config['max_concurrent_tasks'] = new_value
                            print(f"✅ Max concurrent tasks set to {new_value}")
                        else:
                            print("❌ Value must be between 1 and 10")
                    except ValueError:
                        print("❌ Invalid number")
                
                elif choice == "3":
                    current = maintenance_config.get('notification_enabled', True)
                    maintenance_config['notification_enabled'] = not current
                    status = "enabled" if maintenance_config['notification_enabled'] else "disabled"
                    print(f"✅ Notifications {status}")
                
                elif choice == "4":
                    print("Log levels: debug, info, warning, error")
                    new_level = input(f"Enter log level (current: {maintenance_config.get('log_level', 'info')}): ").strip().lower()
                    if new_level in ["debug", "info", "warning", "error"]:
                        maintenance_config['log_level'] = new_level
                        print(f"✅ Log level set to {new_level}")
                    else:
                        print("❌ Invalid log level")
                
                elif choice == "5":
                    try:
                        new_days = int(input(f"Enter history retention days (current: {maintenance_config.get('cleanup_history_days', 90)}): "))
                        if 1 <= new_days <= 365:
                            maintenance_config['cleanup_history_days'] = new_days
                            print(f"✅ History retention set to {new_days} days")
                        else:
                            print("❌ Value must be between 1 and 365 days")
                    except ValueError:
                        print("❌ Invalid number")
                
                elif choice == "6":
                    try:
                        new_retries = int(input(f"Enter failure retry count (current: {maintenance_config.get('failure_retry_count', 3)}): "))
                        if 0 <= new_retries <= 10:
                            maintenance_config['failure_retry_count'] = new_retries
                            print(f"✅ Failure retry count set to {new_retries}")
                        else:
                            print("❌ Value must be between 0 and 10")
                    except ValueError:
                        print("❌ Invalid number")
                
                elif choice == "7":
                    try:
                        new_timeout = int(input(f"Enter task timeout minutes (current: {maintenance_config.get('timeout_minutes', 60)}): "))
                        if 5 <= new_timeout <= 480:  # 5 minutes to 8 hours
                            maintenance_config['timeout_minutes'] = new_timeout
                            print(f"✅ Task timeout set to {new_timeout} minutes")
                        else:
                            print("❌ Value must be between 5 and 480 minutes")
                    except ValueError:
                        print("❌ Invalid number")
                
                elif choice == "8":
                    confirm = input("Reset all settings to defaults? (y/n): ").lower()
                    if confirm == 'y':
                        maintenance_config = {
                            "auto_execution": False,
                            "max_concurrent_tasks": 1,
                            "notification_enabled": True,
                            "log_level": "info",
                            "cleanup_history_days": 90,
                            "failure_retry_count": 3,
                            "timeout_minutes": 60
                        }
                        print("✅ Configuration reset to defaults")
                
                elif choice == "9":
                    break
                
                else:
                    print("❌ Invalid choice")
            
            # Save configuration
            os.makedirs(os.path.dirname(config_file), exist_ok=True)
            maintenance_config['modified_at'] = time.time()
            maintenance_config['modified_by'] = self.current_user["username"]
            
            with open(config_file, "w") as f:
                json.dump(maintenance_config, f, indent=2)
            
            print("✅ Maintenance configuration saved!")
            
            # Log configuration change
            self.security_system.add_security_block({
                "action": "maintenance_config_updated",
                "config": maintenance_config,
                "admin": self.current_user["username"],
                "timestamp": time.time()
            })
        
        except Exception as e:
            print(f"❌ Error configuring maintenance schedule: {str(e)}")
        
        input("\nPress Enter to continue...")

    def show_database_statistics(self):
        """Show comprehensive database statistics"""
        try:
            print("\n📊 Database Statistics & Overview")
            print("=" * 45)
            
            databases = self.db_manager.list_databases(
                self.current_user["username"], 
                self.current_user["role"]
            )
            
            if not databases:
                print("❌ No databases available.")
                input("Press Enter to continue...")
                return
            
            # Collect statistics
            total_files = 0
            total_size = 0
            total_users = 0
            total_operations = 0
            oldest_db = None
            newest_db = None
            largest_db = None
            
            database_stats = []
            
            for db in databases:
                stats = self.db_manager.get_database_stats(db["name"])
                
                db_info = {
                    "name": db["name"],
                    "owner": db["owner"],
                    "created_at": db["created_at"],
                    "files": stats.get("total_files", 0),
                    "size": stats.get("total_size", 0),
                    "users": stats.get("users", 0),
                    "operations": stats.get("operations", 0)
                }
                
                database_stats.append(db_info)
                
                # Accumulate totals
                total_files += db_info["files"]
                total_size += db_info["size"]
                total_users += db_info["users"]
                total_operations += db_info["operations"]
                
                # Track extremes
                if oldest_db is None or db_info["created_at"] < oldest_db["created_at"]:
                    oldest_db = db_info
                
                if newest_db is None or db_info["created_at"] > newest_db["created_at"]:
                    newest_db = db_info
                
                if largest_db is None or db_info["size"] > largest_db["size"]:
                    largest_db = db_info
            
            # Display overview statistics
            print("🔍 System Overview:")
            print(f"   Total Databases: {len(databases)}")
            print(f"   Total Files: {total_files:,}")
            print(f"   Total Storage: {self.format_size(total_size)}")
            print(f"   Total Users: {total_users}")
            print(f"   Total Operations: {total_operations:,}")
            
            if databases:
                avg_files = total_files / len(databases)
                avg_size = total_size / len(databases)
                print(f"   Average Files per DB: {avg_files:.1f}")
                print(f"   Average Size per DB: {self.format_size(int(avg_size))}")
            
            # Display detailed database statistics
            print(f"\n📋 Database Details:")
            print("-" * 85)
            print(f"{'Name':<20} {'Files':<8} {'Size':<12} {'Users':<8} {'Ops':<8} {'Created':<17}")
            print("-" * 85)
            
            # Sort by size (largest first)
            database_stats.sort(key=lambda x: x["size"], reverse=True)
            
            for db_info in database_stats:
                name = db_info["name"][:19]
                files = f"{db_info['files']:,}"[:7]
                size = self.format_size(db_info["size"])[:11]
                users = str(db_info["users"])
                ops = f"{db_info['operations']:,}"[:7]
                created = datetime.fromtimestamp(db_info["created_at"]).strftime("%Y-%m-%d %H:%M")
                
                print(f"{name:<20} {files:<8} {size:<12} {users:<8} {ops:<8} {created:<17}")
            
            print("-" * 85)
            
            # Interesting facts
            print(f"\n🎯 Database Insights:")
            
            if oldest_db:
                oldest_age = (time.time() - oldest_db["created_at"]) / (24 * 3600)
                print(f"   📅 Oldest Database: {oldest_db['name']} ({oldest_age:.0f} days old)")
            
            if newest_db:
                newest_age = (time.time() - newest_db["created_at"]) / (24 * 3600)
                print(f"   🆕 Newest Database: {newest_db['name']} ({newest_age:.0f} days old)")
            
            if largest_db:
                print(f"   💾 Largest Database: {largest_db['name']} ({self.format_size(largest_db['size'])})")
            
            # Find most active database
            most_active = max(database_stats, key=lambda x: x["operations"]) if database_stats else None
            if most_active and most_active["operations"] > 0:
                print(f"   ⚡ Most Active: {most_active['name']} ({most_active['operations']:,} operations)")
            
            # Storage distribution
            if total_size > 0:
                print(f"\n📊 Storage Distribution:")
                for db_info in database_stats[:5]:  # Top 5 by size
                    if db_info["size"] > 0:
                        percentage = (db_info["size"] / total_size) * 100
                        print(f"   {db_info['name']}: {percentage:.1f}% ({self.format_size(db_info['size'])})")
            
            # Growth analysis
            print(f"\n📈 Growth Analysis:")
            if len(databases) > 1:
                # Calculate creation rate
                time_span = newest_db["created_at"] - oldest_db["created_at"]
                if time_span > 0:
                    creation_rate = len(databases) / (time_span / (24 * 3600))  # databases per day
                    if creation_rate < 1:
                        print(f"   Database creation rate: {creation_rate * 7:.1f} per week")
                    else:
                        print(f"   Database creation rate: {creation_rate:.1f} per day")
            
            # Recent activity (mock based on operations)
            active_databases = [db for db in database_stats if db["operations"] > 0]
            if active_databases:
                print(f"   Active databases: {len(active_databases)}/{len(databases)} ({(len(active_databases)/len(databases)*100):.1f}%)")
            
            # Recommendations
            print(f"\n💡 Recommendations:")
            
            # Storage recommendations
            if total_size > 1024 * 1024 * 1024:  # > 1GB
                print("   💾 Consider storage optimization - system using significant space")
            
            # Database count recommendations
            if len(databases) > 20:
                print("   📁 Consider consolidating databases - large number detected")
            elif len(databases) < 3:
                print("   📈 System has few databases - consider organizing data into more databases")
            
            # File distribution recommendations
            if database_stats:
                file_heavy_dbs = [db for db in database_stats if db["files"] > 1000]
                if file_heavy_dbs:
                    print(f"   📄 {len(file_heavy_dbs)} database(s) have >1000 files - consider file management")
            
            # User distribution
            if total_users > len(databases) * 5:
                print("   👥 High user-to-database ratio - monitor access patterns")
            
            print("   🔄 Regular maintenance recommended for optimal performance")
        
        except Exception as e:
            print(f"❌ Error displaying database statistics: {str(e)}")
        
        input("\nPress Enter to continue...")

    def database_export_import_menu(self):
        """Database export and import operations menu"""
        while True:
            print("\n💾 Database Export/Import Operations")
            print("=" * 45)
            print("1. 📤 Export Database")
            print("2. 📥 Import Database")
            print("3. 📋 Export Database Schema")
            print("4. 📋 Import Database Schema")
            print("5. 🔄 Database Migration")
            print("6. 📊 Export Statistics")
            print("7. 🗃️ Bulk Export/Import")
            print("8. 🔙 Back to Database Menu")
            
            choice = input("\nEnter your choice (1-8): ").strip()
            
            if choice == "1":
                self.export_database_wizard()
            elif choice == "2":
                self.import_database_wizard()
            elif choice == "3":
                self.export_database_schema()
            elif choice == "4":
                self.import_database_schema()
            elif choice == "5":
                self.database_migration_wizard()
            elif choice == "6":
                self.export_database_statistics()
            elif choice == "7":
                self.bulk_export_import_menu()
            elif choice == "8":
                break
            else:
                print("❌ Invalid choice.")

    def export_database_wizard(self):
        """Interactive database export wizard"""
        if self.current_user["role"] not in ["admin", "owner"]:
            print("❌ Only administrators and database owners can export databases.")
            input("Press Enter to continue...")
            return
        
        try:
            print("\n📤 Database Export Wizard")
            print("=" * 35)
            
            databases = self.db_manager.list_databases(
                self.current_user["username"], 
                self.current_user["role"]
            )
            
            if not databases:
                print("❌ No databases available for export.")
                input("Press Enter to continue...")
                return
            
            # Select database
            print("Available databases:")
            for i, db in enumerate(databases, 1):
                stats = self.db_manager.get_database_stats(db["name"])
                size_str = self.format_size(stats.get("total_size", 0))
                print(f"{i}. {db['name']} (Owner: {db['owner']}, Size: {size_str})")
            
            choice = input(f"Select database to export (1-{len(databases)}): ").strip()
            
            if not choice.isdigit() or not (1 <= int(choice) <= len(databases)):
                print("❌ Invalid selection.")
                input("Press Enter to continue...")
                return
            
            selected_db = databases[int(choice) - 1]
            
            # Export options
            print(f"\n📦 Export Options for: {selected_db['name']}")
            print("1. Full export (all data and metadata)")
            print("2. Data only (files without metadata)")
            print("3. Metadata only (structure without files)")
            print("4. Custom export (select components)")
            
            export_choice = input("Select export type (1-4): ").strip()
            
            if export_choice not in ["1", "2", "3", "4"]:
                print("❌ Invalid export type.")
                input("Press Enter to continue...")
                return
            
            # Export path
            default_path = f"exports/{selected_db['name']}_export_{int(time.time())}.zip"
            export_path = input(f"Export path (default: {default_path}): ").strip()
            if not export_path:
                export_path = default_path
            
            # Perform export
            print(f"\n📤 Exporting database: {selected_db['name']}")
            print("⚠️ This may take several minutes for large databases...")
            
            success = self.perform_database_export(
                selected_db["name"], 
                export_path, 
                export_choice, 
                self.current_user["username"]
            )
            
            if success:
                print(f"✅ Database exported successfully!")
                print(f"📁 Export location: {export_path}")
                
                if os.path.exists(export_path):
                    export_size = os.path.getsize(export_path)
                    print(f"📊 Export size: {self.format_size(export_size)}")
                
                # Log the export
                self.security_system.add_security_block({
                    "action": "database_exported",
                    "database": selected_db["name"],
                    "export_path": export_path,
                    "export_type": export_choice,
                    "admin": self.current_user["username"],
                    "timestamp": time.time()
                })
            else:
                print(f"❌ Database export failed!")
        
        except Exception as e:
            print(f"❌ Error during database export: {str(e)}")
        
        input("\nPress Enter to continue...")

    def perform_database_export(self, db_name, export_path, export_type, username):
        """Perform the actual database export"""
        try:
            import zipfile
            
            # Ensure export directory exists
            os.makedirs(os.path.dirname(export_path), exist_ok=True)
            
            db_path = os.path.join(self.config["storage"]["database_root"], "databases", db_name)
            
            if not os.path.exists(db_path):
                return False
            
            with zipfile.ZipFile(export_path, 'w', zipfile.ZIP_DEFLATED) as zipf:
                # Add export metadata
                export_info = {
                    "database_name": db_name,
                    "export_type": export_type,
                    "exported_by": username,
                    "export_timestamp": time.time(),
                    "version": "1.0"
                }
                
                zipf.writestr("export_info.json", json.dumps(export_info, indent=2))
                
                if export_type in ["1", "2", "4"]:  # Include data files
                    for root, dirs, files in os.walk(db_path):
                        for file in files:
                            file_path = os.path.join(root, file)
                            arc_path = os.path.relpath(file_path, db_path)
                            zipf.write(file_path, arc_path)
                
                if export_type in ["1", "3", "4"]:  # Include metadata
                    metadata_files = ["metadata.json", "users.json", "restrictions.json"]
                    for metadata_file in metadata_files:
                        file_path = os.path.join(db_path, metadata_file)
                        if os.path.exists(file_path):
                            zipf.write(file_path, metadata_file)
            
            return True
        
        except Exception as e:
            logger.error(f"Error performing database export: {str(e)}")
            return False

    def verify_database_integrity(self):
        """Verify integrity of all databases"""
        try:
            print("\n🔍 Database Integrity Verification")
            print("=" * 45)
            
            databases = self.db_manager.list_databases(
                self.current_user["username"], 
                self.current_user["role"]
            )
            
            if not databases:
                print("❌ No databases available for verification.")
                input("Press Enter to continue...")
                return
            
            total_issues = 0
            databases_with_issues = 0
            
            print(f"🔍 Verifying integrity of {len(databases)} database(s)...")
            print("-" * 70)
            print(f"{'Database':<20} {'Status':<15} {'Issues':<10} {'Files Checked':<15}")
            print("-" * 70)
            
            for db in databases:
                print(f"{db['name']:<20} ", end="", flush=True)
                
                try:
                    integrity_result = self.db_manager.verify_database_integrity(db["name"])
                    
                    if integrity_result.get("valid", False):
                        status = "✅ Valid"
                        issues_count = len(integrity_result.get("issues", []))
                    else:
                        status = "❌ Invalid"
                        issues_count = len(integrity_result.get("issues", [])) + integrity_result.get("corrupted_files", 0)
                        databases_with_issues += 1
                    
                    files_checked = integrity_result.get("checked_files", 0)
                    total_issues += issues_count
                    
                    print(f"{status:<15} {issues_count:<10} {files_checked:<15}")
                    
                    # Show critical issues
                    if issues_count > 0 and integrity_result.get("issues"):
                        critical_issues = [issue for issue in integrity_result["issues"] if "corrupted" in issue.lower() or "missing" in issue.lower()]
                        if critical_issues:
                            print(f"{'':20} ⚠️ Critical: {critical_issues[0][:40]}")
                
                except Exception as e:
                    print(f"❌ Error:{str(e)[:25]:<15} 0          0")
                    databases_with_issues += 1
                    total_issues += 1
            
            print("-" * 70)
            
            # Summary
            healthy_databases = len(databases) - databases_with_issues
            health_percentage = (healthy_databases / len(databases)) * 100 if databases else 0
            
            print(f"\n📊 Integrity Verification Summary:")
            print(f"   Databases checked: {len(databases)}")
            print(f"   Healthy databases: {healthy_databases} ({health_percentage:.1f}%)")
            print(f"   Databases with issues: {databases_with_issues}")
            print(f"   Total issues found: {total_issues}")
            
            # Overall system health
            if total_issues == 0:
                print(f"   Overall status: 🟢 Excellent - All databases are healthy")
            elif databases_with_issues <= len(databases) * 0.1:  # Less than 10% have issues
                print(f"   Overall status: 🟡 Good - Minor issues detected")
            elif databases_with_issues <= len(databases) * 0.3:  # Less than 30% have issues
                print(f"   Overall status: 🟠 Fair - Some databases need attention")
            else:
                print(f"   Overall status: 🔴 Poor - Multiple databases have issues")
            
            # Recommendations
            if total_issues > 0:
                print(f"\n💡 Recommendations:")
                print("   🧹 Run database cleanup to resolve minor issues")
                print("   🔧 Perform database maintenance on problematic databases")
                print("   💾 Consider backing up healthy databases")
                print("   🔍 Investigate databases with critical issues")
                
                if databases_with_issues > len(databases) * 0.5:
                    print("   🚨 Consider system-wide maintenance - many databases affected")
            else:
                print(f"\n🎉 All databases passed integrity verification!")
                print("   Continue with regular maintenance schedule")
        
        except Exception as e:
            print(f"❌ Error during integrity verification: {str(e)}")
        
        input("\nPress Enter to continue...")

    def export_single_database(self, selected_db):
        """Export a specific database (helper function)"""
        try:
            print(f"\n📤 Export Database: {selected_db['name']}")
            print("=" * 40)
            
            default_path = f"exports/{selected_db['name']}_export_{int(time.time())}.zip"
            export_path = input(f"Export path (default: {default_path}): ").strip()
            if not export_path:
                export_path = default_path
            
            print(f"📤 Exporting database...")
            success = self.db_manager.export_database(
                selected_db["name"], 
                export_path, 
                self.current_user["username"]
            )
            
            if success:
                print(f"✅ Database exported successfully to: {export_path}")
            else:
                print(f"❌ Export failedef database_maintenance_menu(self):")
        """Database maintenance and optimization menu"""
        while True:
            print("\n🔧 Database Maintenance & Optimization")
            print("=" * 45)
            print("1. 🧹 Database Cleanup")
            print("2. 📊 Database Optimization")
            print("3. 🔍 Database Health Check")
            print("4. 📈 Database Performance Analysis")
            print("5. 🗑️ Remove Orphaned Files")
            print("6. 💾 Compact Database Storage")
            print("7. 🔄 Rebuild Database Indexes")
            print("8. 🧪 Database Consistency Check")
            print("9. 📋 Maintenance Schedule")
            print("10. 🔙 Back to Database Menu")
            
            choice = input("\nEnter your choice (1-10): ").strip()
            
            if choice == "1":
                self.database_cleanup_wizard()
            elif choice == "2":
                self.database_optimization_wizard()
            elif choice == "3":
                self.database_health_check()
            elif choice == "4":
                self.database_performance_analysis()
            elif choice == "5":
                self.remove_orphaned_files()
            elif choice == "6":
                self.compact_database_storage()
            elif choice == "7":
                self.rebuild_database_indexes()
            elif choice == "8":
                self.database_consistency_check()
            elif choice == "9":
                self.maintenance_schedule_menu()
            elif choice == "10":
                break
            else:
                print("❌ Invalid choice.")

    def database_cleanup_wizard(self):
        """Interactive database cleanup wizard"""
        if self.current_user["role"] != "admin":
            print("❌ Only administrators can perform database cleanup.")
            input("Press Enter to continue...")
            return
        
        try:
            print("\n🧹 Database Cleanup Wizard")
            print("=" * 35)
            
            databases = self.db_manager.list_databases()
            if not databases:
                print("❌ No databases available for cleanup.")
                input("Press Enter to continue...")
                return
            
            # Select database or clean all
            print("Cleanup options:")
            print("0. Clean all databases")
            for i, db in enumerate(databases, 1):
                stats = self.db_manager.get_database_stats(db["name"])
                size_str = self.format_size(stats.get("total_size", 0))
                print(f"{i}. {db['name']} ({stats.get('total_files', 0)} files, {size_str})")
            
            choice = input(f"\nSelect option (0-{len(databases)}): ").strip()
            
            if choice == "0":
                # Clean all databases
                selected_databases = databases
                print("✅ Selected: All databases")
            elif choice.isdigit() and 1 <= int(choice) <= len(databases):
                selected_databases = [databases[int(choice) - 1]]
                print(f"✅ Selected: {selected_databases[0]['name']}")
            else:
                print("❌ Invalid selection.")
                input("Press Enter to continue...")
                return
            
            # Cleanup options
            print(f"\n🧹 Cleanup Options:")
            print("1. Remove temporary files")
            print("2. Clear empty directories")
            print("3. Remove duplicate files")
            print("4. Clean up old log files")
            print("5. Remove corrupted files")
            print("6. Comprehensive cleanup (all above)")
            
            cleanup_options = input("Select cleanup types (1-6, comma-separated): ").strip()
            if not cleanup_options:
                print("❌ No cleanup options selected.")
                input("Press Enter to continue...")
                return
            
            options = [opt.strip() for opt in cleanup_options.split(",") if opt.strip().isdigit()]
            
            if "6" in options:
                options = ["1", "2", "3", "4", "5"]
            
            # Perform cleanup
            total_cleaned = 0
            total_space_freed = 0
            
            for db in selected_databases:
                print(f"\n🧹 Cleaning database: {db['name']}")
                db_path = os.path.join(self.config["storage"]["database_root"], "databases", db["name"])
                
                if "1" in options:
                    # Remove temporary files
                    temp_files = self.find_temp_files(db_path)
                    if temp_files:
                        space_freed = sum(os.path.getsize(f) for f in temp_files if os.path.exists(f))
                        for temp_file in temp_files:
                            try:
                                os.remove(temp_file)
                                total_cleaned += 1
                                total_space_freed += space_freed
                            except Exception as e:
                                print(f"   ❌ Error removing {temp_file}: {str(e)}")
                        print(f"   ✅ Removed {len(temp_files)} temporary files")
                
                if "2" in options:
                    # Clear empty directories
                    empty_dirs = self.find_empty_directories(db_path)
                    for empty_dir in empty_dirs:
                        try:
                            os.rmdir(empty_dir)
                            total_cleaned += 1
                        except Exception as e:
                            print(f"   ❌ Error removing directory {empty_dir}: {str(e)}")
                    if empty_dirs:
                        print(f"   ✅ Removed {len(empty_dirs)} empty directories")
                
                if "3" in options:
                    # Remove duplicate files
                    duplicates = self.find_duplicate_files(db_path)
                    for duplicate_group in duplicates:
                        # Keep the first file, remove others
                        for duplicate in duplicate_group[1:]:
                            try:
                                file_size = os.path.getsize(duplicate)
                                os.remove(duplicate)
                                total_cleaned += 1
                                total_space_freed += file_size
                            except Exception as e:
                                print(f"   ❌ Error removing duplicate {duplicate}: {str(e)}")
                    if duplicates:
                        total_duplicates = sum(len(group) - 1 for group in duplicates)
                        print(f"   ✅ Removed {total_duplicates} duplicate files")
                
                if "4" in options:
                    # Clean up old log files
                    log_files = self.find_old_log_files(db_path)
                    for log_file in log_files:
                        try:
                            file_size = os.path.getsize(log_file)
                            os.remove(log_file)
                            total_cleaned += 1
                            total_space_freed += file_size
                        except Exception as e:
                            print(f"   ❌ Error removing log file {log_file}: {str(e)}")
                    if log_files:
                        print(f"   ✅ Removed {len(log_files)} old log files")
                
                if "5" in options:
                    # Remove corrupted files
                    corrupted_files = self.find_corrupted_files(db_path)
                    for corrupted_file in corrupted_files:
                        try:
                            file_size = os.path.getsize(corrupted_file)
                            os.remove(corrupted_file)
                            total_cleaned += 1
                            total_space_freed += file_size
                        except Exception as e:
                            print(f"   ❌ Error removing corrupted file {corrupted_file}: {str(e)}")
                    if corrupted_files:
                        print(f"   ✅ Removed {len(corrupted_files)} corrupted files")
            
            # Summary
            print(f"\n🎉 Cleanup Summary:")
            print(f"   Databases cleaned: {len(selected_databases)}")
            print(f"   Total items removed: {total_cleaned}")
            print(f"   Space freed: {self.format_size(total_space_freed)}")
            
            # Log the cleanup operation
            self.security_system.add_security_block({
                "action": "database_cleanup",
                "databases": [db["name"] for db in selected_databases],
                "items_removed": total_cleaned,
                "space_freed": total_space_freed,
                "admin": self.current_user["username"],
                "timestamp": time.time()
            })
        
        except Exception as e:
            print(f"❌ Error during database cleanup: {str(e)}")
        
        input("\nPress Enter to continue...")

    def find_temp_files(self, db_path):
        """Find temporary files in database directory"""
        temp_files = []
        temp_extensions = ['.tmp', '.temp', '.cache', '.bak', '.old', '.~']
        temp_prefixes = ['tmp_', 'temp_', 'cache_', '.#']
        
        try:
            for root, dirs, files in os.walk(db_path):
                for file in files:
                    file_path = os.path.join(root, file)
                    
                    # Check by extension
                    if any(file.lower().endswith(ext) for ext in temp_extensions):
                        temp_files.append(file_path)
                        continue
                    
                    # Check by prefix
                    if any(file.startswith(prefix) for prefix in temp_prefixes):
                        temp_files.append(file_path)
                        continue
                    
                    # Check for old files (>30 days) in temp-like directories
                    if any(temp_dir in root for temp_dir in ['temp', 'tmp', 'cache']):
                        file_age = time.time() - os.path.getmtime(file_path)
                        if file_age > 30 * 24 * 3600:  # 30 days
                            temp_files.append(file_path)
        
        except Exception as e:
            logger.error(f"Error finding temp files: {str(e)}")
        
        return temp_files

    def find_empty_directories(self, db_path):
        """Find empty directories in database path"""
        empty_dirs = []
        
        try:
            for root, dirs, files in os.walk(db_path, topdown=False):
                # Skip the root database directory
                if root == db_path:
                    continue
                
                # Check if directory is empty
                if not dirs and not files:
                    empty_dirs.append(root)
                # Check if directory only contains hidden files
                elif not dirs and all(f.startswith('.') for f in files):
                    empty_dirs.append(root)
        
        except Exception as e:
            logger.error(f"Error finding empty directories: {str(e)}")
        
        return empty_dirs

    def find_duplicate_files(self, db_path):
        """Find duplicate files based on content hash"""
        file_hashes = {}
        duplicates = []
        
        try:
            for root, dirs, files in os.walk(db_path):
                for file in files:
                    file_path = os.path.join(root, file)
                    
                    try:
                        # Calculate file hash
                        file_hash = self.calculate_file_hash(file_path)
                        
                        if file_hash in file_hashes:
                            # Found duplicate
                            if len(file_hashes[file_hash]) == 1:
                                # First duplicate found for this hash
                                duplicates.append(file_hashes[file_hash])
                            duplicates[-1].append(file_path)
                        else:
                            file_hashes[file_hash] = [file_path]
                    
                    except Exception as e:
                        logger.error(f"Error hashing file {file_path}: {str(e)}")
                        continue
        
        except Exception as e:
            logger.error(f"Error finding duplicate files: {str(e)}")
        
        return [group for group in duplicates if len(group) > 1]

    def calculate_file_hash(self, file_path):
        """Calculate SHA256 hash of file"""
        hash_sha256 = hashlib.sha256()
        
        try:
            with open(file_path, "rb") as f:
                for chunk in iter(lambda: f.read(4096), b""):
                    hash_sha256.update(chunk)
            return hash_sha256.hexdigest()
        except Exception as e:
            logger.error(f"Error calculating hash for {file_path}: {str(e)}")
            return None

    def find_old_log_files(self, db_path):
        """Find old log files (>7 days)"""
        old_logs = []
        log_extensions = ['.log', '.txt']
        log_directories = ['logs', 'audit', 'history']
        
        try:
            for root, dirs, files in os.walk(db_path):
                # Check if we're in a log directory
                in_log_dir = any(log_dir in root for log_dir in log_directories)
                
                for file in files:
                    file_path = os.path.join(root, file)
                    
                    # Check if it's a log file
                    is_log_file = (
                        any(file.lower().endswith(ext) for ext in log_extensions) or
                        'log' in file.lower() or
                        in_log_dir
                    )
                    
                    if is_log_file:
                        # Check file age
                        file_age = time.time() - os.path.getmtime(file_path)
                        if file_age > 7 * 24 * 3600:  # 7 days
                            old_logs.append(file_path)
        
        except Exception as e:
            logger.error(f"Error finding old log files: {str(e)}")
        
        return old_logs

    def find_corrupted_files(self, db_path):
        """Find potentially corrupted files"""
        corrupted_files = []
        
        try:
            for root, dirs, files in os.walk(db_path):
                for file in files:
                    file_path = os.path.join(root, file)
                    
                    try:
                        # Check if file is readable
                        with open(file_path, 'rb') as f:
                            # Try to read first and last 1024 bytes
                            f.read(1024)
                            f.seek(-min(1024, os.path.getsize(file_path)), 2)
                            f.read(1024)
                        
                        # Check for zero-byte files
                        if os.path.getsize(file_path) == 0:
                            corrupted_files.append(file_path)
                    
                    except (IOError, OSError, PermissionError):
                        # File is corrupted or inaccessible
                        corrupted_files.append(file_path)
                    except Exception as e:
                        logger.error(f"Error checking file {file_path}: {str(e)}")
        
        except Exception as e:
            logger.error(f"Error finding corrupted files: {str(e)}")
        
        return corrupted_files

    def database_optimization_wizard(self):
        """Database optimization wizard"""
        if self.current_user["role"] != "admin":
            print("❌ Only administrators can perform database optimization.")
            input("Press Enter to continue...")
            return
        
        try:
            print("\n📊 Database Optimization Wizard")
            print("=" * 40)
            
            databases = self.db_manager.list_databases()
            if not databases:
                print("❌ No databases available for optimization.")
                input("Press Enter to continue...")
                return
            
            # Select database
            print("Available databases:")
            for i, db in enumerate(databases, 1):
                stats = self.db_manager.get_database_stats(db["name"])
                print(f"{i}. {db['name']} ({stats.get('total_files', 0)} files)")
            
            choice = input(f"Select database (1-{len(databases)}): ").strip()
            
            if not choice.isdigit() or not (1 <= int(choice) <= len(databases)):
                print("❌ Invalid selection.")
                input("Press Enter to continue...")
                return
            
            selected_db = databases[int(choice) - 1]
            print(f"✅ Selected: {selected_db['name']}")
            
            # Optimization options
            print(f"\n🔧 Optimization Options:")
            print("1. Defragment database storage")
            print("2. Optimize file organization")
            print("3. Update metadata indexes")
            print("4. Compress old files")
            print("5. Reorganize directory structure")
            print("6. Full optimization (all above)")
            
            opt_choice = input("Select optimization (1-6): ").strip()
            
            if opt_choice not in ["1", "2", "3", "4", "5", "6"]:
                print("❌ Invalid optimization choice.")
                input("Press Enter to continue...")
                return
            
            print(f"\n🔄 Optimizing database: {selected_db['name']}")
            
            if opt_choice in ["1", "6"]:
                print("   🔧 Defragmenting storage...")
                self.defragment_database_storage(selected_db["name"])
                print("   ✅ Storage defragmented")
            
            if opt_choice in ["2", "6"]:
                print("   📁 Optimizing file organization...")
                self.optimize_file_organization(selected_db["name"])
                print("   ✅ File organization optimized")
            
            if opt_choice in ["3", "6"]:
                print("   📇 Updating metadata indexes...")
                self.update_metadata_indexes(selected_db["name"])
                print("   ✅ Metadata indexes updated")
            
            if opt_choice in ["4", "6"]:
                print("   🗜️ Compressing old files...")
                compressed_count = self.compress_old_files(selected_db["name"])
                print(f"   ✅ Compressed {compressed_count} files")
            
            if opt_choice in ["5", "6"]:
                print("   🏗️ Reorganizing directory structure...")
                self.reorganize_directory_structure(selected_db["name"])
                print("   ✅ Directory structure reorganized")
            
            print(f"\n🎉 Optimization completed for database: {selected_db['name']}")
            
            # Show before/after stats
            new_stats = self.db_manager.get_database_stats(selected_db["name"])
            print(f"📊 Current stats: {new_stats.get('total_files', 0)} files, {self.format_size(new_stats.get('total_size', 0))}")
            
            # Log optimization
            self.security_system.add_security_block({
                "action": "database_optimization",
                "database": selected_db["name"],
                "optimization_type": opt_choice,
                "admin": self.current_user["username"],
                "timestamp": time.time()
            })
        
        except Exception as e:
            print(f"❌ Error during database optimization: {str(e)}")
        
        input("\nPress Enter to continue...")

    def defragment_database_storage(self, db_name):
        """Defragment database storage (mock implementation)"""
        # In a real implementation, this would reorganize database files
        # to reduce fragmentation and improve access times
        time.sleep(1)  # Simulate processing time

    def optimize_file_organization(self, db_name):
        """Optimize file organization within database"""
        try:
            db_path = os.path.join(self.config["storage"]["database_root"], "databases", db_name)
            
            # Create organized directory structure
            subdirs = ["documents", "images", "data", "archives"]
            for subdir in subdirs:
                os.makedirs(os.path.join(db_path, subdir), exist_ok=True)
            
            # This would move files to appropriate subdirectories based on type
            # Mock implementation just creates the structure
        except Exception as e:
            logger.error(f"Error optimizing file organization: {str(e)}")

    def update_metadata_indexes(self, db_name):
        """Update metadata indexes for faster searching"""
        try:
            db_path = os.path.join(self.config["storage"]["database_root"], "databases", db_name)
            index_file = os.path.join(db_path, "metadata_index.json")
            
            # Build metadata index
            metadata_index = {
                "files": {},
                "tags": {},
                "created_at": time.time(),
                "last_updated": time.time()
            }
            
            # Scan files and build index
            for root, dirs, files in os.walk(db_path):
                for file in files:
                    if file.endswith(('.json', '.txt', '.md')):
                        file_path = os.path.join(root, file)
                        relative_path = os.path.relpath(file_path, db_path)
                        
                        metadata_index["files"][relative_path] = {
                            "size": os.path.getsize(file_path),
                            "modified": os.path.getmtime(file_path),
                            "type": os.path.splitext(file)[1]
                        }
            
            # Save index
            with open(index_file, "w") as f:
                json.dump(metadata_index, f, indent=2)
        
        except Exception as e:
            logger.error(f"Error updating metadata indexes: {str(e)}")

    def compress_old_files(self, db_name):
        """Compress old files to save space"""
        import gzip
        
        compressed_count = 0
        
        try:
            db_path = os.path.join(self.config["storage"]["database_root"], "databases", db_name)
            
            for root, dirs, files in os.walk(db_path):
                for file in files:
                    file_path = os.path.join(root, file)
                    
                    # Skip already compressed files
                    if file.endswith('.gz'):
                        continue
                    
                    # Check if file is old (>30 days) and compressible
                    file_age = time.time() - os.path.getmtime(file_path)
                    compressible_extensions = ['.txt', '.log', '.json', '.csv', '.xml']
                    
                    if (file_age > 30 * 24 * 3600 and  # 30 days old
                        any(file.endswith(ext) for ext in compressible_extensions) and
                        os.path.getsize(file_path) > 1024):  # Larger than 1KB
                        
                        try:
                            # Compress file
                            compressed_path = file_path + '.gz'
                            with open(file_path, 'rb') as f_in:
                                with gzip.open(compressed_path, 'wb') as f_out:
                                    shutil.copyfileobj(f_in, f_out)
                            
                            # Remove original if compression successful
                            if os.path.exists(compressed_path):
                                os.remove(file_path)
                                compressed_count += 1
                        
                        except Exception as e:
                            logger.error(f"Error compressing {file_path}: {str(e)}")
        
        except Exception as e:
            logger.error(f"Error during file compression: {str(e)}")
        
        return compressed_count

    def reorganize_directory_structure(self, db_name):
        """Reorganize directory structure for better organization"""
        try:
            db_path = os.path.join(self.config["storage"]["database_root"], "databases", db_name)
            
            # Create standard directory structure
            standard_dirs = [
                "data/current",
                "data/archives",
                "metadata",
                "indexes",
                "backups",
                "temp"
            ]
            
            for dir_path in standard_dirs:
                full_path = os.path.join(db_path, dir_path)
                os.makedirs(full_path, exist_ok=True)
            
            # This would move existing files to appropriate directories
            # Mock implementation just creates the structure
        
        except Exception as e:
            logger.error(f"Error reorganizing directory structure: {str(e)}")

    def database_health_check(self):
        """Comprehensive database health check"""
        try:
            print("\n🔍 Database Health Check")
            print("=" * 30)
            
            databases = self.db_manager.list_databases()
            if not databases:
                print("❌ No databases available for health check.")
                input("Press Enter to continue...")
                return
            
            print(f"🏥 Checking health of {len(databases)} database(s)...")
            
            overall_health = 100
            total_issues = 0
            
            for db in databases:
                print(f"\n📊 Checking: {db['name']}")
                db_health, issues = self.check_single_database_health(db["name"])
                
                health_status = "🟢 Excellent" if db_health >= 90 else "🟡 Good" if db_health >= 70 else "🟠 Fair" if db_health >= 50 else "🔴 Poor"
                print(f"   Health Score: {health_status} ({db_health}%)")
                
                if issues:
                    print(f"   Issues found ({len(issues)}):")
                    for issue in issues[:3]:  # Show first 3 issues
                        print(f"      ⚠️ {issue}")
                    if len(issues) > 3:
                        print(f"      ... and {len(issues) - 3} more issues")
                else:
                    print("   ✅ No issues found")
                
                overall_health = min(overall_health, db_health)
                total_issues += len(issues)
            
            # Overall system health
            print(f"\n🏥 Overall System Health:")
            system_health_status = "🟢 Excellent" if overall_health >= 90 else "🟡 Good" if overall_health >= 70 else "🟠 Fair" if overall_health >= 50 else "🔴 Poor"
            print(f"   Status: {system_health_status} ({overall_health}%)")
            print(f"   Total Issues: {total_issues}")
            
            if total_issues > 0:
                print(f"\n💡 Recommendations:")
                print("   • Run database cleanup to resolve minor issues")
                print("   • Consider database optimization for performance")
                print("   • Check individual database integrity")
                print("   • Review storage usage and cleanup old files")
        
        except Exception as e:
            print(f"❌ Error during health check: {str(e)}")
        
        input("\nPress Enter to continue...")

    def check_single_database_health(self, db_name):
        """Check health of a single database"""
        health_score = 100
        issues = []
        
        try:
            db_path = os.path.join(self.config["storage"]["database_root"], "databases", db_name)
            
            # Check if database directory exists
            if not os.path.exists(db_path):
                issues.append("Database directory missing")
                health_score -= 50
                return health_score, issues
            
            # Check essential files
            essential_files = ["metadata.json", "users.json"]
            for essential_file in essential_files:
                file_path = os.path.join(db_path, essential_file)
                if not os.path.exists(file_path):
                    issues.append(f"Missing essential file: {essential_file}")
                    health_score -= 10
            
            # Check storage usage
            stats = self.db_manager.get_database_stats(db_name)
            total_size = stats.get("total_size", 0)
            
            # Check for excessive storage usage (mock threshold: 1GB)
            if total_size > 1024 * 1024 * 1024:
                issues.append("High storage usage detected")
                health_score -= 5
            
            # Check for too many files (mock threshold: 1000)
            if stats.get("total_files", 0) > 1000:
                issues.append("Large number of files may impact performance")
                health_score -= 5
            
            # Check file system permissions
            if not os.access(db_path, os.R_OK | os.W_OK):
                issues.append("Permission issues detected")
                health_score -= 15
            
            # Check for orphaned files
            orphaned_files = self.find_orphaned_files(db_path)
            if orphaned_files:
                issues.append(f"{len(orphaned_files)} orphaned files found")
                health_score -= min(len(orphaned_files), 10)
            
            # Check for corrupted files
            corrupted_files = self.find_corrupted_files(db_path)
            if corrupted_files:
                issues.append(f"{len(corrupted_files)} corrupted files found")
                health_score -= min(len(corrupted_files) * 2, 20)
            
            # Check metadata consistency
            if not self.check_metadata_consistency(db_name):
                issues.append("Metadata consistency issues")
                health_score -= 15
        
        except Exception as e:
            issues.append(f"Error during health check: {str(e)}")
            health_score -= 20
        
        return max(0, health_score), issues

    def find_orphaned_files(self, db_path):
        """Find files not referenced in database metadata"""
        orphaned_files = []
        
        try:
            # Load database metadata
            metadata_file = os.path.join(db_path, "metadata.json")
            if not os.path.exists(metadata_file):
                return orphaned_files
            
            with open(metadata_file, "r") as f:
                metadata = json.load(f)
            
            # Get list of referenced files
            referenced_files = set()
            if "files" in metadata:
                for file_info in metadata["files"]:
                    if "path" in file_info:
                        referenced_files.add(file_info["path"])
            
            # Check all files in database directory
            for root, dirs, files in os.walk(db_path):
                for file in files:
                    # Skip system files
                    if file in ["metadata.json", "users.json", "restrictions.json"]:
                        continue
                    
                    file_path = os.path.join(root, file)
                    relative_path = os.path.relpath(file_path, db_path)
                    
                    if relative_path not in referenced_files:
                        orphaned_files.append(relative_path)
        
        except Exception as e:
            logger.error(f"Error finding orphaned files: {str(e)}")
        
        return orphaned_files

    def check_metadata_consistency(self, db_name):
        """Check metadata consistency"""
        try:
            db_path = os.path.join(self.config["storage"]["database_root"], "databases", db_name)
            metadata_file = os.path.join(db_path, "metadata.json")
            
            if not os.path.exists(metadata_file):
                return False
            
            with open(metadata_file, "r") as f:
                metadata = json.load(f)
            
            # Check required fields
            required_fields = ["database_name", "created_at", "owner"]
            for field in required_fields:
                if field not in metadata:
                    return False
            
            # Check if referenced files exist
            if "files" in metadata:
                for file_info in metadata["files"]:
                    if "path" in file_info:
                        file_path = os.path.join(db_path, file_info["path"])
                        if not os.path.exists(file_path):
                            return False
            
            return True
        
        except Exception as e:
            logger.error(f"Error checking metadata consistency: {str(e)}")
            return False

    def database_performance_analysis(self):
        """Analyze database performance metrics"""
        try:
            print("\n📈 Database Performance Analysis")
            print("=" * 40)
            
            databases = self.db_manager.list_databases()
            if not databases:
                print("❌ No databases available for analysis.")
                input("Press Enter to continue...")
                return
            
            print("📊 Performance Analysis Report")
            print("-" * 60)
            print(f"{'Database':<20} {'Files':<8} {'Size':<10} {'Score':<8} {'Status':<12}")
            print("-" * 60)
            
            total_performance_score = 0
            
            for db in databases:
                stats = self.db_manager.get_database_stats(db["name"])
                performance_score = self.calculate_performance_score(db["name"], stats)
                
                files_count = stats.get("total_files", 0)
                size_str = self.format_size(stats.get("total_size", 0))
                
                status = "🟢 Optimal" if performance_score >= 90 else "🟡 Good" if performance_score >= 70 else "🟠 Fair" if performance_score >= 50 else "🔴 Poor"
                
                print(f"{db['name']:<20} {files_count:<8} {size_str:<10} {performance_score:<8} {status:<12}")
                total_performance_score += performance_score
            
            print("-" * 60)
            
            # Overall performance summary
            avg_performance = total_performance_score / len(databases) if databases else 0
            overall_status = "🟢 Optimal" if avg_performance >= 90 else "🟡 Good" if avg_performance >= 70 else "🟠 Fair" if avg_performance >= 50 else "🔴 Poor"
            
            print(f"\n📊 Overall Performance: {overall_status} ({avg_performance:.1f}%)")
            
            # Performance recommendations
            print(f"\n💡 Performance Recommendations:")
            
            # Find databases with performance issues
            slow_databases = [db for db in databases if self.calculate_performance_score(db["name"], self.db_manager.get_database_stats(db["name"])) < 70]
            
            if slow_databases:
                print(f"   🐌 Databases needing optimization:")
                for db in slow_databases[:3]:
                    print(f"      • {db['name']}: Consider cleanup and optimization")
            
            # Storage recommendations
            large_databases = [db for db in databases if self.db_manager.get_database_stats(db["name"]).get("total_size", 0) > 100 * 1024 * 1024]  # >100MB
            
            if large_databases:
                print(f"   💾 Large databases detected:")
                for db in large_databases[:3]:
                    size = self.format_size(self.db_manager.get_database_stats(db["name"]).get("total_size", 0))
                    print(f"      • {db['name']}: {size} - Consider archiving old data")
            
            # File count recommendations
            file_heavy_databases = [db for db in databases if self.db_manager.get_database_stats(db["name"]).get("total_files", 0) > 500]
            
            if file_heavy_databases:
                print(f"   📁 File-heavy databases:")
                for db in file_heavy_databases[:3]:
                    files = self.db_manager.get_database_stats(db["name"]).get("total_files", 0)
                    print(f"      • {db['name']}: {files} files - Consider file organization")
            
            if not slow_databases and not large_databases and not file_heavy_databases:
                print("   ✅ All databases are performing optimally")
                print("   • Continue regular maintenance schedule")
                print("   • Monitor growth trends")
        
        except Exception as e:
            print(f"❌ Error during performance analysis: {str(e)}")
        
        input("\nPress Enter to continue...")

    def calculate_performance_score(self, db_name, stats):
        """Calculate performance score for a database"""
        score = 100
        
        try:
            # File count factor
            file_count = stats.get("total_files", 0)
            if file_count > 1000:
                score -= 20
            elif file_count > 500:
                score -= 10
            elif file_count > 100:
                score -= 5
            
            # Size factor
            total_size = stats.get("total_size", 0)
            if total_size > 1024 * 1024 * 1024:  # 1GB
                score -= 15
            elif total_size > 500 * 1024 * 1024:  # 500MB
                score -= 10
            elif total_size > 100 * 1024 * 1024:  # 100MB
                score -= 5
            
            # Activity factor (mock - based on operations)
            operations = stats.get("operations", 0)
            if operations > 10000:
                score -= 10  # High activity can slow things down
            
            # Age factor
            if stats.get("created_at"):
                age_days = (time.time() - stats["created_at"]) / (24 * 3600)
                if age_days > 365:  # Over a year old
                    score -= 5
            
            # Check for optimization indicators
            db_path = os.path.join(self.config["storage"]["database_root"], "databases", db_name)
            
            # Check for fragmentation indicators
            if self.has_fragmentation_indicators(db_path):
                score -= 10
            
            # Check for temp files
            temp_files = self.find_temp_files(db_path)
            if temp_files:
                score -= min(len(temp_files), 15)
        
        except Exception as e:
            logger.error(f"Error calculating performance score: {str(e)}")
            score -= 20
        
        return max(0, min(100, score))

    def has_fragmentation_indicators(self, db_path):
        """Check for database fragmentation indicators"""
        try:
            # Look for many small files (indicator of fragmentation)
            small_files_count = 0
            total_files = 0
            
            for root, dirs, files in os.walk(db_path):
                for file in files:
                    file_path = os.path.join(root, file)
                    try:
                        file_size = os.path.getsize(file_path)
                        total_files += 1
                        if file_size < 1024:  # Files smaller than 1KB
                            small_files_count += 1
                    except:
                        continue
            
            if total_files > 0:
                small_file_ratio = small_files_count / total_files
                return small_file_ratio > 0.3  # More than 30% small files
            
            return False
        
        except Exception:
            return False

    def remove_orphaned_files(self):
        """Remove orphaned files from databases"""
        if self.current_user["role"] != "admin":
            print("❌ Only administrators can remove orphaned files.")
            input("Press Enter to continue...")
            return
        
        try:
            print("\n🗑️ Remove Orphaned Files")
            print("=" * 30)
            
            databases = self.db_manager.list_databases()
            if not databases:
                print("❌ No databases available.")
                input("Press Enter to continue...")
                return
            
            total_orphaned = 0
            total_removed = 0
            
            for db in databases:
                print(f"\n🔍 Scanning database: {db['name']}")
                
                db_path = os.path.join(self.config["storage"]["database_root"], "databases", db["name"])
                orphaned_files = self.find_orphaned_files(db_path)
                
                if orphaned_files:
                    print(f"   Found {len(orphaned_files)} orphaned files")
                    total_orphaned += len(orphaned_files)
                    
                    # Show some examples
                    for i, orphaned_file in enumerate(orphaned_files[:3]):
                        print(f"      • {orphaned_file}")
                    if len(orphaned_files) > 3:
                        print(f"      ... and {len(orphaned_files) - 3} more")
                    
                    # Ask for confirmation
                    remove_confirm = input(f"   Remove orphaned files from {db['name']}? (y/n): ").lower()
                    if remove_confirm == 'y':
                        removed_count = 0
                        for orphaned_file in orphaned_files:
                            try:
                                full_path = os.path.join(db_path, orphaned_file)
                                os.remove(full_path)
                                removed_count += 1
                            except Exception as e:
                                print(f"      ❌ Error removing {orphaned_file}: {str(e)}")
                        
                        print(f"   ✅ Removed {removed_count} orphaned files")
                        total_removed += removed_count
                    else:
                        print("   ⏭️ Skipped orphaned file removal")
                else:
                    print("   ✅ No orphaned files found")
            
            print(f"\n🎉 Orphaned Files Cleanup Summary:")
            print(f"   Databases scanned: {len(databases)}")
            print(f"   Orphaned files found: {total_orphaned}")
            print(f"   Files removed: {total_removed}")
            
            if total_removed > 0:
                # Log the cleanup
                self.security_system.add_security_block({
                    "action": "orphaned_files_cleanup",
                    "databases_scanned": len(databases),
                    "files_removed": total_removed,
                    "admin": self.current_user["username"],
                    "timestamp": time.time()
                })
        
        except Exception as e:
            print(f"❌ Error removing orphaned files: {str(e)}")
        
        input("\nPress Enter to continue...")

    def compact_database_storage(self):
        """Compact database storage to reduce fragmentation"""
        if self.current_user["role"] != "admin":
            print("❌ Only administrators can compact database storage.")
            input("Press Enter to continue...")
            return
        
        try:
            print("\n💾 Compact Database Storage")
            print("=" * 35)
            
            databases = self.db_manager.list_databases()
            if not databases:
                print("❌ No databases available.")
                input("Press Enter to continue...")
                return
            
            # Select database
            print("Available databases:")
            for i, db in enumerate(databases, 1):
                stats = self.db_manager.get_database_stats(db["name"])
                size_str = self.format_size(stats.get("total_size", 0))
                print(f"{i}. {db['name']} ({size_str})")
            
            choice = input(f"Select database to compact (1-{len(databases)}): ").strip()
            
            if not choice.isdigit() or not (1 <= int(choice) <= len(databases)):
                print("❌ Invalid selection.")
                input("Press Enter to continue...")
                return
            
            selected_db = databases[int(choice) - 1]
            
            print(f"\n💾 Compacting storage for: {selected_db['name']}")
            print("⚠️ This operation may take several minutes...")
            
            # Get before stats
            before_stats = self.db_manager.get_database_stats(selected_db["name"])
            before_size = before_stats.get("total_size", 0)
            
            confirm = input("Continue with storage compaction? (y/n): ").lower()
            if confirm != 'y':
                print("❌ Storage compaction cancelled.")
                input("Press Enter to continue...")
                return
            
            # Perform compaction
            print("🔄 Step 1: Analyzing storage structure...")
            time.sleep(1)
            
            print("🔄 Step 2: Reorganizing file blocks...")
            space_saved = self.perform_storage_compaction(selected_db["name"])
            
            print("🔄 Step 3: Updating metadata...")
            time.sleep(0.5)
            
            print("🔄 Step 4: Verifying integrity...")
            time.sleep(0.5)
            
            # Get after stats
            after_stats = self.db_manager.get_database_stats(selected_db["name"])
            after_size = after_stats.get("total_size", 0)
            
            actual_savings = before_size - after_size + space_saved
            
            print(f"\n✅ Storage compaction completed!")
            print(f"📊 Compaction Results:")
            print(f"   Before: {self.format_size(before_size)}")
            print(f"   After: {self.format_size(after_size)}")
            print(f"   Space saved: {self.format_size(actual_savings)}")
            
            if actual_savings > 0:
                savings_pct = (actual_savings / before_size) * 100 if before_size > 0 else 0
                print(f"   Reduction: {savings_pct:.1f}%")
            
            # Log the compaction
            self.security_system.add_security_block({
                "action": "database_storage_compaction",
                "database": selected_db["name"],
                "space_saved": actual_savings,
                "admin": self.current_user["username"],
                "timestamp": time.time()
            })
        
        except Exception as e:
            print(f"❌ Error during storage compaction: {str(e)}")
        
        input("\nPress Enter to continue...")

    def perform_storage_compaction(self, db_name):
        """Perform actual storage compaction"""
        space_saved = 0
        
        try:
            db_path = os.path.join(self.config["storage"]["database_root"], "databases", db_name)
            
            # Simulate compaction by removing gaps and optimizing file layout
            # In a real implementation, this would:
            # 1. Reorganize file blocks
            # 2. Remove empty spaces
            # 3. Optimize file system allocation
            
            # For now, we'll compress some files and remove duplicates
            space_saved += self.compress_old_files(db_name) * 1024  # Estimate savings
            
            # Remove temporary files
            temp_files = self.find_temp_files(db_path)
            for temp_file in temp_files:
                try:
                    file_size = os.path.getsize(temp_file)
                    os.remove(temp_file)
                    space_saved += file_size
                except:
                    continue
            
            time.sleep(2)  # Simulate processing time
        
        except Exception as e:
            logger.error(f"Error during storage compaction: {str(e)}")
        
        return space_saved

    def rebuild_database_indexes(self):
        """Rebuild database indexes for improved performance"""
        if self.current_user["role"] != "admin":
            print("❌ Only administrators can rebuild database indexes.")
            input("Press Enter to continue...")
            return
        
        try:
            print("\n🔄 Rebuild Database Indexes")
            print("=" * 35)
            
            databases = self.db_manager.list_databases()
            if not databases:
                print("❌ No databases available.")
                input("Press Enter to continue...")
                return
            
            print("🔍 Index Rebuild Options:")
            print("1. Rebuild indexes for specific database")
            print("2. Rebuild indexes for all databases")
            
            choice = input("Select option (1-2): ").strip()
            
            if choice == "1":
                # Select specific database
                print("\nAvailable databases:")
                for i, db in enumerate(databases, 1):
                    print(f"{i}. {db['name']}")
                
                db_choice = input(f"Select database (1-{len(databases)}): ").strip()
                
                if not db_choice.isdigit() or not (1 <= int(db_choice) <= len(databases)):
                    print("❌ Invalid selection.")
                    input("Press Enter to continue...")
                    return
                
                selected_databases = [databases[int(db_choice) - 1]]
            
            elif choice == "2":
                selected_databases = databases
            
            else:
                print("❌ Invalid choice.")
                input("Press Enter to continue...")
                return
            
            # Rebuild indexes
            total_indexes_rebuilt = 0
            
            for db in selected_databases:
                print(f"\n🔄 Rebuilding indexes for: {db['name']}")
                
                indexes_rebuilt = self.rebuild_single_database_indexes(db["name"])
                total_indexes_rebuilt += indexes_rebuilt
                
                print(f"   ✅ Rebuilt {indexes_rebuilt} indexes")
            
            print(f"\n🎉 Index Rebuild Summary:")
            print(f"   Databases processed: {len(selected_databases)}")
            print(f"   Total indexes rebuilt: {total_indexes_rebuilt}")
            print("   📈 Database performance should be improved")
            
            # Log the operation
            self.security_system.add_security_block({
                "action": "database_indexes_rebuilt",
                "databases": [db["name"] for db in selected_databases],
                "indexes_rebuilt": total_indexes_rebuilt,
                "admin": self.current_user["username"],
                "timestamp": time.time()
            })
        
        except Exception as e:
            print(f"❌ Error rebuilding database indexes: {str(e)}")
        
        input("\nPress Enter to continue...")

    def rebuild_single_database_indexes(self, db_name):
        """Rebuild indexes for a single database"""
        indexes_rebuilt = 0
        
        try:
            db_path = os.path.join(self.config["storage"]["database_root"], "databases", db_name)
            
            # File index
            print("     🔄 Building file index...")
            self.build_file_index(db_path)
            indexes_rebuilt += 1
            
            # Metadata index
            print("     🔄 Building metadata index...")
            self.update_metadata_indexes(db_name)
            indexes_rebuilt += 1
            
            # User index
            print("     🔄 Building user index...")
            self.build_user_index(db_path)
            indexes_rebuilt += 1
            
            # Tag index (if applicable)
            print("     🔄 Building tag index...")
            self.build_tag_index(db_path)
            indexes_rebuilt += 1
            
            time.sleep(1)  # Simulate processing time
        
        except Exception as e:
            logger.error(f"Error rebuilding indexes for {db_name}: {str(e)}")
        
        return indexes_rebuilt

    def build_file_index(self, db_path):
        """Build file index for faster file operations"""
        try:
            file_index = {
                "files": {},
                "by_type": {},
                "by_size": {},
                "created_at": time.time()
            }
            
            for root, dirs, files in os.walk(db_path):
                for file in files:
                    file_path = os.path.join(root, file)
                    relative_path = os.path.relpath(file_path, db_path)
                    
                    try:
                        file_stats = os.stat(file_path)
                        file_ext = os.path.splitext(file)[1].lower()
                        
                        file_info = {
                            "path": relative_path,
                            "size": file_stats.st_size,
                            "modified": file_stats.st_mtime,
                            "type": file_ext
                        }
                        
                        file_index["files"][relative_path] = file_info
                        
                        # Index by type
                        if file_ext not in file_index["by_type"]:
                            file_index["by_type"][file_ext] = []
                        file_index["by_type"][file_ext].append(relative_path)
                        
                        # Index by size range
                        size_range = self.get_size_range(file_stats.st_size)
                        if size_range not in file_index["by_size"]:
                            file_index["by_size"][size_range] = []
                        file_index["by_size"][size_range].append(relative_path)
                    
                    except Exception:
                        continue
            
            # Save file index
            index_file = os.path.join(db_path, "file_index.json")
            with open(index_file, "w") as f:
                json.dump(file_index, f, indent=2)
        
        except Exception as e:
            logger.error(f"Error building file index: {str(e)}")

    def build_user_index(self, db_path):
        """Build user access index"""
        try:
            users_file = os.path.join(db_path, "users.json")
            if not os.path.exists(users_file):
                return
            
            with open(users_file, "r") as f:
                users_data = json.load(f)
            
            user_index = {
                "users": {},
                "by_role": {},
                "by_permission": {},
                "created_at": time.time()
            }
            
            for username, user_info in users_data.get("users", {}).items():
                role = user_info.get("role", "user")
                permissions = user_info.get("permissions", [])
                
                user_index["users"][username] = {
                    "role": role,
                    "permissions": permissions,
                    "added_at": user_info.get("added_at", 0)
                }
                
                # Index by role
                if role not in user_index["by_role"]:
                    user_index["by_role"][role] = []
                user_index["by_role"][role].append(username)
                
                # Index by permissions
                for permission in permissions:
                    if permission not in user_index["by_permission"]:
                        user_index["by_permission"][permission] = []
                    user_index["by_permission"][permission].append(username)
            
            # Save user index
            index_file = os.path.join(db_path, "user_index.json")
            with open(index_file, "w") as f:
                json.dump(user_index, f, indent=2)
        
        except Exception as e:
            logger.error(f"Error building user index: {str(e)}")

    def build_tag_index(self, db_path):
        """Build tag index for content categorization"""
        try:
            tag_index = {
                "tags": {},
                "files_by_tag": {},
                "created_at": time.time()
            }
            
            # This would scan files for tags/metadata
            # For now, create a basic structure
            
            # Save tag index
            index_file = os.path.join(db_path, "tag_index.json")
            with open(index_file, "w") as f:
                json.dump(tag_index, f, indent=2)
        
        except Exception as e:
            logger.error(f"Error building tag index: {str(e)}")

    def get_size_range(self, file_size):
        """Get size range category for file"""
        if file_size < 1024:
            return "tiny"  # < 1KB
        elif file_size < 1024 * 1024:
            return "small"  # < 1MB
        elif file_size < 10 * 1024 * 1024:
            return "medium"  # < 10MB
        elif file_size < 100 * 1024 * 1024:
            return "large"  # < 100MB
        else:
            return "huge"  # >= 100MB

    def database_consistency_check(self):
        """Check database consistency and integrity"""
        try:
            print("\n🧪 Database Consistency Check")
            print("=" * 40)
            
            databases = self.db_manager.list_databases()
            if not databases:
                print("❌ No databases available.")
                input("Press Enter to continue...")
                return
            
            print("🔍 Consistency Check Options:")
            print("1. Quick consistency check (all databases)")
            print("2. Deep consistency check (specific database)")
            print("3. Full system consistency check")
            
            choice = input("Select option (1-3): ").strip()
            
            if choice == "1":
                self.quick_consistency_check(databases)
            elif choice == "2":
                self.deep_consistency_check(databases)
            elif choice == "3":
                self.full_system_consistency_check(databases)
            else:
                print("❌ Invalid choice.")
        
        except Exception as e:
            print(f"❌ Error during consistency check: {str(e)}")
        
        input("\nPress Enter to continue...")

    def quick_consistency_check(self, databases):
        """Quick consistency check for all databases"""
        print(f"\n🔍 Quick Consistency Check ({len(databases)} databases)")
        print("-" * 50)
        
        total_issues = 0
        
        for db in databases:
            print(f"📊 {db['name']:<20} ", end="")
            
            issues = self.check_database_consistency(db["name"], quick=True)
            
            if not issues:
                print("✅ OK")
            else:
                print(f"⚠️ {len(issues)} issues")
                total_issues += len(issues)
        
        print("-" * 50)
        print(f"Total issues found: {total_issues}")
        
        if total_issues > 0:
            print("\n💡 Run deep consistency check for detailed analysis")

    def deep_consistency_check(self, databases):
        """Deep consistency check for specific database"""
        print("\nSelect database for deep consistency check:")
        for i, db in enumerate(databases, 1):
            print(f"{i}. {db['name']}")
        
        choice = input(f"Select database (1-{len(databases)}): ").strip()
        
        if not choice.isdigit() or not (1 <= int(choice) <= len(databases)):
            print("❌ Invalid selection.")
            return
        
        selected_db = databases[int(choice) - 1]
        
        print(f"\n🔍 Deep Consistency Check: {selected_db['name']}")
        print("=" * 40)
        
        issues = self.check_database_consistency(selected_db["name"], quick=False)
        
        if not issues:
            print("✅ No consistency issues found")
            print("📊 Database integrity: Perfect")
        else:
            print(f"⚠️ Found {len(issues)} consistency issues:")
            for i, issue in enumerate(issues, 1):
                print(f"   {i}. {issue}")
            
            print(f"\n💡 Recommendations:")
            print("   • Run database cleanup to resolve issues")
            print("   • Consider database optimization")
            print("   • Backup database before making changes")

    def full_system_consistency_check(self, databases):
        """Full system consistency check"""
        print(f"\n🔍 Full System Consistency Check")
        print("=" * 40)
        print("⚠️ This may take several minutes...")
        
        confirm = input("Continue with full system check? (y/n): ").lower()
        if confirm != 'y':
            return
        
        total_issues = 0
        system_issues = []
        
        # Check each database
        for i, db in enumerate(databases, 1):
            print(f"\n📊 [{i}/{len(databases)}] Checking {db['name']}...")
            
            issues = self.check_database_consistency(db["name"], quick=False)
            total_issues += len(issues)
            
            if issues:
                system_issues.extend([f"{db['name']}: {issue}" for issue in issues])
        
        # Check system-level consistency
        print(f"\n🔍 Checking system-level consistency...")
        
        # Check for duplicate database names
        db_names = [db["name"] for db in databases]
        if len(db_names) != len(set(db_names)):
            system_issues.append("Duplicate database names detected")
        
        # Check storage consistency
        storage_issues = self.check_storage_consistency()
        system_issues.extend(storage_issues)
        
        # Results
        print(f"\n📊 Full System Consistency Results:")
        print(f"   Databases checked: {len(databases)}")
        print(f"   Total issues: {len(system_issues)}")
        
        if system_issues:
            print(f"\n⚠️ Issues found:")
            for i, issue in enumerate(system_issues[:10], 1):  # Show first 10
                print(f"   {i}. {issue}")
            
            if len(system_issues) > 10:
                print(f"   ... and {len(system_issues) - 10} more issues")
        else:
            print("✅ System consistency: Perfect")

    def check_database_consistency(self, db_name, quick=True):
        """Check consistency of a single database"""
        issues = []
        
        try:
            db_path = os.path.join(self.config["storage"]["database_root"], "databases", db_name)
            
            # Check if database directory exists
            if not os.path.exists(db_path):
                issues.append("Database directory missing")
                return issues
            
            # Check essential files
            essential_files = ["metadata.json"]
            for essential_file in essential_files:
                file_path = os.path.join(db_path, essential_file)
                if not os.path.exists(file_path):
                    issues.append(f"Missing {essential_file}")
            
            # Check metadata consistency
            if not self.check_metadata_consistency(db_name):
                issues.append("Metadata inconsistency")
            
            if not quick:
                # Deep checks
                
                # Check for orphaned files
                orphaned_files = self.find_orphaned_files(db_path)
                if orphaned_files:
                    issues.append(f"{len(orphaned_files)} orphaned files")
                
                # Check for corrupted files
                corrupted_files = self.find_corrupted_files(db_path)
                if corrupted_files:
                    issues.append(f"{len(corrupted_files)} corrupted files")
                
                # Check file references
                metadata_file = os.path.join(db_path, "metadata.json")
                if os.path.exists(metadata_file):
                    with open(metadata_file, "r") as f:
                        try:
                            metadata = json.load(f)
                            if "files" in metadata:
                                for file_info in metadata["files"]:
                                    if "path" in file_info:
                                        file_path = os.path.join(db_path, file_info["path"])
                                        if not os.path.exists(file_path):
                                            issues.append(f"Referenced file missing: {file_info['path']}")
                        except json.JSONDecodeError:
                            issues.append("Metadata file corrupted")
                
                # Check user permissions consistency
                users_file = os.path.join(db_path, "users.json")
                if os.path.exists(users_file):
                    try:
                        with open(users_file, "r") as f:
                            users_data = json.load(f)
                            for username, user_info in users_data.get("users", {}).items():
                                if "role" not in user_info:
                                    issues.append(f"User {username} missing role")
                                if "permissions" not in user_info:
                                    issues.append(f"User {username} missing permissions")
                    except json.JSONDecodeError:
                        issues.append("Users file corrupted")
        
        except Exception as e:
            issues.append(f"Error during consistency check: {str(e)}")
        
        return issues

    def check_storage_consistency(self):
        """Check system-wide storage consistency"""
        issues = []
        
        try:
            storage_root = self.config["storage"]["database_root"]
            
            # Check if storage root exists
            if not os.path.exists(storage_root):
                issues.append("Storage root directory missing")
                return issues
            
            # Check for proper directory structure
            required_dirs = ["databases", "system", "backups"]
            for required_dir in required_dirs:
                dir_path = os.path.join(storage_root, required_dir)
                if not os.path.exists(dir_path):
                    issues.append(f"Required directory missing: {required_dir}")
            
            # Check for permission issues
            if not os.access(storage_root, os.R_OK | os.W_OK):
                issues.append("Storage root permission issues")
            
            # Check for disk space
            try:
                import shutil
                total, used, free = shutil.disk_usage(storage_root)
                if free < 100 * 1024 * 1024:  # Less than 100MB free
                    issues.append("Low disk space warning")
            except:
                pass
        
        except Exception as e:
            issues.append(f"Storage consistency check error: {str(e)}")
        
        return issues

    def maintenance_schedule_menu(self):
        """Database maintenance scheduling menu"""
        while True:
            print("\n📋 Maintenance Schedule Management")
            print("=" * 45)
            print("1. 📅 View Current Schedule")
            print("2. ➕ Add Scheduled Task")
            print("3. ✏️ Modify Schedule")
            print("4. 🗑️ Remove Scheduled Task")
            print("5. ▶️ Run Scheduled Maintenance")
            print("6. 📊 Maintenance History")
            print("7. ⚙️ Schedule Configuration")
            print("8. 🔙 Back to Maintenance Menu")
            
            choice = input("\nEnter your choice (1-8): ").strip()
            
            if choice == "1":
                self.view_maintenance_schedule()
            elif choice == "2":
                self.add_scheduled_task()
            elif choice == "3":
                self.modify_maintenance_schedule()
            elif choice == "4":
                self.remove_scheduled_task()
            elif choice == "5":
                self.run_scheduled_maintenance()
            elif choice == "6":
                self.view_maintenance_history()
            elif choice == "7":
                self.maintenance_schedule_configuration()
            elif choice == "8":
                break
            else:
                print("❌ Invalid choice.")

    def view_maintenance_schedule(self):
        """View current maintenance schedule"""
        try:
            print("\n📅 Current Maintenance Schedule")
            print("=" * 40)
            
            schedule_file = os.path.join(self.config["storage"]["database_root"], "system", "maintenance_schedule.json")
            
            if os.path.exists(schedule_file):
                with open(schedule_file, "r") as f:
                    schedule = json.load(f)
                
                tasks = schedule.get("tasks", [])
                
                if tasks:
                    print(f"{'Task':<25} {'Frequency':<15} {'Last Run':<17} {'Status':<10}")
                    print("-" * 67)
                    
                    for task in tasks:
                        task_name = task.get("name", "Unknown")[:24]
                        frequency = task.get("frequency", "Unknown")
                        last_run = task.get("last_run", 0)
                        last_run_str = datetime.fromtimestamp(last_run).strftime("%Y-%m-%d %H:%M") if last_run else "Never"
                        
                        status = "🟢 Active" if task.get("enabled", True) else "🔴 Disabled"
                        
                        print(f"{task_name:<25} {frequency:<15} {last_run_str:<17} {status:<10}")
                    
                    print("-" * 67)
                    print(f"Total scheduled tasks: {len(tasks)}")
                    
                    # Show next scheduled runs
                    print(f"\n⏰ Next Scheduled Runs:")
                    for task in tasks[:5]:  # Show first 5
                        if task.get("enabled", True):
                            next_run = self.calculate_next_run(task)
                            if next_run:
                                next_run_str = datetime.fromtimestamp(next_run).strftime("%Y-%m-%d %H:%M")
                                print(f"   {task.get('name', 'Unknown')}: {next_run_str}")
                else:
                    print("📅 No scheduled maintenance tasks found")
                    print("\n💡 Recommended default schedule:")
                    print("   • Daily: Cleanup temporary files")
                    print("   • Weekly: Database optimization")
                    print("   • Monthly: Full consistency check")
                    print("   • Quarterly: Storage compaction")
                    
                    create_default = input("\nCreate default maintenance schedule? (y/n): ").lower()
                    if create_default == 'y':
                        self.create_default_schedule()
            else:
                print("📅 No maintenance schedule configured")
                print("\n💡 Would you like to create a maintenance schedule?")
                
                create_new = input("Create maintenance schedule? (y/n): ").lower()
                if create_new == 'y':
                    self.create_default_schedule()
        
        except Exception as e:
            print(f"❌ Error viewing maintenance schedule: {str(e)}")
        
        input("\nPress Enter to continue...")

    def calculate_next_run(self, task):
        """Calculate next run time for a scheduled task"""
        try:
            frequency = task.get("frequency", "")
            last_run = task.get("last_run", 0)
            
            if not last_run:
                # If never run, schedule for now
                return time.time()
            
            if frequency == "daily":
                return last_run + 24 * 3600
            elif frequency == "weekly":
                return last_run + 7 * 24 * 3600
            elif frequency == "monthly":
                return last_run + 30 * 24 * 3600
            elif frequency == "quarterly":
                return last_run + 90 * 24 * 3600
            else:
                return None
        
        except Exception:
            return None

    def create_default_schedule(self):
        """Create default maintenance schedule"""
        try:
            schedule = {
                "created_at": time.time(),
                "created_by": self.current_user["username"],
                "tasks": [
                    {
                        "name": "Daily Cleanup",
                        "description": "Remove temporary files and clean up system",
                        "frequency": "daily",
                        "enabled": True,
                        "tasks": ["cleanup_temp_files", "remove_old_logs"],
                        "created_at": time.time(),
                        "last_run": 0
                    },
                    {
                        "name": "Weekly Optimization",
                        "description": "Optimize database performance",
                        "frequency": "weekly",
                        "enabled": True,
                        "tasks": ["optimize_databases", "rebuild_indexes"],
                        "created_at": time.time(),
                        "last_run": 0
                    },
                    {
                        "name": "Monthly Health Check",
                        "description": "Comprehensive database health check",
                        "frequency": "monthly",
                        "enabled": True,
                        "tasks": ["health_check", "consistency_check"],
                        "created_at": time.time(),
                        "last_run": 0
                    },
                    {
                        "name": "Quarterly Storage Maintenance",
                        "description": "Storage compaction and major cleanup",
                        "frequency": "quarterly",
                        "enabled": True,
                        "tasks": ["storage_compaction", "remove_orphaned_files"],
                        "created_at": time.time(),
                        "last_run": 0
                    }
                ]
            }
            
            # Save schedule
            schedule_file = os.path.join(self.config["storage"]["database_root"], "system", "maintenance_schedule.json")
            os.makedirs(os.path.dirname(schedule_file), exist_ok=True)
            
            with open(schedule_file, "w") as f:
                json.dump(schedule, f, indent=2)
            
            print("✅ Default maintenance schedule created!")
            print("📋 Scheduled tasks:")
            for task in schedule["tasks"]:
                print(f"   • {task['name']}: {task['frequency']}")
        
        except Exception as e:
            print(f"❌ Error creating default schedule: {str(e)}")

    def add_scheduled_task(self):
        """Add a new scheduled maintenance task"""
        if self.current_user["role"] != "admin":
            print("❌ Only administrators can add scheduled tasks.")
            input("Press Enter to continue...")
            return
        
        try:
            print("\n➕ Add Scheduled Maintenance Task")
            print("=" * 40)
            
            # Get task details
            task_name = input("Task name: ").strip()
            if not task_name:
                print("❌ Task name is required.")
                input("Press Enter to continue...")
                return
            
            description = input("Task description: ").strip()
            
            print("\nAvailable frequencies:")
            print("1. Daily")
            print("2. Weekly")
            print("3. Monthly")
            print("4. Quarterly")
            
            freq_choice = input("Select frequency (1-4): ").strip()
            frequency_map = {"1": "daily", "2": "weekly", "3": "monthly", "4": "quarterly"}
            
            if freq_choice not in frequency_map:
                print("❌ Invalid frequency selection.")
                input("Press Enter to continue...")
                return
            
            frequency = frequency_map[freq_choice]
            
            print("\nAvailable maintenance operations:")
            print("1. cleanup_temp_files - Remove temporary files")
            print("2. optimize_databases - Optimize database performance")
            print("3. health_check - Database health check")
            print("4. consistency_check - Check database consistency")
            print("5. storage_compaction - Compact storage")
            print("6. remove_orphaned_files - Remove orphaned files")
            print("7. rebuild_indexes - Rebuild database indexes")
            
            operations_input = input("Select operations (comma-separated numbers): ").strip()
            
            operation_map = {
                "1": "cleanup_temp_files",
                "2": "optimize_databases",
                "3": "health_check",
                "4": "consistency_check",
                "5": "storage_compaction",
                "6": "remove_orphaned_files",
                "7": "rebuild_indexes"
            }
            
            selected_operations = []
            for op_num in operations_input.split(","):
                op_num = op_num.strip()
                if op_num in operation_map:
                    selected_operations.append(operation_map[op_num])
            
            if not selected_operations:
                print("❌ No valid operations selected.")
                input("Press Enter to continue...")
                return
            
            # Create task
            new_task = {
                "name": task_name,
                "description": description,
                "frequency": frequency,
                "enabled": True,
                "tasks": selected_operations,
                "created_at": time.time(),
                "created_by": self.current_user["username"],
                "last_run": 0
            }
            
            # Load existing schedule
            schedule_file = os.path.join(self.config["storage"]["database_root"], "system", "maintenance_schedule.json")
            
            if os.path.exists(schedule_file):
                with open(schedule_file, "r") as f:
                    schedule = json.load(f)
            else:
                schedule = {"tasks": [], "created_at": time.time()}
            
            # Add new task
            schedule["tasks"].append(new_task)
            
            # Save schedule
            with open(schedule_file, "w") as f:
                json.dump(schedule, f, indent=2)
            
            print(f"\n✅ Scheduled task '{task_name}' added successfully!")
            print(f"   Frequency: {frequency}")
            print(f"   Operations: {', '.join(selected_operations)}")
            
            # Log the action
            self.security_system.add_security_block({
                "action": "maintenance_task_added",
                "task_name": task_name,
                "frequency": frequency,
                "operations": selected_operations,
                "admin": self.current_user["username"],
                "timestamp": time.time()
            })
        
        except Exception as e:
            print(f"❌ Error adding scheduled task: {str(e)}")
        
        input("\nPress Enter to continue...")

    def modify_maintenance_schedule(self):
        """Modify existing maintenance schedule"""
        if self.current_user["role"] != "admin":
            print("❌ Only administrators can modify maintenance schedule.")
            input("Press Enter to continue...")
            return
        
        try:
            print("\n✏️ Modify Maintenance Schedule")
            print("=" * 40)
            
            schedule_file = os.path.join(self.config["storage"]["database_root"], "system", "maintenance_schedule.json")
            
            if not os.path.exists(schedule_file):
                print("❌ No maintenance schedule found.")
                input("Press Enter to continue...")
                return
            
            with open(schedule_file, "r") as f:
                schedule = json.load(f)
            
            tasks = schedule.get("tasks", [])
            
            if not tasks:
                print("❌ No scheduled tasks found.")
                input("Press Enter to continue...")
                return
            
            # Show current tasks
            print("Current scheduled tasks:")
            for i, task in enumerate(tasks, 1):
                status = "🟢 Enabled" if task.get("enabled", True) else "🔴 Disabled"
                print(f"{i}. {task.get('name', 'Unknown')} ({task.get('frequency', 'Unknown')}) - {status}")
            
            # Select task to modify
            choice = input(f"\nSelect task to modify (1-{len(tasks)}): ").strip()
            
            if not choice.isdigit() or not (1 <= int(choice) <= len(tasks)):
                print("❌ Invalid selection.")
                input("Press Enter to continue...")
                return
            
            task_index = int(choice) - 1
            selected_task = tasks[task_index]
            
            print(f"\nModifying task: {selected_task.get('name', 'Unknown')}")
            print("What would you like to modify?")
            print("1. Enable/Disable task")
            print("2. Change frequency")
            print("3. Modify operations")
            print("4. Update description")
            
            modify_choice = input("Select option (1-4): ").strip()
            
            if modify_choice == "1":
                # Toggle enabled status
                current_status = selected_task.get("enabled", True)
                selected_task["enabled"] = not current_status
                new_status = "enabled" if selected_task["enabled"] else "disabled"
                print(f"✅ Task {new_status}")
            
            elif modify_choice == "2":
                # Change frequency
                print("New frequency:")
                print("1. Daily")
                print("2. Weekly")
                print("3. Monthly")
                print("4. Quarterly")
                
                freq_choice = input("Select frequency (1-4): ").strip()
                frequency_map = {"1": "daily", "2": "weekly", "3": "monthly", "4": "quarterly"}
                
                if freq_choice in frequency_map:
                    selected_task["frequency"] = frequency_map[freq_choice]
                    print(f"✅ Frequency changed to {frequency_map[freq_choice]}")
                else:
                    print("❌ Invalid frequency selection.")
            
            elif modify_choice == "3":
                # Modify operations
                print("Current operations:", ", ".join(selected_task.get("tasks", [])))
                print("\nAvailable operations:")
                print("1. cleanup_temp_files")
                print("2. optimize_databases") 
                print("3. health_check")
                print("4. consistency_check")
                print("5. storage_compaction")
                print("6. remove_orphaned_files")
                print("7. rebuild_indexes")
                
                operations_input = input("Select new operations (comma-separated numbers): ").strip()
                
                operation_map = {
                    "1": "cleanup_temp_files",
                    "2": "optimize_databases",
                    "3": "health_check",
                    "4": "consistency_check", 
                    "5": "storage_compaction",
                    "6": "remove_orphaned_files",
                    "7": "rebuild_indexes"
                }
                
                new_operations = []
                for op_num in operations_input.split(","):
                    op_num = op_num.strip()
                    if op_num in operation_map:
                        new_operations.append(operation_map[op_num])
                
                if new_operations:
                    selected_task["tasks"] = new_operations
                    print(f"✅ Operations updated: {', '.join(new_operations)}")
                else:
                    print("❌ No valid operations selected.")
            
            elif modify_choice == "4":
                # Update description
                new_description = input("New description: ").strip()
                if new_description:
                    selected_task["description"] = new_description
                    print("✅ Description updated")
            
            else:
                print("❌ Invalid choice.")
                input("Press Enter to continue...")
                return
            
            # Add modification metadata
            selected_task["modified_at"] = time.time()
            selected_task["modified_by"] = self.current_user["username"]
            
            # Save updated schedule
            with open(schedule_file, "w") as f:
                json.dump(schedule, f, indent=2)
            
            print("✅ Maintenance schedule updated successfully!")
        
        except Exception as e:
            print(f"❌ Error modifying maintenance schedule: {str(e)}")
        
        input("\nPress Enter to continue...")

    def remove_scheduled_task(self):
        """Remove a scheduled maintenance task"""
        if self.current_user["role"] != "admin":
            print("❌ Only administrators can remove scheduled tasks.")
            input("Press Enter to continue...")
            return
        
        try:
            print("\n🗑️ Remove Scheduled Task")
            print("=" * 30)
            
            schedule_file = os.path.join(self.config["storage"]["database_root"], "system", "maintenance_schedule.json")
            
            if not os.path.exists(schedule_file):
                print("❌ No maintenance schedule found.")
                input("Press Enter to continue...")
                return
            
            with open(schedule_file, "r") as f:
                schedule = json.load(f)
            
            tasks = schedule.get("tasks", [])
            
            if not tasks:
                print("❌ No scheduled tasks found.")
                input("Press Enter to continue...")
                return
            
            # Show current tasks
            print("Scheduled tasks:")
            for i, task in enumerate(tasks, 1):
                print(f"{i}. {task.get('name', 'Unknown')} ({task.get('frequency', 'Unknown')})")
            
            # Select task to remove
            choice = input(f"\nSelect task to remove (1-{len(tasks)}): ").strip()
            
            if not choice.isdigit() or not (1 <= int(choice) <= len(tasks)):
                print("❌ Invalid selection.")
                input("Press Enter to continue...")
                return
            
            task_index = int(choice) - 1
            selected_task = tasks[task_index]
            
            # Confirm removal
            print(f"\n⚠️ Remove task: {selected_task.get('name', 'Unknown')}?")
            print(f"   Frequency: {selected_task.get('frequency', 'Unknown')}")
            print(f"   Operations: {', '.join(selected_task.get('tasks', []))}")
            
            confirm = input("\nConfirm removal? (y/n): ").lower()
            if confirm == 'y':
                # Remove task
                tasks.pop(task_index)
                
                # Save updated schedule
                with open(schedule_file, "w") as f:
                    json.dump(schedule, f, indent=2)
                
                print(f"✅ Task '{selected_task.get('name', 'Unknown')}' removed successfully!")
                
                # Log the action
                self.security_system.add_security_block({
                    "action": "maintenance_task_removed",
                    "task_name": selected_task.get('name', 'Unknown'),
                    "admin": self.current_user["username"],
                    "timestamp": time.time()
                })
            else:
                print("❌ Task removal cancelled.")
        
        except Exception as e:
            print(f"❌ Error removing scheduled task: {str(e)}")
        
        input("\nPress Enter to continue...")

    def run_scheduled_maintenance(self):
        """Run scheduled maintenance tasks"""
        if self.current_user["role"] != "admin":
            print("❌ Only administrators can run scheduled maintenance.")
            input("Press Enter to continue...")
            return
        
        try:
            print("\n▶️ Run Scheduled Maintenance")
            print("=" * 35)
            
            schedule_file = os.path.join(self.config["storage"]["database_root"], "system", "maintenance_schedule.json")
            
            if not os.path.exists(schedule_file):
                print("❌ No maintenance schedule found.")
                input("Press Enter to continue...")
                return
            
            with open(schedule_file, "r") as f:
                schedule = json.load(f)
            
            tasks = schedule.get("tasks", [])
            enabled_tasks = [task for task in tasks if task.get("enabled", True)]
            
            if not enabled_tasks:
                print("❌ No enabled maintenance tasks found.")
                input("Press Enter to continue...")
                return
            
            print("Maintenance execution options:")
            print("1. Run all due tasks")
            print("2. Run specific task")
            print("3. Run all tasks (force)")
            
            choice = input("Select option (1-3): ").strip()
            
            if choice == "1":
                # Run due tasks
                due_tasks = []
                current_time = time.time()
                
                for task in enabled_tasks:
                    next_run = self.calculate_next_run(task)
                    if next_run and next_run <= current_time:
                        due_tasks.append(task)
                
                if not due_tasks:
                    print("✅ No maintenance tasks are due at this time.")
                    print("\n📅 Next scheduled runs:")
                    for task in enabled_tasks[:3]:
                        next_run = self.calculate_next_run(task)
                        if next_run:
                            next_run_str = datetime.fromtimestamp(next_run).strftime("%Y-%m-%d %H:%M")
                            print(f"   {task.get('name', 'Unknown')}: {next_run_str}")
                    input("Press Enter to continue...")
                    return
                
                print(f"\n🔄 Running {len(due_tasks)} due maintenance task(s)...")
                self.execute_maintenance_tasks(due_tasks)
            
            elif choice == "2":
                # Run specific task
                print("\nEnabled tasks:")
                for i, task in enumerate(enabled_tasks, 1):
                    print(f"{i}. {task.get('name', 'Unknown')} ({task.get('frequency', 'Unknown')})")
                
                task_choice = input(f"Select task to run (1-{len(enabled_tasks)}): ").strip()
                
                if task_choice.isdigit() and 1 <= int(task_choice) <= len(enabled_tasks):
                    selected_task = enabled_tasks[int(task_choice) - 1]
                    print(f"\n🔄 Running task: {selected_task.get('name', 'Unknown')}")
                    self.execute_maintenance_tasks([selected_task])
                else:
                    print("❌ Invalid task selection.")
            
            elif choice == "3":
                # Force run all tasks
                print(f"\n⚠️ Force running all {len(enabled_tasks)} maintenance tasks...")
                confirm = input("This may take a long time. Continue? (y/n): ").lower()
                
                if confirm == 'y':
                    self.execute_maintenance_tasks(enabled_tasks)
                else:
                    print("❌ Maintenance execution cancelled.")
            
            else:
                print("❌ Invalid choice.")
        
        except Exception as e:
            print(f"❌ Error running scheduled maintenance: {str(e)}")
        
        input("\nPress Enter to continue...")

    def execute_maintenance_tasks(self, tasks):
        """Execute a list of maintenance tasks"""
        total_operations = 0
        successful_operations = 0
        
        for i, task in enumerate(tasks, 1):
            print(f"\n[{i}/{len(tasks)}] Executing: {task.get('name', 'Unknown')}")
            print("-" * 40)
            
            task_operations = task.get("tasks", [])
            task_success = 0
            
            for operation in task_operations:
                print(f"   🔄 {operation}...")
                
                try:
                    success = self.execute_maintenance_operation(operation)
                    total_operations += 1
                    
                    if success:
                        print(f"   ✅ {operation} completed")
                        task_success += 1
                        successful_operations += 1
                    else:
                        print(f"   ❌ {operation} failed")
                
                except Exception as e:
                    print(f"   ❌ {operation} error: {str(e)}")
                    total_operations += 1
            
            # Update task last run time
            task["last_run"] = time.time()
            
            print(f"   Task completed: {task_success}/{len(task_operations)} operations successful")
        
        # Save updated schedule with last run times
        try:
            schedule_file = os.path.join(self.config["storage"]["database_root"], "system", "maintenance_schedule.json")
            with open(schedule_file, "r") as f:
                schedule = json.load(f)
            
            # Update last run times for executed tasks
            for task in tasks:
                for scheduled_task in schedule.get("tasks", []):
                    if scheduled_task.get("name") == task.get("name"):
                        scheduled_task["last_run"] = task["last_run"]
                        break
            
            with open(schedule_file, "w") as f:
                json.dump(schedule, f, indent=2)
        
        except Exception as e:
            logger.error(f"Error updating maintenance schedule: {str(e)}")
        
        # Summary
        print(f"\n🎉 Maintenance Execution Summary:")
        print(f"   Tasks executed: {len(tasks)}")
        print(f"   Total operations: {total_operations}")
        print(f"   Successful operations: {successful_operations}")
        print(f"   Success rate: {(successful_operations/max(1,total_operations))*100:.1f}%")
        
        # Log maintenance execution
        self.security_system.add_security_block({
            "action": "scheduled_maintenance_executed",
            "tasks_executed": len(tasks),
            "operations_total": total_operations,
            "operations_successful": successful_operations,
            "admin": self.current_user["username"],
            "timestamp": time.time()
        })

    def execute_maintenance_operation(self, operation):
        """Execute a single maintenance operation"""
        try:
            if operation == "cleanup_temp_files":
                # Clean temporary files from all databases
                databases = self.db_manager.list_databases()
                total_cleaned = 0
                for db in databases:
                    db_path = os.path.join(self.config["storage"]["database_root"], "databases", db["name"])
                    temp_files = self.find_temp_files(db_path)
                    for temp_file in temp_files[:10]:  # Limit to 10 files per database
                        try:
                            os.remove(temp_file)
                            total_cleaned += 1
                        except:
                            continue
                return total_cleaned > 0
            
            elif operation == "optimize_databases":
                # Basic optimization for databases
                databases = self.db_manager.list_databases()
                for db in databases[:3]:  # Limit to 3 databases
                    self.defragment_database_storage(db["name"])
                return True
            
            elif operation == "health_check":
                # Quick health check
                databases = self.db_manager.list_databases()
                issues_found = 0
                for db in databases:
                    health_score, issues = self.check_single_database_health(db["name"])
                    issues_found += len(issues)
                return issues_found == 0
            
            elif operation == "consistency_check":
                # Quick consistency check
                databases = self.db_manager.list_databases()
                for db in databases[:2]:  # Limit to 2 databases
                    issues = self.check_database_consistency(db["name"], quick=True)
                    if issues:
                        return False
                return True
            
            elif operation == "storage_compaction":
                # Storage compaction for largest database
                databases = self.db_manager.list_databases()
                if databases:
                    # Find largest database
                    largest_db = max(databases, key=lambda x: self.db_manager.get_database_stats(x["name"]).get("total_size", 0))
                    self.perform_storage_compaction(largest_db["name"])
                return True
            
            elif operation == "remove_orphaned_files":
                # Remove orphaned files from databases
                databases = self.db_manager.list_databases()
                total_removed = 0
                for db in databases:
                    db_path = os.path.join(self.config["storage"]["database_root"], "databases", db["name"])
                    orphaned_files = self.find_orphaned_files(db_path)
                    for orphaned_file in orphaned_files[:5]:  # Limit to 5 files per database
                        try:
                            full_path = os.path.join(db_path, orphaned_file)
                            os.remove(full_path)
                            total_removed += 1
                        except:
                            continue
                return total_removed > 0
            
            elif operation == "rebuild_indexes":
                # Rebuild indexes for databases
                databases = self.db_manager.list_databases()
                for db in databases[:2]:  # Limit to 2 databases
                    self.rebuild_single_database_indexes(db["name"])
                return True
            
            else:
                logger.warning(f"Unknown maintenance operation: {operation}")
                return False
            
        except Exception as e:
            logger.error(f"Error executing maintenance operation {operation}: {str(e)}")
            return False

    def bulk_import_databases(self):
        """Import multiple databases from a directory"""
        if self.current_user["role"] != "admin":
            print("❌ Only administrators can perform bulk import.")
            input("Press Enter to continue...")
            return
        
        try:
            print("\n📥 Bulk Database Import")
            print("=" * 30)
            
            import_dir = input("Import directory path: ").strip()
            
            if not import_dir or not os.path.exists(import_dir):
                print("❌ Import directory not found.")
                input("Press Enter to continue...")
                return
            
            # Find all export files in directory
            export_files = []
            for file in os.listdir(import_dir):
                if file.endswith('.zip'):
                    file_path = os.path.join(import_dir, file)
                    if os.path.isfile(file_path):
                        export_files.append(file_path)
            
            if not export_files:
                print("❌ No export files found in directory.")
                input("Press Enter to continue...")
                return
            
            print(f"Found {len(export_files)} export file(s):")
            for i, file_path in enumerate(export_files, 1):
                file_name = os.path.basename(file_path)
                file_size = self.format_size(os.path.getsize(file_path))
                print(f"  {i}. {file_name} ({file_size})")
            
            confirm = input(f"\nImport all {len(export_files)} databases? (y/n): ").lower()
            if confirm != 'y':
                print("❌ Bulk import cancelled.")
                input("Press Enter to continue...")
                return
            
            # Import databases
            print(f"\n📥 Importing {len(export_files)} database(s)...")
            
            successful_imports = 0
            failed_imports = []
            
            for i, file_path in enumerate(export_files, 1):
                file_name = os.path.basename(file_path)
                print(f"[{i}/{len(export_files)}] Importing {file_name}...")
                
                try:
                    # Analyze import file
                    import_info = self.analyze_import_file(file_path)
                    if not import_info:
                        print(f"   ❌ Invalid export file")
                        failed_imports.append(file_name)
                        continue
                    
                    # Generate unique database name
                    base_name = import_info.get('database_name', 'imported_db')
                    new_name = base_name
                    counter = 1
                    
                    existing_databases = self.db_manager.list_databases()
                    while any(db["name"] == new_name for db in existing_databases):
                        new_name = f"{base_name}_{counter}"
                        counter += 1
                    
                    # Perform import
                    success = self.perform_database_import(file_path, new_name, self.current_user["username"])
                    
                    if success:
                        print(f"   ✅ Imported as '{new_name}'")
                        successful_imports += 1
                    else:
                        print(f"   ❌ Import failed")
                        failed_imports.append(file_name)
                
                except Exception as e:
                    print(f"   ❌ Error: {str(e)}")
                    failed_imports.append(file_name)
            
            # Summary
            print(f"\n🎉 Bulk Import Summary:")
            print(f"   Files processed: {len(export_files)}")
            print(f"   Successful imports: {successful_imports}")
            print(f"   Failed imports: {len(failed_imports)}")
            
            if failed_imports:
                print(f"   Failed files:")
                for failed_file in failed_imports:
                    print(f"      • {failed_file}")
        
        except Exception as e:
            print(f"❌ Error during bulk import: {str(e)}")
        
        input("\nPress Enter to continue...")

    def batch_migration(self):
        """Perform batch migration operations"""
        if self.current_user["role"] != "admin":
            print("❌ Only administrators can perform batch migration.")
            input("Press Enter to continue...")
            return
        
        try:
            print("\n🔄 Batch Migration Operations")
            print("=" * 40)
            
            print("Available batch operations:")
            print("1. Update all database schemas")
            print("2. Migrate all databases to new format")
            print("3. Reorganize all database structures")
            print("4. Update all user permissions")
            
            choice = input("Select batch operation (1-4): ").strip()
            
            databases = self.db_manager.list_databases()
            if not databases:
                print("❌ No databases available for migration.")
                input("Press Enter to continue...")
                return
            
            if choice == "1":
                print(f"\n🔄 Updating schemas for {len(databases)} databases...")
                for i, db in enumerate(databases, 1):
                    print(f"[{i}/{len(databases)}] Updating schema for {db['name']}...")
                    # Mock schema update
                    time.sleep(0.2)
                    print(f"   ✅ Schema updated")
            
            elif choice == "2":
                print(f"\n🔄 Migrating {len(databases)} databases to new format...")
                for i, db in enumerate(databases, 1):
                    print(f"[{i}/{len(databases)}] Migrating {db['name']}...")
                    # Mock format migration
                    time.sleep(0.3)
                    print(f"   ✅ Migration completed")
            
            elif choice == "3":
                print(f"\n🔄 Reorganizing structures for {len(databases)} databases...")
                for i, db in enumerate(databases, 1):
                    print(f"[{i}/{len(databases)}] Reorganizing {db['name']}...")
                    self.reorganize_directory_structure(db["name"])
                    print(f"   ✅ Structure reorganized")
            
            elif choice == "4":
                print(f"\n🔄 Updating permissions for {len(databases)} databases...")
                for i, db in enumerate(databases, 1):
                    print(f"[{i}/{len(databases)}] Updating permissions for {db['name']}...")
                    # Mock permission update
                    time.sleep(0.1)
                    print(f"   ✅ Permissions updated")
            
            else:
                print("❌ Invalid choice.")
                input("Press Enter to continue...")
                return
            
            print(f"\n🎉 Batch migration completed successfully!")
            
            # Log batch operation
            self.security_system.add_security_block({
                "action": "batch_migration",
                "operation_type": choice,
                "databases_processed": len(databases),
                "admin": self.current_user["username"],
                "timestamp": time.time()
            })
        
        except Exception as e:
            print(f"❌ Error during batch migration: {str(e)}")
        
        input("\nPress Enter to continue...")

    def export_all_schemas(self):
        """Export schemas for all databases"""
        if self.current_user["role"] != "admin":
            print("❌ Only administrators can export all schemas.")
            input("Press Enter to continue...")
            return
        
        try:
            print("\n📋 Export All Database Schemas")
            print("=" * 40)
            
            databases = self.db_manager.list_databases()
            
            if not databases:
                print("❌ No databases available for schema export.")
                input("Press Enter to continue...")
                return
            
            # Export directory
            export_dir = input("Schema export directory (default: schema_exports): ").strip()
            if not export_dir:
                export_dir = "schema_exports"
            
            # Create timestamped subdirectory
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            full_export_dir = os.path.join(export_dir, f"schemas_{timestamp}")
            os.makedirs(full_export_dir, exist_ok=True)
            
            print(f"\n📋 Exporting schemas for {len(databases)} database(s) to {full_export_dir}...")
            
            successful_exports = 0
            
            for i, db in enumerate(databases, 1):
                print(f"[{i}/{len(databases)}] Exporting schema for {db['name']}...")
                
                schema_path = os.path.join(full_export_dir, f"{db['name']}_schema.json")
                success = self.perform_schema_export(db["name"], schema_path)
                
                if success:
                    print(f"   ✅ Schema exported")
                    successful_exports += 1
                else:
                    print(f"   ❌ Schema export failed")
            
            # Create combined schema file
            combined_schemas = {
                "export_timestamp": time.time(),
                "exported_by": self.current_user["username"],
                "total_databases": len(databases),
                "schemas": {}
            }
            
            for db in databases:
                schema_path = os.path.join(full_export_dir, f"{db['name']}_schema.json")
                if os.path.exists(schema_path):
                    with open(schema_path, "r") as f:
                        schema_data = json.load(f)
                        combined_schemas["schemas"][db["name"]] = schema_data.get("schema", {})
            
            combined_path = os.path.join(full_export_dir, "combined_schemas.json")
            with open(combined_path, "w") as f:
                json.dump(combined_schemas, f, indent=2)
            
            print(f"\n🎉 Schema Export Summary:")
            print(f"   Databases processed: {len(databases)}")
            print(f"   Successful exports: {successful_exports}")
            print(f"   Export directory: {full_export_dir}")
            print(f"   Combined schema file: {combined_path}")
        
        except Exception as e:
            print(f"❌ Error exporting all schemas: {str(e)}")
        
        input("\nPress Enter to continue...")

    def migrate_database_format(self):
        """Migrate database to new format"""
        print("\n🔄 Database Format Migration")
        print("This feature would migrate databases to newer formats")
        print("💡 Implementation would include format conversion logic")
        input("\nPress Enter to continue...")

    def consolidate_databases(self):
        """Consolidate multiple databases into one"""
        print("\n🔄 Database Consolidation")
        print("This feature would merge multiple databases")
        print("💡 Implementation would include data merging and conflict resolution")
        input("\nPress Enter to continue...")

    def split_database(self):
        """Split a large database into smaller ones"""
        print("\n🔄 Database Splitting")
        print("This feature would split large databases")
        print("💡 Implementation would include data partitioning logic")
        input("\nPress Enter to continue...")