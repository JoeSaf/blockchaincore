#!/usr/bin/env python3
"""
Advanced File Upload System with Blockchain Integration
Secure file upload system with GUI, blockchain verification, and integration
with the C++ blockchain node and database management system.
"""

import os
import json
import time
import hashlib
import shutil
import mimetypes
from typing import Dict, List, Optional, Any, Tuple
from pathlib import Path
import tkinter as tk
from tkinter import filedialog, ttk, messagebox
from datetime import datetime
import threading
import logging

logger = logging.getLogger(__name__)

class SecureFileUploader:
    """Secure file upload system with blockchain integration"""
    
    def __init__(self, database_manager, security_system, storage_root: str = "secure_uploads"):
        self.db_manager = database_manager
        self.security_system = security_system
        self.storage_root = storage_root
        self.upload_chain_file = os.path.join(storage_root, "upload_chain.json")
        self.upload_chain = []
        
        self.initialize_storage()
        self.load_upload_chain()
    
    def initialize_storage(self):
        """Initialize secure storage directories"""
        os.makedirs(self.storage_root, exist_ok=True)
        os.makedirs(os.path.join(self.storage_root, "quarantine"), exist_ok=True)
        os.makedirs(os.path.join(self.storage_root, "approved"), exist_ok=True)
        os.makedirs(os.path.join(self.storage_root, "metadata"), exist_ok=True)
        logger.info(f"Secure upload storage initialized at {self.storage_root}")
    
    def load_upload_chain(self):
        """Load the upload operation chain"""
        if os.path.exists(self.upload_chain_file):
            try:
                with open(self.upload_chain_file, "r") as f:
                    self.upload_chain = json.load(f)
                logger.info(f"Loaded {len(self.upload_chain)} upload operations")
            except Exception as e:
                logger.error(f"Failed to load upload chain: {str(e)}")
                self.upload_chain = []
        
        self.save_upload_chain()
    
    def save_upload_chain(self):
        """Save the upload operation chain"""
        try:
            with open(self.upload_chain_file, "w") as f:
                json.dump(self.upload_chain, f, indent=2)
        except Exception as e:
            logger.error(f"Failed to save upload chain: {str(e)}")
    
    def calculate_file_hash(self, file_path: str) -> str:
        """Calculate SHA256 hash of a file"""
        hash_sha256 = hashlib.sha256()
        try:
            with open(file_path, "rb") as f:
                for chunk in iter(lambda: f.read(4096), b""):
                    hash_sha256.update(chunk)
            return hash_sha256.hexdigest()
        except Exception as e:
            logger.error(f"Failed to calculate file hash: {str(e)}")
            return ""
    
    def scan_file_security(self, file_path: str) -> Dict:
        """Perform security scan on uploaded file"""
        scan_result = {
            "safe": True,
            "threats": [],
            "file_type": "unknown",
            "size": 0,
            "hash": ""
        }
        
        try:
            # Get file info
            file_size = os.path.getsize(file_path)
            file_hash = self.calculate_file_hash(file_path)
            file_type, _ = mimetypes.guess_type(file_path)
            
            scan_result.update({
                "size": file_size,
                "hash": file_hash,
                "file_type": file_type or "unknown"
            })
            
            # Basic security checks
            
            # Check file size (max 100MB)
            if file_size > 100 * 1024 * 1024:
                scan_result["safe"] = False
                scan_result["threats"].append("file_too_large")
            
            # Check for suspicious extensions
            dangerous_extensions = ['.exe', '.bat', '.cmd', '.com', '.pif', '.scr', '.vbs', '.js']
            if any(file_path.lower().endswith(ext) for ext in dangerous_extensions):
                scan_result["safe"] = False
                scan_result["threats"].append("dangerous_file_type")
            
            # Check for double extensions (like .txt.exe)
            if file_path.count('.') > 1:
                extensions = [ext for ext in file_path.split('.')[1:]]
                if any(ext.lower() in ['exe', 'bat', 'cmd'] for ext in extensions[:-1]):
                    scan_result["safe"] = False
                    scan_result["threats"].append("double_extension")
            
            # Simple content-based checks
            if file_type and file_type.startswith('text/'):
                try:
                    with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                        content = f.read(1024)  # Read first 1KB
                        
                        # Check for suspicious patterns
                        suspicious_patterns = ['<script>', 'javascript:', 'eval(', 'document.write']
                        if any(pattern in content.lower() for pattern in suspicious_patterns):
                            scan_result["safe"] = False
                            scan_result["threats"].append("suspicious_content")
                except Exception:
                    pass
        
        except Exception as e:
            logger.error(f"Security scan failed: {str(e)}")
            scan_result["safe"] = False
            scan_result["threats"].append("scan_error")
        
        return scan_result
    
    def upload_file(self, file_path: str, username: str, database_name: str = None, metadata: Dict = None) -> Dict:
        """Upload a file with security scanning and blockchain verification"""
        try:
            upload_id = hashlib.sha256(f"{file_path}{username}{time.time()}".encode()).hexdigest()
            
            # Perform security scan
            scan_result = self.scan_file_security(file_path)
            
            # Determine destination based on scan result
            if scan_result["safe"]:
                dest_dir = os.path.join(self.storage_root, "approved")
                status = "approved"
            else:
                dest_dir = os.path.join(self.storage_root, "quarantine")
                status = "quarantined"
            
            # Generate unique filename
            timestamp = int(time.time())
            original_name = os.path.basename(file_path)
            stored_name = f"{timestamp}_{upload_id[:8]}_{original_name}"
            stored_path = os.path.join(dest_dir, stored_name)
            
            # Copy file to secure location
            shutil.copy2(file_path, stored_path)
            
            # Create upload metadata
            upload_metadata = {
                "upload_id": upload_id,
                "original_name": original_name,
                "stored_name": stored_name,
                "stored_path": stored_path,
                "uploaded_by": username,
                "uploaded_at": time.time(),
                "status": status,
                "database": database_name,
                "scan_result": scan_result,
                "metadata": metadata or {},
                "blockchain_verified": False
            }
            
            # Save metadata
            metadata_file = os.path.join(self.storage_root, "metadata", f"{upload_id}.json")
            with open(metadata_file, "w") as f:
                json.dump(upload_metadata, f, indent=2)
            
            # Add to upload chain
            self.upload_chain.append(upload_metadata)
            self.save_upload_chain()
            
            # Try to store in database if specified
            if database_name and scan_result["safe"]:
                try:
                    db_result = self.db_manager.store_file_in_database(
                        database_name, stored_path, username, upload_metadata
                    )
                    if db_result:
                        upload_metadata["database_stored"] = True
                        upload_metadata["database_path"] = db_result
                except Exception as e:
                    logger.warning(f"Failed to store in database: {str(e)}")
                    upload_metadata["database_stored"] = False
            
            # Log security event
            self.security_system.add_security_block({
                "action": "file_upload",
                "upload_id": upload_id,
                "filename": original_name,
                "username": username,
                "status": status,
                "threats": scan_result["threats"],
                "timestamp": time.time()
            })
            
            upload_result = {
                "success": True,
                "upload_id": upload_id,
                "status": status,
                "stored_path": stored_path,
                "threats": scan_result["threats"],
                "metadata": upload_metadata
            }
            
            logger.info(f"File uploaded: {original_name} - Status: {status}")
            return upload_result
            
        except Exception as e:
            logger.error(f"File upload failed: {str(e)}")
            return {
                "success": False,
                "error": str(e),
                "upload_id": None
            }
    
    def get_user_uploads(self, username: str) -> List[Dict]:
        """Get all uploads for a specific user"""
        return [upload for upload in self.upload_chain if upload["uploaded_by"] == username]
    
    def approve_quarantined_file(self, upload_id: str, admin_username: str) -> bool:
        """Approve a quarantined file (admin only)"""
        try:
            # Find upload
            upload = next((u for u in self.upload_chain if u["upload_id"] == upload_id), None)
            if not upload:
                logger.error(f"Upload {upload_id} not found")
                return False
            
            if upload["status"] != "quarantined":
                logger.error(f"Upload {upload_id} is not quarantined")
                return False
            
            # Move file from quarantine to approved
            quarantine_path = upload["stored_path"]
            approved_path = quarantine_path.replace("quarantine", "approved")
            
            shutil.move(quarantine_path, approved_path)
            
            # Update metadata
            upload["status"] = "approved"
            upload["stored_path"] = approved_path
            upload["approved_by"] = admin_username
            upload["approved_at"] = time.time()
            
            self.save_upload_chain()
            
            # Log security event
            self.security_system.add_security_block({
                "action": "file_approved",
                "upload_id": upload_id,
                "approved_by": admin_username,
                "timestamp": time.time()
            })
            
            logger.info(f"File approved: {upload['original_name']} by {admin_username}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to approve file: {str(e)}")
            return False
    
    def delete_upload(self, upload_id: str, username: str) -> bool:
        """Delete an uploaded file"""
        try:
            # Find upload
            upload = next((u for u in self.upload_chain if u["upload_id"] == upload_id), None)
            if not upload:
                logger.error(f"Upload {upload_id} not found")
                return False
            
            # Check permissions
            if upload["uploaded_by"] != username and not self.security_system.users.get(username, {}).get("role") == "admin":
                logger.error(f"User {username} not authorized to delete upload {upload_id}")
                return False
            
            # Delete file
            if os.path.exists(upload["stored_path"]):
                os.remove(upload["stored_path"])
            
            # Delete metadata
            metadata_file = os.path.join(self.storage_root, "metadata", f"{upload_id}.json")
            if os.path.exists(metadata_file):
                os.remove(metadata_file)
            
            # Remove from chain
            self.upload_chain = [u for u in self.upload_chain if u["upload_id"] != upload_id]
            self.save_upload_chain()
            
            # Log security event
            self.security_system.add_security_block({
                "action": "file_deleted",
                "upload_id": upload_id,
                "deleted_by": username,
                "timestamp": time.time()
            })
            
            logger.info(f"File deleted: {upload['original_name']} by {username}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to delete file: {str(e)}")
            return False

class FileUploadGUI:
    """Advanced GUI for file upload system"""
    
    def __init__(self, file_uploader: SecureFileUploader, username: str, user_role: str):
        self.file_uploader = file_uploader
        self.username = username
        self.user_role = user_role
        self.selected_files = []
        
        self.root = tk.Tk()
        self.root.title(f"Secure File Upload - {username}")
        self.root.geometry("900x700")
        self.root.configure(bg='#f0f0f0')
        
        self.setup_gui()
    
    def setup_gui(self):
        """Setup the GUI components"""
        # Main frame
        main_frame = ttk.Frame(self.root, padding="10")
        main_frame.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        
        # Title
        title_label = ttk.Label(main_frame, text="🔒 Secure File Upload System", 
                               font=("Arial", 16, "bold"))
        title_label.grid(row=0, column=0, columnspan=3, pady=10)
        
        # User info
        user_info = ttk.Label(main_frame, text=f"Logged in as: {self.username} ({self.user_role})")
        user_info.grid(row=1, column=0, columnspan=3, pady=5)
        
        # Database selection
        db_frame = ttk.LabelFrame(main_frame, text="Target Database", padding="5")
        db_frame.grid(row=2, column=0, columnspan=3, sticky=(tk.W, tk.E), pady=10)
        
        self.database_var = tk.StringVar()
        self.database_combo = ttk.Combobox(db_frame, textvariable=self.database_var, width=30)
        self.database_combo.grid(row=0, column=0, padx=5)
        
        refresh_db_btn = ttk.Button(db_frame, text="Refresh", command=self.refresh_databases)
        refresh_db_btn.grid(row=0, column=1, padx=5)
        
        # File selection area
        file_frame = ttk.LabelFrame(main_frame, text="Selected Files", padding="5")
        file_frame.grid(row=3, column=0, columnspan=3, sticky=(tk.W, tk.E, tk.N, tk.S), pady=10)
        
        # File list with details
        columns = ('filename', 'size', 'type', 'status')
        self.file_tree = ttk.Treeview(file_frame, columns=columns, show='headings', height=8)
        
        self.file_tree.heading('filename', text='Filename')
        self.file_tree.heading('size', text='Size')
        self.file_tree.heading('type', text='Type')
        self.file_tree.heading('status', text='Status')
        
        self.file_tree.column('filename', width=300)
        self.file_tree.column('size', width=100)
        self.file_tree.column('type', width=100)
        self.file_tree.column('status', width=100)
        
        # Scrollbar for file list
        file_scrollbar = ttk.Scrollbar(file_frame, orient=tk.VERTICAL, command=self.file_tree.yview)
        self.file_tree.configure(yscrollcommand=file_scrollbar.set)
        
        self.file_tree.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        file_scrollbar.grid(row=0, column=1, sticky=(tk.N, tk.S))
        
        # File operation buttons
        btn_frame = ttk.Frame(main_frame)
        btn_frame.grid(row=4, column=0, columnspan=3, pady=10)
        
        add_files_btn = ttk.Button(btn_frame, text="Add Files", command=self.add_files)
        add_files_btn.grid(row=0, column=0, padx=5)
        
        remove_files_btn = ttk.Button(btn_frame, text="Remove Selected", command=self.remove_selected)
        remove_files_btn.grid(row=0, column=1, padx=5)
        
        clear_all_btn = ttk.Button(btn_frame, text="Clear All", command=self.clear_all)
        clear_all_btn.grid(row=0, column=2, padx=5)
        
        upload_btn = ttk.Button(btn_frame, text="🚀 Upload Files", command=self.upload_files)
        upload_btn.grid(row=0, column=3, padx=5)
        
        # Upload history
        history_frame = ttk.LabelFrame(main_frame, text="Upload History", padding="5")
        history_frame.grid(row=5, column=0, columnspan=3, sticky=(tk.W, tk.E, tk.N, tk.S), pady=10)
        
        history_columns = ('filename', 'uploaded_at', 'status', 'database')
        self.history_tree = ttk.Treeview(history_frame, columns=history_columns, show='headings', height=6)
        
        for col in history_columns:
            self.history_tree.heading(col, text=col.replace('_', ' ').title())
            self.history_tree.column(col, width=150)
        
        history_scrollbar = ttk.Scrollbar(history_frame, orient=tk.VERTICAL, command=self.history_tree.yview)
        self.history_tree.configure(yscrollcommand=history_scrollbar.set)
        
        self.history_tree.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        history_scrollbar.grid(row=0, column=1, sticky=(tk.N, tk.S))
        
        # History buttons
        history_btn_frame = ttk.Frame(history_frame)
        history_btn_frame.grid(row=1, column=0, pady=5)
        
        refresh_history_btn = ttk.Button(history_btn_frame, text="Refresh", command=self.refresh_history)
        refresh_history_btn.grid(row=0, column=0, padx=5)
        
        if self.user_role == "admin":
            approve_btn = ttk.Button(history_btn_frame, text="Approve Selected", command=self.approve_selected)
            approve_btn.grid(row=0, column=1, padx=5)
        
        delete_btn = ttk.Button(history_btn_frame, text="Delete Selected", command=self.delete_selected)
        delete_btn.grid(row=0, column=2, padx=5)
        
        # Status bar
        self.status_var = tk.StringVar()
        self.status_var.set("Ready")
        status_bar = ttk.Label(main_frame, textvariable=self.status_var, relief=tk.SUNKEN, anchor=tk.W)
        status_bar.grid(row=6, column=0, columnspan=3, sticky=(tk.W, tk.E), pady=5)
        
        # Configure grid weights
        self.root.columnconfigure(0, weight=1)
        self.root.rowconfigure(0, weight=1)
        main_frame.columnconfigure(0, weight=1)
        main_frame.rowconfigure(3, weight=1)
        main_frame.rowconfigure(5, weight=1)
        file_frame.columnconfigure(0, weight=1)
        file_frame.rowconfigure(0, weight=1)
        history_frame.columnconfigure(0, weight=1)
        history_frame.rowconfigure(0, weight=1)
        
        # Initialize data
        self.refresh_databases()
        self.refresh_history()
    
    def refresh_databases(self):
        """Refresh the database list"""
        try:
            databases = self.file_uploader.db_manager.list_databases(self.username, self.user_role)
            db_names = [db["name"] for db in databases]
            self.database_combo['values'] = db_names
            if db_names:
                self.database_combo.set(db_names[0])
            self.status_var.set(f"Found {len(db_names)} databases")
        except Exception as e:
            self.status_var.set(f"Error loading databases: {str(e)}")
    
    def add_files(self):
        """Add files to upload queue"""
        files = filedialog.askopenfilenames(
            title="Select Files to Upload",
            filetypes=[
                ("All Files", "*.*"),
                ("Documents", "*.pdf *.doc *.docx *.txt"),
                ("Images", "*.png *.jpg *.jpeg *.gif *.bmp"),
                ("Data Files", "*.json *.csv *.xml *.xlsx"),
                ("Code Files", "*.py *.js *.html *.css *.cpp *.h")
            ]
        )
        
        for file_path in files:
            if file_path not in [f["path"] for f in self.selected_files]:
                file_info = self.get_file_info(file_path)
                self.selected_files.append(file_info)
                
                # Add to tree view
                self.file_tree.insert('', 'end', values=(
                    file_info["name"],
                    file_info["size_str"],
                    file_info["type"],
                    "Pending"
                ))
        
        self.status_var.set(f"Selected {len(self.selected_files)} files")
    
    def get_file_info(self, file_path: str) -> Dict:
        """Get file information"""
        try:
            stat = os.stat(file_path)
            size = stat.st_size
            size_str = self.format_size(size)
            file_type = mimetypes.guess_type(file_path)[0] or "Unknown"
            
            return {
                "path": file_path,
                "name": os.path.basename(file_path),
                "size": size,
                "size_str": size_str,
                "type": file_type,
                "modified": stat.st_mtime
            }
        except Exception as e:
            return {
                "path": file_path,
                "name": os.path.basename(file_path),
                "size": 0,
                "size_str": "Unknown",
                "type": "Unknown",
                "modified": 0,
                "error": str(e)
            }
    
    def format_size(self, size_bytes: int) -> str:
        """Format file size in human readable format"""
        for unit in ['B', 'KB', 'MB', 'GB']:
            if size_bytes < 1024.0:
                return f"{size_bytes:.1f} {unit}"
            size_bytes /= 1024.0
        return f"{size_bytes:.1f} TB"
    
    def remove_selected(self):
        """Remove selected files from upload queue"""
        selected_items = self.file_tree.selection()
        for item in selected_items:
            index = self.file_tree.index(item)
            self.file_tree.delete(item)
            if 0 <= index < len(self.selected_files):
                self.selected_files.pop(index)
        
        self.status_var.set(f"Selected {len(self.selected_files)} files")
    
    def clear_all(self):
        """Clear all selected files"""
        self.file_tree.delete(*self.file_tree.get_children())
        self.selected_files.clear()
        self.status_var.set("All files cleared")
    
    def upload_files(self):
        """Upload all selected files"""
        if not self.selected_files:
            messagebox.showwarning("No Files", "Please select files to upload")
            return
        
        database_name = self.database_var.get() if self.database_var.get() else None
        
        # Show progress dialog
        progress_window = tk.Toplevel(self.root)
        progress_window.title("Uploading Files")
        progress_window.geometry("400x200")
        progress_window.transient(self.root)
        progress_window.grab_set()
        
        progress_label = ttk.Label(progress_window, text="Preparing upload...")
        progress_label.pack(pady=10)
        
        progress_bar = ttk.Progressbar(progress_window, mode='determinate', maximum=len(self.selected_files))
        progress_bar.pack(pady=10, padx=20, fill=tk.X)
        
        result_text = tk.Text(progress_window, height=8, width=50)
        result_text.pack(pady=10, padx=20, fill=tk.BOTH, expand=True)
        
        def upload_thread():
            """Upload files in separate thread"""
            successful_uploads = 0
            failed_uploads = 0
            
            for i, file_info in enumerate(self.selected_files):
                progress_label.config(text=f"Uploading: {file_info['name']}")
                progress_bar['value'] = i
                progress_window.update()
                
                try:
                    result = self.file_uploader.upload_file(
                        file_info["path"],
                        self.username,
                        database_name,
                        {"gui_upload": True, "upload_session": time.time()}
                    )
                    
                    if result["success"]:
                        successful_uploads += 1
                        status = "✅ " + result["status"].upper()
                        if result["threats"]:
                            status += f" (Threats: {', '.join(result['threats'])})"
                    else:
                        failed_uploads += 1
                        status = "❌ FAILED: " + result.get("error", "Unknown error")
                    
                    result_text.insert(tk.END, f"{file_info['name']}: {status}\n")
                    result_text.see(tk.END)
                    
                except Exception as e:
                    failed_uploads += 1
                    result_text.insert(tk.END, f"{file_info['name']}: ❌ ERROR: {str(e)}\n")
                    result_text.see(tk.END)
                
                progress_window.update()
            
            progress_bar['value'] = len(self.selected_files)
            progress_label.config(text=f"Complete! ✅ {successful_uploads} success, ❌ {failed_uploads} failed")
            
            # Add close button
            close_btn = ttk.Button(progress_window, text="Close", 
                                 command=lambda: [progress_window.destroy(), self.refresh_history(), self.clear_all()])
            close_btn.pack(pady=10)
        
        # Start upload in thread
        threading.Thread(target=upload_thread, daemon=True).start()
    
    def refresh_history(self):
        """Refresh upload history"""
        try:
            # Clear existing items
            self.history_tree.delete(*self.history_tree.get_children())
            
            # Get user uploads
            uploads = self.file_uploader.get_user_uploads(self.username)
            
            # Add admin view for all uploads if admin
            if self.user_role == "admin":
                all_uploads = self.file_uploader.upload_chain
                uploads = all_uploads
            
            # Sort by upload time (newest first)
            uploads.sort(key=lambda x: x.get("uploaded_at", 0), reverse=True)
            
            for upload in uploads:
                uploaded_at = datetime.fromtimestamp(upload.get("uploaded_at", 0)).strftime("%Y-%m-%d %H:%M")
                database = upload.get("database", "None")
                status = upload.get("status", "unknown")
                
                # Add status indicators
                if status == "approved":
                    status = "✅ Approved"
                elif status == "quarantined":
                    status = "🔒 Quarantined"
                elif status == "deleted":
                    status = "🗑️ Deleted"
                
                self.history_tree.insert('', 'end', values=(
                    upload.get("original_name", "Unknown"),
                    uploaded_at,
                    status,
                    database
                ), tags=(upload.get("upload_id"),))
            
            self.status_var.set(f"Loaded {len(uploads)} upload records")
            
        except Exception as e:
            self.status_var.set(f"Error loading history: {str(e)}")
    
    def approve_selected(self):
        """Approve selected quarantined files (admin only)"""
        if self.user_role != "admin":
            messagebox.showerror("Access Denied", "Only administrators can approve files")
            return
        
        selected_items = self.history_tree.selection()
        if not selected_items:
            messagebox.showwarning("No Selection", "Please select files to approve")
            return
        
        approved_count = 0
        for item in selected_items:
            upload_id = self.history_tree.item(item)["tags"][0] if self.history_tree.item(item)["tags"] else None
            if upload_id:
                if self.file_uploader.approve_quarantined_file(upload_id, self.username):
                    approved_count += 1
        
        messagebox.showinfo("Approval Complete", f"Approved {approved_count} files")
        self.refresh_history()
    
    def delete_selected(self):
        """Delete selected uploads"""
        selected_items = self.history_tree.selection()
        if not selected_items:
            messagebox.showwarning("No Selection", "Please select files to delete")
            return
        
        if messagebox.askyesno("Confirm Delete", "Are you sure you want to delete the selected files?"):
            deleted_count = 0
            for item in selected_items:
                upload_id = self.history_tree.item(item)["tags"][0] if self.history_tree.item(item)["tags"] else None
                if upload_id:
                    if self.file_uploader.delete_upload(upload_id, self.username):
                        deleted_count += 1
            
            messagebox.showinfo("Deletion Complete", f"Deleted {deleted_count} files")
            self.refresh_history()
    
    def show(self):
        """Show the GUI"""
        self.root.mainloop()

def create_upload_interface(database_manager, security_system, username: str, user_role: str):
    """Create and show the file upload interface"""
    file_uploader = SecureFileUploader(database_manager, security_system)
    gui = FileUploadGUI(file_uploader, username, user_role)
    return gui

def demonstrate_file_upload_system(database_manager, security_system):
    """Demonstrate the file upload system"""
    print("\n📁 Secure File Upload System Demo")
    print("=" * 50)
    
    # Create file uploader
    file_uploader = SecureFileUploader(database_manager, security_system)
    
    print("1. System initialized")
    print(f"   Storage root: {file_uploader.storage_root}")
    print(f"   Upload chain length: {len(file_uploader.upload_chain)}")
    
    # Create a test file
    test_file = "test_upload.txt"
    with open(test_file, "w") as f:
        f.write("This is a test file for upload demonstration.\n")
        f.write(f"Created at: {datetime.now()}\n")
    
    print(f"\n2. Created test file: {test_file}")
    
    # Upload the test file
    print("3. Uploading test file...")
    result = file_uploader.upload_file(test_file, "demo_user", None, {"demo": True})
    
    if result["success"]:
        print(f"   ✅ Upload successful!")
        print(f"   Upload ID: {result['upload_id']}")
        print(f"   Status: {result['status']}")
        print(f"   Stored at: {result['stored_path']}")
        if result["threats"]:
            print(f"   ⚠️  Threats detected: {', '.join(result['threats'])}")
    else:
        print(f"   ❌ Upload failed: {result.get('error', 'Unknown error')}")
    
    # Show upload history
    print("\n4. Upload history:")
    uploads = file_uploader.get_user_uploads("demo_user")
    for upload in uploads:
        print(f"   📄 {upload['original_name']} - {upload['status']} - {datetime.fromtimestamp(upload['uploaded_at'])}")
    
    # Clean up test file
    try:
        os.remove(test_file)
        print(f"\n5. Cleaned up test file: {test_file}")
    except Exception:
        pass
    
    print("\n🎉 File upload system demo completed!")

if __name__ == "__main__":
    # Demo the file upload system
    from blockchain_bridge import BlockchainBridge
    from database_manager import IntegratedDatabaseManager
    from security_auth import PolymorphicSecuritySystem, initialize_security_system
    
    print("📁 Starting Secure File Upload System...")
    
    # Initialize components
    bridge = BlockchainBridge()
    db_manager = IntegratedDatabaseManager(bridge)
    security_system = initialize_security_system(bridge)
    
    # Run demonstration
    demonstrate_file_upload_system(db_manager, security_system)
    
    # Optionally show GUI (uncomment to test)
    # gui = create_upload_interface(db_manager, security_system, "admin", "admin")
    # gui.show()