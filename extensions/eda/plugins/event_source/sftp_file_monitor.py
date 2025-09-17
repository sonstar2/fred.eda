"""
SFTP File Monitor Event Source Plugin for Ansible EDA

This plugin monitors an SFTP server for new files and sends events when files are created.
"""

import asyncio
import logging
import os
import time
from datetime import datetime
from typing import Any, Dict, List, Optional

try:
    import paramiko
    from paramiko import SSHClient, SFTPClient
    HAS_PARAMIKO = True
except ImportError:
    HAS_PARAMIKO = False


DOCUMENTATION = """
---
module: sftp_file_monitor
author:
  - Your Name (@yourusername)
version_added: "1.0.0"
short_description: Monitor SFTP server for new files
description:
  - This event source plugin monitors an SFTP server directory for new files
  - Sends events when new files are detected in the monitored path
  - Supports SSH key and password authentication
  - Provides comprehensive file metadata in events

options:
  host:
    description: SFTP server hostname or IP address
    type: str
    required: true
  port:
    description: SFTP server port
    type: int
    default: 22
  username:
    description: Username for SFTP authentication
    type: str
    required: true
  password:
    description: Password for authentication (if not using SSH key)
    type: str
    required: false
  ssh_key_path:
    description: Path to SSH private key file
    type: str
    required: false
  ssh_key_passphrase:
    description: Passphrase for SSH private key
    type: str
    required: false
  monitor_path:
    description: Path on SFTP server to monitor for new files
    type: str
    default: "/opt/sftp/SFTPUser/"
  poll_interval:
    description: Interval in seconds between checks for new files
    type: int
    default: 30
  file_extensions:
    description: List of file extensions to monitor (empty means all files)
    type: list
    elements: str
    default: []
  recursive:
    description: Whether to monitor subdirectories recursively
    type: bool
    default: false
  connect_timeout:
    description: Connection timeout in seconds
    type: int
    default: 30
  banner_timeout:
    description: SSH banner timeout in seconds
    type: int
    default: 30
  max_retries:
    description: Maximum number of connection retry attempts
    type: int
    default: 3
  retry_delay:
    description: Delay between retry attempts in seconds
    type: int
    default: 5

requirements:
  - paramiko>=2.7.0

notes:
  - Either password or ssh_key_path must be provided for authentication
  - The plugin maintains state to track new files between polling intervals
  - Connection failures trigger automatic reconnection attempts
  - Large directories may impact performance; consider using file_extensions filter
"""

EXAMPLES = """
# Monitor SFTP server with password authentication
- name: Monitor SFTP server for new files
  mycompany.sftp_eda.sftp_file_monitor:
    host: "sftp.example.com"
    username: "monitoring_user"
    password: "{{ sftp_password }}"
    monitor_path: "/opt/sftp/SFTPUser/"
    poll_interval: 60

# Monitor with SSH key authentication and file filtering
- name: Monitor SFTP with SSH key
  mycompany.sftp_eda.sftp_file_monitor:
    host: "192.168.1.100"
    port: 2222
    username: "sftpuser"
    ssh_key_path: "/home/user/.ssh/id_rsa"
    ssh_key_passphrase: "{{ ssh_key_pass }}"
    monitor_path: "/opt/sftp/SFTPUser/"
    file_extensions: [".txt", ".csv", ".json", ".xml"]
    recursive: true
    poll_interval: 30

# Monitor with advanced connection settings
- name: Monitor SFTP with custom timeouts
  mycompany.sftp_eda.sftp_file_monitor:
    host: "sftp-slow.example.com"
    username: "user"
    password: "{{ password }}"
    monitor_path: "/data/incoming/"
    connect_timeout: 60
    banner_timeout: 60
    max_retries: 5
    retry_delay: 10
"""


class SFTPFileMonitor:
    """SFTP File Monitor for detecting new files"""
    
    def __init__(self, config: Dict[str, Any], logger: logging.Logger):
        self.config = config
        self.logger = logger
        
        # Check paramiko availability
        if not HAS_PARAMIKO:
            raise ImportError(
                "The paramiko library is required for this plugin. "
                "Install it with: pip install paramiko"
            )
        
        # SFTP connection parameters
        self.host = config.get("host")
        self.port = config.get("port", 22)
        self.username = config.get("username")
        self.password = config.get("password")
        self.ssh_key_path = config.get("ssh_key_path")
        self.ssh_key_passphrase = config.get("ssh_key_passphrase")
        
        # Connection settings
        self.connect_timeout = config.get("connect_timeout", 30)
        self.banner_timeout = config.get("banner_timeout", 30)
        self.max_retries = config.get("max_retries", 3)
        self.retry_delay = config.get("retry_delay", 5)
        
        # Monitor configuration
        self.monitor_path = config.get("monitor_path", "/opt/sftp/SFTPUser/")
        self.poll_interval = config.get("poll_interval", 30)
        self.file_extensions = config.get("file_extensions", [])
        self.recursive = config.get("recursive", False)
        
        # State tracking
        self.known_files = {}
        self.ssh_client = None
        self.sftp_client = None
        self.is_running = False
        
        # Validate configuration
        self._validate_config()
    
    def _validate_config(self):
        """Validate the plugin configuration"""
        if not self.host:
            raise ValueError("host parameter is required")
        if not self.username:
            raise ValueError("username parameter is required")
        if not self.password and not self.ssh_key_path:
            raise ValueError("Either password or ssh_key_path must be provided")
        if self.poll_interval < 1:
            raise ValueError("poll_interval must be at least 1 second")
        if self.max_retries < 0:
            raise ValueError("max_retries must be non-negative")
    
    def _connect_sftp(self) -> bool:
        """Establish SFTP connection with retry logic"""
        for attempt in range(self.max_retries + 1):
            try:
                self.logger.info(f"Connecting to SFTP server {self.host}:{self.port} "
                               f"(attempt {attempt + 1}/{self.max_retries + 1})")
                
                self.ssh_client = SSHClient()
                self.ssh_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
                
                # Prepare connection parameters
                connect_params = {
                    "hostname": self.host,
                    "port": self.port,
                    "username": self.username,
                    "timeout": self.connect_timeout,
                    "banner_timeout": self.banner_timeout,
                    "look_for_keys": False,
                    "allow_agent": False,
                }
                
                # Use SSH key if provided, otherwise use password
                if self.ssh_key_path:
                    if not os.path.exists(self.ssh_key_path):
                        raise FileNotFoundError(f"SSH key file not found: {self.ssh_key_path}")
                    
                    try:
                        if self.ssh_key_passphrase:
                            key = paramiko.RSAKey.from_private_key_file(
                                self.ssh_key_path, password=self.ssh_key_passphrase
                            )
                        else:
                            key = paramiko.RSAKey.from_private_key_file(self.ssh_key_path)
                        connect_params["pkey"] = key
                    except paramiko.PasswordRequiredException:
                        self.logger.error("SSH key requires a passphrase")
                        return False
                    except Exception as e:
                        self.logger.error(f"Error loading SSH key: {e}")
                        return False
                else:
                    connect_params["password"] = self.password
                
                # Establish SSH connection
                self.ssh_client.connect(**connect_params)
                self.sftp_client = self.ssh_client.open_sftp()
                
                # Test the connection by listing the monitor path
                try:
                    self.sftp_client.listdir(self.monitor_path)
                except FileNotFoundError:
                    self.logger.error(f"Monitor path does not exist: {self.monitor_path}")
                    self._cleanup_connection()
                    return False
                except PermissionError:
                    self.logger.error(f"Permission denied accessing: {self.monitor_path}")
                    self._cleanup_connection()
                    return False
                
                self.logger.info(f"Successfully connected to SFTP server {self.host}:{self.port}")
                return True
                
            except Exception as e:
                self.logger.warning(f"Connection attempt {attempt + 1} failed: {e}")
                self._cleanup_connection()
                
                if attempt < self.max_retries:
                    self.logger.info(f"Retrying in {self.retry_delay} seconds...")
                    time.sleep(self.retry_delay)
                else:
                    self.logger.error(f"Failed to connect after {self.max_retries + 1} attempts")
                    return False
        
        return False
    
    def _cleanup_connection(self):
        """Clean up SFTP and SSH connections"""
        if self.sftp_client:
            try:
                self.sftp_client.close()
            except Exception:
                pass
            self.sftp_client = None
        
        if self.ssh_client:
            try:
                self.ssh_client.close()
            except Exception:
                pass
            self.ssh_client = None
    
    def _should_monitor_file(self, filename: str) -> bool:
        """Check if file should be monitored based on extensions filter"""
        if not self.file_extensions:
            return True
        
        file_ext = os.path.splitext(filename)[1].lower()
        return file_ext in [ext.lower() for ext in self.file_extensions]
    
    def _get_files_recursive(self, path: str) -> List[Dict[str, Any]]:
        """Get files recursively from the given path"""
        files = []
        
        try:
            for item in self.sftp_client.listdir_attr(path):
                # Skip hidden files and directories
                if item.filename.startswith('.'):
                    continue
                
                item_path = os.path.join(path, item.filename).replace("\\", "/")
                
                if item.st_mode & 0o040000:  # Directory
                    if self.recursive:
                        files.extend(self._get_files_recursive(item_path))
                else:  # File
                    if self._should_monitor_file(item.filename):
                        files.append({
                            "path": item_path,
                            "filename": item.filename,
                            "size": item.st_size or 0,
                            "mtime": item.st_mtime or 0,
                            "mode": item.st_mode or 0,
                            "uid": getattr(item, 'st_uid', 0),
                            "gid": getattr(item, 'st_gid', 0)
                        })
        except Exception as e:
            self.logger.error(f"Error scanning directory {path}: {e}")
        
        return files
    
    def _get_current_files(self) -> Dict[str, Dict[str, Any]]:
        """Get current files in the monitored path"""
        if not self.sftp_client:
            return {}
        
        try:
            files = self._get_files_recursive(self.monitor_path)
            return {file_info["path"]: file_info for file_info in files}
            
        except Exception as e:
            self.logger.error(f"Error getting current files: {e}")
            return {}
    
    def _create_file_event(self, file_info: Dict[str, Any]) -> Dict[str, Any]:
        """Create event data for a new file"""
        return {
            "sftp_file_monitor": {
                "event_type": "file_created",
                "timestamp": datetime.utcnow().isoformat() + "Z",
                "sftp_server": {
                    "host": self.host,
                    "port": self.port,
                    "username": self.username
                },
                "file": {
                    "path": file_info["path"],
                    "filename": file_info["filename"],
                    "basename": os.path.splitext(file_info["filename"])[0],
                    "directory": os.path.dirname(file_info["path"]),
                    "size": file_info["size"],
                    "size_human": self._format_file_size(file_info["size"]),
                    "modification_time": datetime.fromtimestamp(file_info["mtime"]).isoformat() + "Z",
                    "extension": os.path.splitext(file_info["filename"])[1],
                    "permissions": oct(file_info["mode"])[-3:] if file_info["mode"] else "000",
                    "uid": file_info.get("uid", 0),
                    "gid": file_info.get("gid", 0)
                },
                "monitor_config": {
                    "monitor_path": self.monitor_path,
                    "recursive": self.recursive,
                    "file_extensions": self.file_extensions,
                    "poll_interval": self.poll_interval
                }
            }
        }
    
    def _format_file_size(self, size_bytes: int) -> str:
        """Format file size in human readable format"""
        if size_bytes == 0:
            return "0 B"
        
        for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
            if size_bytes < 1024.0:
                if unit == 'B':
                    return f"{int(size_bytes)} {unit}"
                else:
                    return f"{size_bytes:.1f} {unit}"
            size_bytes /= 1024.0
        return f"{size_bytes:.1f} PB"
    
    async def scan_for_new_files(self, queue):
        """Main monitoring loop"""
        self.logger.info(f"Starting SFTP file monitoring on {self.host}:{self.monitor_path}")
        self.logger.info(f"Configuration: poll_interval={self.poll_interval}s, "
                        f"recursive={self.recursive}, extensions={self.file_extensions}")
        
        self.is_running = True
        
        # Initial connection
        if not self._connect_sftp():
            self.logger.error("Failed to establish initial SFTP connection")
            return
        
        # Get initial file list
        current_files = self._get_current_files()
        self.known_files = {path: info["mtime"] for path, info in current_files.items()}
        self.logger.info(f"Initial scan found {len(self.known_files)} files")
        
        while self.is_running:
            try:
                # Ensure connection is still active
                if not self.sftp_client:
                    self.logger.warning("SFTP connection lost, attempting to reconnect...")
                    if not self._connect_sftp():
                        self.logger.error("Failed to reconnect, waiting before retry...")
                        await asyncio.sleep(min(self.poll_interval, 30))
                        continue
                
                # Get current files
                current_files = self._get_current_files()
                
                # Detect new and modified files
                new_events = []
                for file_path, file_info in current_files.items():
                    if (file_path not in self.known_files or 
                        self.known_files[file_path] != file_info["mtime"]):
                        new_events.append(file_info)
                
                if new_events:
                    self.logger.info(f"Detected {len(new_events)} new/modified file(s)")
                    
                    for file_info in new_events:
                        event = self._create_file_event(file_info)
                        
                        self.logger.info(f"New file detected: {file_info['filename']} "
                                       f"({self._format_file_size(file_info['size'])})")
                        
                        await queue.put(event)
                
                # Update known files
                self.known_files = {path: info["mtime"] for path, info in current_files.items()}
                
                # Wait before next scan
                await asyncio.sleep(self.poll_interval)
                
            except asyncio.CancelledError:
                self.logger.info("Monitoring cancelled")
                break
            except Exception as e:
                self.logger.error(f"Error during file monitoring: {e}")
                self._cleanup_connection()
                await asyncio.sleep(min(self.poll_interval, 30))
    
    def stop(self):
        """Stop the monitoring loop"""
        self.is_running = False
        self.cleanup()
    
    def cleanup(self):
        """Cleanup resources"""
        self._cleanup_connection()
        self.logger.info("SFTP file monitor cleanup completed")


async def main(queue, args):
    """Main entry point for the EDA plugin"""
    logger = logging.getLogger(__name__)
    
    monitor = None
    try:
        monitor = SFTPFileMonitor(args, logger)
        await monitor.scan_for_new_files(queue)
    except KeyboardInterrupt:
        logger.info("Received interrupt signal")
    except Exception as e:
        logger.error(f"SFTP file monitor failed: {e}")
        raise
    finally:
        if monitor:
            monitor.cleanup()


# For testing purposes
if __name__ == "__main__":
    import sys
    import json
    
    # Mock queue for testing
    class MockQueue:
        def __init__(self):
            self.events = []
            
        async def put(self, item):
            self.events.append(item)
            print(f"Event: {json.dumps(item, indent=2)}")
    
    # Test configuration
    test_config = {
        "host": "localhost",
        "username": "testuser", 
        "password": "testpass",
        "monitor_path": "/opt/sftp/SFTPUser/",
        "poll_interval": 10,
        "file_extensions": [".txt", ".log"],
        "recursive": True
    }
    
    async def test_run():
        queue = MockQueue()
        try:
            await main(queue, test_config)
        except KeyboardInterrupt:
            print("\nTest interrupted")
            print(f"Total events captured: {len(queue.events)}")
    
    if len(sys.argv) > 1 and sys.argv[1] == "test":
        print("Running SFTP monitor test...")
        print("Press Ctrl+C to stop")
        asyncio.run(test_run())
