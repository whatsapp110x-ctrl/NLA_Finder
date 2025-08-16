"""
File handling utilities for the Telegram RDP Scanner Bot
"""
import os
import tempfile
import asyncio
from typing import List, Optional
import logging
# Use relative imports so that the module works correctly when the package is
# imported from outside the repository root.  Absolute imports against
# "config" or "rdp_scanner" rely on those modules being on the Python
# path which isn't always the case.
from .config import MAX_FILE_SIZE, ALLOWED_FILE_EXTENSIONS, TEMP_DIR
from .rdp_scanner import validate_ip_address

logger = logging.getLogger(__name__)

class FileHandler:
    def __init__(self):
        self.temp_dir = TEMP_DIR
        # Create temp directory if it doesn't exist
        os.makedirs(self.temp_dir, exist_ok=True)
    
    async def process_uploaded_file(self, file_content: bytes, filename: str) -> List[str]:
        """
        Process uploaded file and extract IP addresses
        
        Args:
            file_content: File content as bytes
            filename: Name of the uploaded file
            
        Returns:
            List of valid IP addresses
            
        Raises:
            ValueError: If file is invalid or contains no valid IPs
        """
        # Validate file size
        if len(file_content) > MAX_FILE_SIZE:
            raise ValueError(f"File too large. Maximum size is {MAX_FILE_SIZE // (1024*1024)}MB")
        
        # Validate file extension
        file_ext = os.path.splitext(filename)[1].lower()
        if file_ext not in ALLOWED_FILE_EXTENSIONS:
            raise ValueError(f"Invalid file type. Allowed extensions: {', '.join(ALLOWED_FILE_EXTENSIONS)}")
        
        try:
            # Decode file content
            content = file_content.decode('utf-8')
        except UnicodeDecodeError:
            try:
                # Try with different encoding
                content = file_content.decode('latin-1')
            except UnicodeDecodeError:
                raise ValueError("Unable to decode file. Please ensure it's a text file with UTF-8 encoding.")
        
        # Extract IP addresses
        ip_addresses = self._extract_ip_addresses(content)
        
        if not ip_addresses:
            raise ValueError("No valid IP addresses found in the file.")
        
        logger.info(f"Processed file {filename}: found {len(ip_addresses)} valid IP addresses")
        return ip_addresses
    
    def _extract_ip_addresses(self, content: str) -> List[str]:
        """
        Extract valid IP addresses from file content
        
        Args:
            content: File content as string
            
        Returns:
            List of valid IP addresses
        """
        ip_addresses = []
        lines = content.strip().split('\n')
        
        for line_num, line in enumerate(lines, 1):
            # Clean the line
            line = line.strip()
            
            # Skip empty lines and comments
            if not line or line.startswith('#') or line.startswith('//'):
                continue
            
            # Handle multiple IPs per line (comma or space separated)
            potential_ips = line.replace(',', ' ').split()
            
            for potential_ip in potential_ips:
                potential_ip = potential_ip.strip()
                
                # Check if it has a port number (format: IP:PORT)
                if ':' in potential_ip:
                    ip_part = potential_ip.split(':')[0].strip()
                    # Validate the IP part
                    if validate_ip_address(ip_part):
                        if ip_part not in ip_addresses:  # Avoid duplicates
                            ip_addresses.append(ip_part)
                    else:
                        logger.debug(f"Invalid IP on line {line_num}: {potential_ip}")
                else:
                    # Standard IP validation
                    if validate_ip_address(potential_ip):
                        if potential_ip not in ip_addresses:  # Avoid duplicates
                            ip_addresses.append(potential_ip)
                    else:
                        logger.debug(f"Invalid IP on line {line_num}: {potential_ip}")
        
        return ip_addresses
    
    async def create_result_file(self, results_text: str, scan_type: str = "scan") -> str:
        """
        Create a temporary file with scan results
        
        Args:
            results_text: Formatted scan results
            scan_type: Type of scan for filename
            
        Returns:
            Path to the created file
        """
        try:
            # Create temporary file
            timestamp = asyncio.get_event_loop().time()
            filename = f"{scan_type}_results_{int(timestamp)}.txt"
            filepath = os.path.join(self.temp_dir, filename)
            
            # Write results to file
            with open(filepath, 'w', encoding='utf-8') as f:
                f.write(results_text)
            
            logger.info(f"Created result file: {filepath}")
            return filepath
            
        except Exception as e:
            logger.error(f"Error creating result file: {e}")
            raise
    
    def cleanup_file(self, filepath: str) -> None:
        """
        Clean up temporary file
        
        Args:
            filepath: Path to file to be deleted
        """
        try:
            if os.path.exists(filepath):
                os.remove(filepath)
                logger.debug(f"Cleaned up file: {filepath}")
        except Exception as e:
            logger.error(f"Error cleaning up file {filepath}: {e}")
    
    def cleanup_old_files(self, max_age_hours: int = 24) -> None:
        """
        Clean up old temporary files
        
        Args:
            max_age_hours: Maximum age of files to keep (in hours)
        """
        try:
            import time
            current_time = time.time()
            max_age_seconds = max_age_hours * 3600
            
            if not os.path.exists(self.temp_dir):
                return
            
            for filename in os.listdir(self.temp_dir):
                filepath = os.path.join(self.temp_dir, filename)
                if os.path.isfile(filepath):
                    file_age = current_time - os.path.getmtime(filepath)
                    if file_age > max_age_seconds:
                        self.cleanup_file(filepath)
                        logger.debug(f"Cleaned up old file: {filepath}")
                        
        except Exception as e:
            logger.error(f"Error during cleanup: {e}")

    async def save_uploaded_file(self, file_content: bytes, filename: str) -> str:
        """
        Save uploaded file temporarily for processing
        
        Args:
            file_content: File content as bytes
            filename: Original filename
            
        Returns:
            Path to saved file
        """
        try:
            # Create safe filename
            safe_filename = os.path.basename(filename)
            timestamp = asyncio.get_event_loop().time()
            temp_filename = f"upload_{int(timestamp)}_{safe_filename}"
            filepath = os.path.join(self.temp_dir, temp_filename)
            
            # Save file
            with open(filepath, 'wb') as f:
                f.write(file_content)
            
            logger.debug(f"Saved uploaded file: {filepath}")
            return filepath
            
        except Exception as e:
            logger.error(f"Error saving uploaded file: {e}")
            raise

def format_scan_summary(total_scanned: int, open_ports: int, scan_type: str = "RDP") -> str:
    """
    Format a summary of scan results
    
    Args:
        total_scanned: Total number of IPs scanned
        open_ports: Number of open ports found
        scan_type: Type of scan performed
        
    Returns:
        Formatted summary string
    """
    closed_ports = total_scanned - open_ports
    return (
        f"🔍 **{scan_type} Scan Summary**\n"
        f"📊 Total IPs Scanned: {total_scanned}\n"
        f"🔓 Open Ports: {open_ports}\n"
        f"🔒 Closed/Error: {closed_ports}\n"
        f"📈 Success Rate: {(open_ports/total_scanned*100):.1f}%" if total_scanned > 0 else "0.0%"
    )
