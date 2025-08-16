"""
Configuration file for the Telegram RDP Scanner Bot
"""
import os
import logging

# Bot configuration
BOT_TOKEN = os.getenv("BOT_TOKEN", "")

# Scanning configuration
#
# The default timeout for network operations when scanning RDP endpoints.  The
# timeout can be overridden at runtime by setting the `DEFAULT_TIMEOUT`
# environment variable to an integer value representing seconds.  If no
# environment variable is provided the scanner will default to 5 seconds.
DEFAULT_TIMEOUT = int(os.getenv("DEFAULT_TIMEOUT", "5"))  # seconds

# The maximum number of concurrent scanning connections.  To better cope with
# different hosting environments and rate‑limits this value can be configured
# via the `MAX_CONCURRENT_SCANS` environment variable.  When unset it
# defaults to 50 concurrent connections.
MAX_CONCURRENT_SCANS = int(os.getenv("MAX_CONCURRENT_SCANS", "50"))

# Port used for Remote Desktop Protocol.  Exposed as a constant for
# completeness even though it rarely changes.
RDP_PORT = 3389

# File handling
MAX_FILE_SIZE = 10 * 1024 * 1024  # 10MB
ALLOWED_FILE_EXTENSIONS = ['.txt']
TEMP_DIR = 'temp_files'

# Logging configuration
logging.basicConfig(
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    level=logging.INFO
)

logger = logging.getLogger(__name__)

# Help text
HELP_TEXT = """
🔍 **RDP Scanner Bot Commands**

**File Scanning:**
`/scanfile` - Upload a text file with IP addresses (one per line) to scan for open RDP ports
`/scanfile [limit]` - Scan only first N IPs from file (e.g., `/scanfile 100`)

**Single IP Scanning:**
`/scanip <IP_ADDRESS>` - Scan a single IP address for open RDP port
Example: `/scanip 192.168.1.10`

**Range Scanning:**
`/scanrange <START_IP> <END_IP>` - Scan a range of IP addresses for open RDP ports
Example: `/scanrange 192.168.1.1 192.168.1.50`

**NLA Detection:**
`/nlaips <START_IP> <END_IP>` - Scan IP range for Network Level Authentication status
Example: `/nlaips 192.168.1.1 192.168.1.50`

**Get Valid IPs:**
`/get` - Retrieve all valid IPs with open RDP ports found in your scans

**Status Check:**
`/status` - Show current scan status and recent valid IPs found

**Stop Scan:**
`/stop` - Stop all active scans immediately

**Help:**
`/help` - Show this help message

**📋 Features:**
• Real-time scanning progress updates
• **NEW:** Instant notifications when valid IPs are found
• **NEW:** Real-time valid IP counter during scans
• **NEW:** /get command to retrieve all valid IPs
• Downloadable scan results in text format
• Network Level Authentication (NLA) detection
• Batch scanning from uploaded files (supports IP:PORT format)
• IP range scanning with concurrent processing

**⚠️ Security Note:**
This bot is designed for authorized network security auditing only. Ensure you have proper permissions before scanning any network infrastructure.
"""

# Response messages
MESSAGES = {
    'start': "🔍 Welcome to RDP Scanner Bot! Use /help to see available commands.",
    'upload_prompt': "📁 Please upload a text file containing IP addresses (one per line) to scan for open RDP ports.",
    'file_processing': "📊 Processing your file...",
    'scan_starting': "🔍 Starting scan...",
    'scan_complete': "✅ Scan completed!",
    'invalid_ip': "❌ Invalid IP address format.",
    'invalid_range': "❌ Invalid IP range. Please provide valid start and end IP addresses.",
    'file_too_large': f"❌ File too large. Maximum size allowed is {MAX_FILE_SIZE // (1024*1024)}MB.",
    'invalid_file_type': "❌ Invalid file type. Please upload a .txt file.",
    'scan_error': "❌ An error occurred during scanning.",
    'no_file': "❌ No file received. Please upload a text file.",
    'empty_file': "❌ The uploaded file is empty or contains no valid IP addresses."
}
