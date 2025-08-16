# Telegram RDP Scanner Bot

A comprehensive Telegram bot for scanning Remote Desktop Protocol (RDP) ports with advanced features including file upload scanning, IP range scanning, and Network Level Authentication (NLA) detection.

## Features

### 🔍 Flexible IP Scanning
- **Single IP Scan** (`/scanip`): Scan individual IP addresses quickly
- **Range Scan** (`/scanrange`): Scan entire IP ranges or subnets
- **File Upload Scan** (`/scanfile`): Upload text files with IP lists for batch scanning

### 🛡️ Security Features
- **NLA Detection** (`/nlaips`): Identify systems with Network Level Authentication enabled
- **Real-time Progress Updates**: Get live feedback during scans
- **Downloadable Results**: Receive detailed scan results in text format

### 📋 User-Friendly Commands
- **Help System** (`/help`): Built-in command reference
- **Simple Syntax**: Intuitive command structure for all users
- **Error Handling**: Clear feedback for invalid inputs

## Available Commands

### `/scanip <IP_ADDRESS>`
Scan a single IP address for open RDP ports.

**Example:**
```
/scanip 192.168.1.10
```

**Response:**
- ✅ The RDP port (3389) is **OPEN** on 192.168.1.10 (NLA Enabled ✅)
- 🔒 The RDP port (3389) is **CLOSED** on 192.168.1.10

### `/scanrange <START_IP> <END_IP>`
Scan a range of IP addresses for open RDP ports.

**Example:**
```
/scanrange 192.168.1.1 192.168.1.50
```

**Features:**
- Real-time progress updates
- Downloadable results file
- Summary statistics
- NLA status for open ports

### `/scanfile`
Upload a text file containing IP addresses (one per line) for batch scanning.

**Usage:**
1. Send the `/scanfile` command
2. Upload a .txt file with IP addresses
3. Receive scan results and downloadable report

**File Format:**
```
192.168.1.10
192.168.1.20
10.0.0.5
# Comments are supported
192.168.1.30
```

**Also supports IP:PORT format:**
```
47.239.53.29:3389
185.230.55.236:3389
31.24.44.125:3389
195.77.95.153:3389
```
The bot will automatically extract the IP addresses and ignore the port numbers.

### `/nlaips <START_IP> <END_IP>`
Scan IP range specifically for Network Level Authentication status on RDP services.

**Example:**
```
/nlaips 192.168.1.1 192.168.1.50
```

**Output:**
- Lists all IPs with open RDP ports
- Shows NLA status (Enabled/Disabled/Unknown)
- Security recommendations for vulnerable systems

### `/help`
Display comprehensive help with all available commands and usage examples.

## Setup Instructions

### 1. Get a Telegram Bot Token
1. Open Telegram and search for `@BotFather`
2. Start a chat and type `/newbot`
3. Follow instructions to create your bot
4. Copy the bot token (format: `123456789:ABCdefGHIjklMNOpqrsTUVwxyz`)

### 2. Configure the Bot
1. Set the `BOT_TOKEN` environment variable with your token
2. Run the bot using `python main.py`

### 3. Start Using
1. Find your bot on Telegram
2. Send `/start` to begin
3. Use `/help` to see all commands

## Technical Specifications

### Scanning Capabilities
- **Port**: RDP (3389)
- **Timeout**: 5 seconds per connection
- **Concurrency**: Up to 50 simultaneous scans
- **Range Limit**: Maximum 1000 IPs per range scan
- **File Limit**: 10MB maximum file size

### Network Level Authentication Detection
The bot performs RDP protocol negotiation to detect NLA status:
- **Enabled**: System requires authentication before RDP session
- **Disabled**: System allows direct RDP connections (higher risk)
- **Unknown**: Detection failed or inconclusive

### File Processing
- **Supported Formats**: .txt files only
- **Encoding**: UTF-8 and Latin-1 support
- **Comments**: Lines starting with `#` or `//` are ignored
- **Multiple IPs**: Supports comma or space-separated IPs per line

## Security Notes

⚠️ **Important**: This tool is designed for authorized network security auditing only. Always ensure you have proper permissions before scanning any network infrastructure.

### Responsible Use
- Only scan networks you own or have explicit permission to test
- Be mindful of network load during large scans
- Respect rate limiting and timeout settings
- Use results to improve security, not exploit vulnerabilities

### Privacy
- No scan data is stored permanently
- Temporary files are automatically cleaned up
- All processing happens locally on your server

## Error Handling

The bot includes comprehensive error handling for:
- Invalid IP addresses and ranges
- Network timeouts and connection failures
- File format and size validation
- Concurrent scan limitations per user
- Rate limiting and resource management

## Output Examples

### Single IP Scan Result
```
✅ The RDP port (3389) is OPEN on 192.168.1.10 (NLA Enabled ✅)
```

### Range Scan Summary
```
🔍 RDP Scan Summary
📊 Total IPs Scanned: 50
🔓 Open Ports: 3
🔒 Closed/Error: 47
📈 Success Rate: 6.0%
```

### Downloadable Report Format
```
192.168.1.10 - Open - NLA Enabled
192.168.1.20 - Closed
192.168.1.30 - Open - NLA Disabled
192.168.1.40 - Error: Timeout

--- Summary ---
Total IPs Scanned: 4
Open RDP Ports: 2
Closed/Error: 2
```

## Troubleshooting

### Common Issues
1. **"Invalid IP address format"**: Ensure IPs are properly formatted (e.g., 192.168.1.1)
2. **"File too large"**: Keep uploaded files under 10MB
3. **"You already have an active scan"**: Wait for current scan to complete
4. **"Invalid file type"**: Only .txt files are supported

### Rate Limiting
- One active scan per user at a time
- Maximum 50 concurrent network connections
- 1000 IP limit per range scan

## Architecture

The bot consists of four main components:
- **Main Bot** (`main.py`): Telegram interface and command handling
- **RDP Scanner** (`rdp_scanner.py`): Core scanning and NLA detection engine
- **File Handler** (`file_handler.py`): File upload processing and result generation
- **Configuration** (`config.py`): Settings and message templates

For technical details, see the project's `replit.md` file.