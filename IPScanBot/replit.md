# Overview

This is a fully functional Telegram RDP Scanner Bot that provides comprehensive Remote Desktop Protocol (RDP) port scanning capabilities through a Telegram interface. The bot is currently running and ready to use. Users can scan for open RDP ports on single IP addresses, IP ranges, or bulk scan from uploaded text files. It includes advanced Network Level Authentication (NLA) detection functionality and provides real-time progress updates with downloadable results. The system is built as an asynchronous Python application using the python-telegram-bot library v21.8, designed to handle concurrent scanning operations efficiently while providing real-time feedback to users through Telegram messages.

## Status: COMPLETED & RUNNING
- Bot is active and polling for Telegram messages
- All 7 core commands implemented and working: /scanip, /scanrange, /scanfile, /nlaips, /get, /status, /stop, /help
- Enhanced /scanfile with IP limiting capability (/scanfile 100)
- File upload processing with validation
- NLA detection capabilities 
- Real-time progress updates and downloadable results (every 2-5% instead of 10-20%)
- Instant valid IP notifications with NLA status
- /stop command to cancel active scans
- /status command showing scan status and recent valid IPs
- Comprehensive error handling and user feedback

# User Preferences

Preferred communication style: Simple, everyday language.

# System Architecture

## Bot Framework Architecture
The application is built on the python-telegram-bot library using an asynchronous architecture with the Application and Handler pattern. The main bot class `TelegramRDPBot` manages command handlers for different scanning operations (/scanip, /scanrange, /scanfile, /nlaips) and maintains state for active scans per user to prevent concurrent operations.

## Scanning Engine Design
The `RDPScanner` class implements the core scanning functionality using asyncio for concurrent operations. It employs a semaphore-based concurrency control mechanism (MAX_CONCURRENT_SCANS = 50) to limit simultaneous network connections and prevent resource exhaustion. The scanner performs both port availability checks and NLA detection using low-level socket operations with configurable timeouts.

## File Processing System
The `FileHandler` class manages uploaded file processing with built-in validation for file size (10MB limit), file extensions (.txt only), and content parsing. It extracts IP addresses from uploaded text files, validates them, and integrates with the scanning engine. The system uses a temporary file directory structure for intermediate file storage.

## Concurrency and State Management
The architecture implements user-level scan state tracking to prevent multiple concurrent scans per user while allowing global concurrent operations. The scanning operations are throttled using asyncio semaphores, and the system provides real-time progress updates through Telegram message editing.

## Error Handling and Validation
The system includes comprehensive input validation for IP addresses, IP ranges, and file content. Error handling is implemented at multiple layers - network-level exceptions during scanning, file processing errors, and user input validation errors, with appropriate user-friendly error messages returned through the Telegram interface.

# External Dependencies

## Telegram Bot API
Integrates with the Telegram Bot API through the python-telegram-bot library for receiving commands, handling file uploads, and sending responses. Requires a BOT_TOKEN environment variable for authentication.

## Network Socket Operations
Uses Python's built-in socket library for low-level network connections to perform RDP port scanning on port 3389. Implements custom timeout handling and connection management for reliable network operations.

## File System Operations
Relies on local file system for temporary file storage during file upload processing. Creates and manages a temporary directory structure for uploaded files with automatic cleanup capabilities.

## Standard Python Libraries
Utilizes asyncio for asynchronous operations, ipaddress for IP validation and manipulation, struct for binary data handling during NLA detection, and logging for comprehensive application monitoring and debugging.