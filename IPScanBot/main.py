"""
Telegram RDP Scanner Bot
A comprehensive bot for scanning RDP ports with file upload, range scanning, and NLA detection
"""
import asyncio
import logging
import os
import json
from typing import List, Dict, Any

from telegram import Update
from telegram.ext import (
    Application, 
    CommandHandler, 
    MessageHandler, 
    ContextTypes,
    filters
)

# Use package‑relative imports so this script works when executed as
# ``python -m IPScanBot.main`` or via Render.  Direct imports without a
# relative prefix assume the modules are on the Python path which is not
# guaranteed outside of the repository root.
try:
    # Use relative imports when the module is executed as part of the
    # IPScanBot package (e.g. ``python -m IPScanBot.main``).  The
    # ``__package__`` attribute will be set in this case.
    if __package__:
        from .config import BOT_TOKEN, HELP_TEXT, MESSAGES, logger  # type: ignore
        from .rdp_scanner import RDPScanner, validate_ip_address, validate_ip_range  # type: ignore
        from .file_handler import FileHandler, format_scan_summary  # type: ignore
    else:
        # When run as a script (``python IPScanBot/main.py``), the package
        # context is not set.  Fallback to adding the package's parent
        # directory to sys.path so that absolute imports work.  This allows
        # development and testing from the repository root.
        import sys as _sys
        from os import path as _path
        _current_dir = _path.dirname(_path.abspath(__file__))
        _parent_dir = _path.dirname(_current_dir)
        if _parent_dir not in _sys.path:
            _sys.path.insert(0, _parent_dir)
        from IPScanBot.config import BOT_TOKEN, HELP_TEXT, MESSAGES, logger  # type: ignore
        from IPScanBot.rdp_scanner import RDPScanner, validate_ip_address, validate_ip_range  # type: ignore
        from IPScanBot.file_handler import FileHandler, format_scan_summary  # type: ignore
except Exception as import_exc:
    # Re-raise with context to assist debugging
    raise

# Initialize components
scanner = RDPScanner()
file_handler = FileHandler()

class TelegramRDPBot:
    def __init__(self):
        self.application = None
        self.active_scans = {}  # Track active scans per user
        self.valid_ips = {}  # Store valid IPs per user {user_id: [list of valid IPs]}
        self.valid_ips_file = "temp_files/valid_ips_storage.json"
        self._load_valid_ips()
    
    def _load_valid_ips(self):
        """Load valid IPs from persistent storage"""
        try:
            if os.path.exists(self.valid_ips_file):
                with open(self.valid_ips_file, 'r') as f:
                    # Convert string keys back to integers
                    stored_data = json.load(f)
                    self.valid_ips = {int(k): v for k, v in stored_data.items()}
                    logger.info(f"Loaded valid IPs for {len(self.valid_ips)} users from storage")
            else:
                logger.info("No valid IPs storage file found, starting fresh")
        except Exception as e:
            logger.error(f"Error loading valid IPs: {e}")
            self.valid_ips = {}
    
    def _save_valid_ips(self):
        """Save valid IPs to persistent storage"""
        try:
            os.makedirs(os.path.dirname(self.valid_ips_file), exist_ok=True)
            # Convert integer keys to strings for JSON serialization
            data_to_save = {str(k): v for k, v in self.valid_ips.items()}
            with open(self.valid_ips_file, 'w') as f:
                json.dump(data_to_save, f, indent=2)
            logger.info(f"Saved valid IPs for {len(self.valid_ips)} users to storage")
        except Exception as e:
            logger.error(f"Error saving valid IPs: {e}")
    
    async def start_command(self, update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
        """Handle /start command"""
        await update.message.reply_text(MESSAGES['start'])
    
    async def help_command(self, update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
        """Handle /help command"""
        await update.message.reply_text(HELP_TEXT, parse_mode='Markdown')
    
    async def scan_single_ip_command(self, update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
        """Handle /scanip command"""
        user_id = update.effective_user.id
        
        # Check if user has an active scan
        if user_id in self.active_scans:
            await update.message.reply_text("⏳ You already have an active scan. Please wait for it to complete.")
            return
        
        # Validate arguments
        if not context.args or len(context.args) != 1:
            await update.message.reply_text(
                "❌ Usage: `/scanip <IP_ADDRESS>`\n"
                "Example: `/scanip 192.168.1.10`",
                parse_mode='Markdown'
            )
            return
        
        ip_address = context.args[0].strip()
        
        # Validate IP address
        if not validate_ip_address(ip_address):
            await update.message.reply_text(MESSAGES['invalid_ip'])
            return
        
        # Mark user as having active scan
        self.active_scans[user_id] = True
        
        try:
            # Send initial message
            status_message = await update.message.reply_text(
                f"🔍 Scanning IP {ip_address} for open RDP ports..."
            )
            
            # Perform scan
            result = await scanner.scan_single_ip(ip_address)
            
            # Format result
            if result['error']:
                response = f"❌ Scan failed for {ip_address}: {result['error']}"
            elif result['port_open']:
                nla_info = ""
                if result['nla_enabled'] is not None:
                    if result['nla_enabled']:
                        nla_info = " (NLA Enabled ✅)"
                    elif result['nla_enabled'] is False:
                        nla_info = " (NLA Disabled ⚠️)"
                    else:
                        nla_info = " (NLA Status Unknown ❓)"
                
                response = f"✅ The RDP port (3389) is **OPEN** on {ip_address}{nla_info}"
            else:
                response = f"🔒 The RDP port (3389) is **CLOSED** on {ip_address}"
            
            # Update message with result
            await status_message.edit_text(response, parse_mode='Markdown')
            
        except Exception as e:
            logger.error(f"Error in single IP scan: {e}")
            await update.message.reply_text(f"❌ An error occurred: {str(e)}")
        finally:
            # Remove user from active scans
            self.active_scans.pop(user_id, None)
    
    async def scan_range_command(self, update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
        """Handle /scanrange command"""
        user_id = update.effective_user.id
        
        # Check if user has an active scan
        if user_id in self.active_scans:
            await update.message.reply_text("⏳ You already have an active scan. Please wait for it to complete.")
            return
        
        # Validate arguments
        if not context.args or len(context.args) != 2:
            await update.message.reply_text(
                "❌ Usage: `/scanrange <START_IP> <END_IP>`\n"
                "Example: `/scanrange 192.168.1.1 192.168.1.50`",
                parse_mode='Markdown'
            )
            return
        
        start_ip = context.args[0].strip()
        end_ip = context.args[1].strip()
        
        # Validate IP range
        if not validate_ip_range(start_ip, end_ip):
            await update.message.reply_text(MESSAGES['invalid_range'])
            return
        
        # Mark user as having active scan
        self.active_scans[user_id] = True
        
        try:
            # Send initial message
            status_message = await update.message.reply_text(
                f"🔍 Starting range scan from {start_ip} to {end_ip}..."
            )
            
            # Progress callback function
            async def progress_callback(progress: float, current_ip: str, result: Dict[str, Any]):
                """Report progress and handle newly discovered valid IPs.

                When a valid IP is found its address is appended to the
                in‑memory valid IP list and persisted immediately via
                ``_save_valid_ips``.  Progress updates are throttled to every
                5 percent or final completion.  This callback always returns
                ``True`` to indicate that scanning should continue.
                """
                # If this IP has an open RDP port store it and persist
                if result.get('port_open'):
                    if user_id not in self.valid_ips:
                        self.valid_ips[user_id] = []
                    self.valid_ips[user_id].append(f"{result['ip']}:3389")
                    # Persist updated valid IPs for durability
                    self._save_valid_ips()

                    # Compose NLA status string
                    if result.get('nla_enabled') is True:
                        nla_status = " (NLA Enabled ✅)"
                    elif result.get('nla_enabled') is False:
                        nla_status = " (NLA Disabled ⚠️)"
                    else:
                        nla_status = " (NLA Unknown ❓)"

                    # Notify user about valid IP
                    await update.message.reply_text(
                        f"🔓 **VALID IP FOUND!**\n"
                        f"📍 {result['ip']}:3389{nla_status}",
                        parse_mode='Markdown'
                    )

                # Throttle status updates
                if int(progress) % 5 == 0 or progress >= 100:
                    valid_count = len(self.valid_ips.get(user_id, []))
                    status_text = (
                        f"🔍 Scanning... {progress:.1f}% complete\n"
                        f"📍 Current IP: {current_ip}\n"
                        f"🔓 Valid IPs found: {valid_count}"
                    )
                    try:
                        await status_message.edit_text(status_text)
                    except Exception:
                        # Ignore edit conflicts (e.g. rate limits)
                        pass

                return True
            
            # Perform range scan
            results = await scanner.scan_ip_range(start_ip, end_ip, progress_callback)
            
            # Format results
            results_text = scanner.format_results(results, include_nla=True)
            
            # Create result file
            result_file_path = await file_handler.create_result_file(
                results_text, f"range_scan_{start_ip.replace('.', '_')}_to_{end_ip.replace('.', '_')}"
            )
            
            # Count open ports
            open_ports = sum(1 for r in results if r['port_open'])
            
            # Send summary
            summary = format_scan_summary(len(results), open_ports)
            await status_message.edit_text(f"✅ Range scan completed!\n\n{summary}")
            
            # Send result file
            with open(result_file_path, 'rb') as f:
                await update.message.reply_document(
                    document=f,
                    filename=f"rdp_range_scan_{start_ip}_to_{end_ip}.txt",
                    caption="📁 Detailed scan results"
                )
            
            # Cleanup file
            file_handler.cleanup_file(result_file_path)
            
        except Exception as e:
            logger.error(f"Error in range scan: {e}")
            await update.message.reply_text(f"❌ An error occurred: {str(e)}")
        finally:
            # Remove user from active scans
            self.active_scans.pop(user_id, None)
    
    async def scan_nla_command(self, update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
        """Handle /nlaips command for NLA detection"""
        user_id = update.effective_user.id
        
        # Check if user has an active scan
        if user_id in self.active_scans:
            await update.message.reply_text("⏳ You already have an active scan. Please wait for it to complete.")
            return
        
        # Validate arguments
        if not context.args or len(context.args) != 2:
            await update.message.reply_text(
                "❌ Usage: `/nlaips <START_IP> <END_IP>`\n"
                "Example: `/nlaips 192.168.1.1 192.168.1.50`",
                parse_mode='Markdown'
            )
            return
        
        start_ip = context.args[0].strip()
        end_ip = context.args[1].strip()
        
        # Validate IP range
        if not validate_ip_range(start_ip, end_ip):
            await update.message.reply_text(MESSAGES['invalid_range'])
            return
        
        # Mark user as having active scan
        self.active_scans[user_id] = True
        
        try:
            # Send initial message
            status_message = await update.message.reply_text(
                f"🔍 Starting NLA detection scan from {start_ip} to {end_ip}..."
            )
            
            # Progress callback function
            async def progress_callback(progress: float, current_ip: str, result: Dict[str, Any]):
                """Report progress and handle valid IP discovery during NLA scans.

                Valid IPs are persisted immediately.  Progress updates are
                throttled to every 5 percent or on completion.  Always
                returns ``True`` to continue scanning.  Returning ``False``
                would instruct the scanner to stop early, but this callback
                never requests cancellation.
                """
                if result.get('port_open'):
                    if user_id not in self.valid_ips:
                        self.valid_ips[user_id] = []
                    self.valid_ips[user_id].append(f"{result['ip']}:3389")
                    # Persist updated IP list for resilience
                    self._save_valid_ips()

                    # Compose NLA status string
                    if result.get('nla_enabled') is True:
                        nla_status = " (NLA Enabled ✅)"
                    elif result.get('nla_enabled') is False:
                        nla_status = " (NLA Disabled ⚠️)"
                    else:
                        nla_status = " (NLA Unknown ❓)"

                    await update.message.reply_text(
                        f"🔓 **VALID IP FOUND!**\n"
                        f"📍 {result['ip']}:3389{nla_status}",
                        parse_mode='Markdown'
                    )

                if int(progress) % 5 == 0 or progress >= 100:
                    valid_count = len(self.valid_ips.get(user_id, []))
                    status_text = (
                        f"🔍 NLA Scanning... {progress:.1f}% complete\n"
                        f"📍 Current IP: {current_ip}\n"
                        f"🔓 Valid IPs found: {valid_count}"
                    )
                    try:
                        await status_message.edit_text(status_text)
                    except Exception:
                        pass
                return True
            
            # Perform NLA scan
            results = await scanner.scan_ip_range(start_ip, end_ip, progress_callback)
            
            # Filter for open RDP ports and format with NLA info
            open_rdp_results = [r for r in results if r['port_open']]
            
            # Create detailed NLA report
            nla_report_lines = []
            nla_enabled_count = 0
            nla_disabled_count = 0
            nla_unknown_count = 0
            
            for result in open_rdp_results:
                ip = result['ip']
                if result['nla_enabled'] is True:
                    nla_report_lines.append(f"{ip} - RDP Open, NLA Enabled ✅")
                    nla_enabled_count += 1
                elif result['nla_enabled'] is False:
                    nla_report_lines.append(f"{ip} - RDP Open, NLA Disabled ⚠️")
                    nla_disabled_count += 1
                else:
                    nla_report_lines.append(f"{ip} - RDP Open, NLA Status Unknown ❓")
                    nla_unknown_count += 1
            
            # Add summary
            nla_report_lines.extend([
                "",
                "--- NLA Detection Summary ---",
                f"Total IPs with Open RDP: {len(open_rdp_results)}",
                f"NLA Enabled: {nla_enabled_count}",
                f"NLA Disabled: {nla_disabled_count}",
                f"NLA Unknown: {nla_unknown_count}",
                "",
                "⚠️ Systems with NLA Disabled are more vulnerable to unauthorized access."
            ])
            
            nla_report = "\n".join(nla_report_lines)
            
            if not open_rdp_results:
                await status_message.edit_text(
                    "✅ NLA scan completed!\n\n"
                    "🔒 No open RDP ports found in the specified range."
                )
            else:
                # Create result file
                result_file_path = await file_handler.create_result_file(
                    nla_report, f"nla_scan_{start_ip.replace('.', '_')}_to_{end_ip.replace('.', '_')}"
                )
                
                # Send summary
                summary = (
                    f"✅ NLA Detection completed!\n\n"
                    f"🔓 Open RDP Ports Found: {len(open_rdp_results)}\n"
                    f"✅ NLA Enabled: {nla_enabled_count}\n"
                    f"⚠️ NLA Disabled: {nla_disabled_count}\n"
                    f"❓ NLA Unknown: {nla_unknown_count}"
                )
                await status_message.edit_text(summary)
                
                # Send result file
                with open(result_file_path, 'rb') as f:
                    await update.message.reply_document(
                        document=f,
                        filename=f"nla_detection_{start_ip}_to_{end_ip}.txt",
                        caption="📁 Detailed NLA detection results"
                    )
                
                # Cleanup file
                file_handler.cleanup_file(result_file_path)
            
        except Exception as e:
            logger.error(f"Error in NLA scan: {e}")
            await update.message.reply_text(f"❌ An error occurred: {str(e)}")
        finally:
            # Remove user from active scans
            self.active_scans.pop(user_id, None)
    
    async def scan_file_command(self, update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
        """Handle /scanfile command with optional IP limit"""
        user_id = update.effective_user.id
        
        # Parse optional IP limit from command arguments
        ip_limit = None
        if context.args:
            try:
                ip_limit = int(context.args[0])
                if ip_limit <= 0:
                    await update.message.reply_text(
                        "❌ IP limit must be a positive number.\n"
                        "Example: `/scanfile 100` to scan first 100 IPs"
                    )
                    return
            except ValueError:
                await update.message.reply_text(
                    "❌ Invalid IP limit. Please use a number.\n"
                    "Example: `/scanfile 50` to scan first 50 IPs"
                )
                return
        
        # Store the IP limit for this user
        if ip_limit:
            if not hasattr(self, 'user_ip_limits'):
                self.user_ip_limits = {}
            self.user_ip_limits[user_id] = ip_limit
            
        limit_text = f" (Limited to first {ip_limit} IPs)" if ip_limit else ""
        
        upload_message = (
            f"📁 **File Upload Scan**{limit_text}\n\n"
            "Please upload a .txt file containing IP addresses.\n"
            "Supported formats:\n"
            "• One IP per line: `192.168.1.1`\n"
            "• IP with port: `192.168.1.1:3389`\n"
            "• Mixed format is supported\n\n"
            "📝 Maximum file size: 10MB\n"
            f"🔢 IP limit: {'First ' + str(ip_limit) + ' IPs' if ip_limit else 'No limit'}\n\n"
            "💡 **Tip**: Use `/scanfile 100` to scan only first 100 IPs"
        )
        
        await update.message.reply_text(upload_message, parse_mode='Markdown')
    
    async def handle_document(self, update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
        """Handle uploaded documents"""
        user_id = update.effective_user.id
        
        # Check if user has an active scan
        if user_id in self.active_scans:
            await update.message.reply_text("⏳ You already have an active scan. Please wait for it to complete.")
            return
        
        document = update.message.document
        
        if not document:
            await update.message.reply_text(MESSAGES['no_file'])
            return
        
        # Mark user as having active scan
        self.active_scans[user_id] = True
        
        try:
            # Send processing message
            status_message = await update.message.reply_text(MESSAGES['file_processing'])
            
            # Download file
            file = await document.get_file()
            file_content = await file.download_as_bytearray()
            
            # Process file and extract IPs
            try:
                ip_addresses = await file_handler.process_uploaded_file(
                    bytes(file_content), document.file_name
                )
            except ValueError as e:
                await status_message.edit_text(f"❌ {str(e)}")
                return
            
            # Apply IP limit if set by user
            original_count = len(ip_addresses)
            if hasattr(self, 'user_ip_limits') and user_id in self.user_ip_limits:
                ip_limit = self.user_ip_limits[user_id]
                ip_addresses = ip_addresses[:ip_limit]
                # Clear the limit after use
                del self.user_ip_limits[user_id]
                logger.info(f"Applied IP limit {ip_limit} for user {user_id}, scanning {len(ip_addresses)} of {original_count} IPs")
                
                # Update status with limit information
                await status_message.edit_text(
                    f"📊 Found {original_count} IP addresses, scanning first {len(ip_addresses)} (limit applied). Starting scan..."
                )
            else:
                # Update status without limit
                await status_message.edit_text(
                    f"📊 Found {len(ip_addresses)} valid IP addresses. Starting scan..."
                )
            
            # Progress callback function
            async def progress_callback(progress: float, current_ip: str, result: Dict[str, Any]):
                try:
                    # Check if scan was stopped
                    if user_id not in self.active_scans:
                        logger.info(f"Scan stopped for user {user_id}")
                        return False  # Signal to stop scanning
                    
                    # Check if this IP has open RDP port and store it
                    if result['port_open']:
                        if user_id not in self.valid_ips:
                            self.valid_ips[user_id] = []
                        self.valid_ips[user_id].append(f"{result['ip']}:3389")
                        self._save_valid_ips()  # Save to persistent storage
                        
                        # Send real-time notification for valid IP
                        nla_status = ""
                        if result['nla_enabled'] is True:
                            nla_status = " (NLA Enabled ✅)"
                        elif result['nla_enabled'] is False:
                            nla_status = " (NLA Disabled ⚠️)"
                        else:
                            nla_status = " (NLA Unknown ❓)"
                        
                        try:
                            await update.message.reply_text(
                                f"🔓 **VALID IP FOUND!**\n"
                                f"📍 {result['ip']}:3389{nla_status}",
                                parse_mode='Markdown'
                            )
                        except Exception as e:
                            logger.error(f"Failed to send valid IP notification: {e}")
                    
                    if int(progress) % 2 == 0 or progress >= 100:  # Update every 2%
                        valid_count = len(self.valid_ips.get(user_id, []))
                        status_text = f"🔍 File scanning... {progress:.1f}% complete\n📍 Current IP: {current_ip}\n🔓 Valid IPs found: {valid_count}"
                        try:
                            await status_message.edit_text(status_text)
                        except Exception as e:
                            logger.error(f"Failed to update progress: {e}")
                    
                    return True  # Continue scanning
                except Exception as e:
                    logger.error(f"Error in progress callback: {e}")
                    return True
            
            # Perform scan on all IPs from file with timeout protection
            try:
                results = await asyncio.wait_for(
                    scanner.scan_ip_list(ip_addresses, progress_callback),
                    timeout=300  # 5 minute timeout for safety
                )
            except asyncio.TimeoutError:
                logger.error(f"Scan timeout for user {user_id}")
                await status_message.edit_text("❌ Scan timed out. Please try with fewer IPs or use /stop to cancel.")
                return
            
            # Format results
            results_text = scanner.format_results(results, include_nla=True)
            
            # Create result file
            result_file_path = await file_handler.create_result_file(
                results_text, f"file_scan_{document.file_name.replace('.', '_')}"
            )
            
            # Count open ports
            open_ports = sum(1 for r in results if r['port_open'])
            
            # Send summary
            summary = format_scan_summary(len(results), open_ports)
            await status_message.edit_text(f"✅ File scan completed!\n\n{summary}")
            
            # Send result file
            with open(result_file_path, 'rb') as f:
                await update.message.reply_document(
                    document=f,
                    filename=f"rdp_scan_results_{document.file_name}",
                    caption="📁 Detailed scan results from uploaded file"
                )
            
            # Cleanup file
            file_handler.cleanup_file(result_file_path)
            
        except Exception as e:
            logger.error(f"Error processing file: {e}")
            await update.message.reply_text(f"❌ An error occurred: {str(e)}")
        finally:
            # Remove user from active scans
            self.active_scans.pop(user_id, None)
    
    async def stop_command(self, update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
        """Handle /stop command to stop all active scans"""
        user_id = update.effective_user.id
        
        if user_id in self.active_scans:
            self.active_scans.pop(user_id, None)
            await update.message.reply_text(
                "🛑 **Scan Stopped**\n"
                "All active scans have been cancelled.\n"
                "You can start a new scan anytime.",
                parse_mode='Markdown'
            )
            logger.info(f"User {user_id} stopped their active scan")
        else:
            await update.message.reply_text(
                "ℹ️ No active scans to stop.\n"
                "Start a scan with /scanip, /scanrange, or /scanfile commands."
            )

    async def status_command(self, update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
        """Handle /status command to show current scan status and valid IPs"""
        user_id = update.effective_user.id
        
        # Check if user has active scan
        active_scan = user_id in self.active_scans
        
        # Check valid IPs count
        valid_count = len(self.valid_ips.get(user_id, []))
        
        status_msg = f"📊 **Bot Status for User {user_id}**\n\n"
        status_msg += f"🔄 Active Scan: {'Yes' if active_scan else 'No'}\n"
        status_msg += f"🔓 Valid IPs Found: {valid_count}\n\n"
        
        if valid_count > 0:
            status_msg += "**Recent Valid IPs:**\n"
            recent_ips = self.valid_ips[user_id][-5:]  # Show last 5 IPs
            for ip in recent_ips:
                status_msg += f"• {ip}\n"
            if valid_count > 5:
                status_msg += f"• ... and {valid_count - 5} more\n"
            status_msg += f"\nUse /get to download complete list"
        else:
            status_msg += "Run a scan to find valid IPs"
        
        await update.message.reply_text(status_msg, parse_mode='Markdown')

    async def get_valid_ips_command(self, update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
        """Handle /get command to retrieve all valid IPs found by user"""
        user_id = update.effective_user.id
        
        logger.info(f"Get command called by user {user_id}, valid_ips: {self.valid_ips}")
        
        if user_id not in self.valid_ips or not self.valid_ips[user_id]:
            await update.message.reply_text(
                "📝 No valid IPs found yet.\n"
                "Run a scan first using /scanip, /scanrange, or /scanfile commands."
            )
            return
        
        valid_ips_list = self.valid_ips[user_id]
        total_count = len(valid_ips_list)
        
        # Create the text content
        timestamp = asyncio.get_event_loop().time()
        results_text = f"Valid RDP IPs Found - {total_count} total\n"
        results_text += f"Generated on: {timestamp}\n\n"
        
        for ip in valid_ips_list:
            results_text += f"{ip}\n"
        
        results_text += f"\n--- Summary ---\n"
        results_text += f"Total Valid IPs: {total_count}\n"
        results_text += f"All IPs have port 3389 (RDP) open\n"
        
        try:
            # Create result file
            result_file_path = await file_handler.create_result_file(
                results_text, f"valid_ips_user_{user_id}"
            )
            
            # Send summary message
            await update.message.reply_text(
                f"📋 **Valid IPs Summary**\n"
                f"🔓 Total Valid IPs: {total_count}\n"
                f"📁 Sending detailed list as file...",
                parse_mode='Markdown'
            )
            
            # Send result file
            with open(result_file_path, 'rb') as f:
                await update.message.reply_document(
                    document=f,
                    filename=f"valid_rdp_ips_{total_count}_results.txt",
                    caption=f"📁 Complete list of {total_count} valid RDP IPs"
                )
            
            # Cleanup file
            file_handler.cleanup_file(result_file_path)
            
        except Exception as e:
            logger.error(f"Error creating valid IPs file: {e}")
            
            # Fallback: send as text if file creation fails
            if len(results_text) < 4000:  # Telegram message limit
                await update.message.reply_text(f"```\n{results_text}\n```", parse_mode='Markdown')
            else:
                # Split into multiple messages if too long
                chunks = [results_text[i:i+3500] for i in range(0, len(results_text), 3500)]
                for i, chunk in enumerate(chunks):
                    await update.message.reply_text(f"```\nPart {i+1}/{len(chunks)}:\n{chunk}\n```", parse_mode='Markdown')

    async def handle_text_message(self, update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
        """Handle text messages that aren't commands"""
        await update.message.reply_text(
            "ℹ️ Please use one of the available commands. Type /help to see all commands."
        )
    
    def setup_handlers(self) -> None:
        """Setup command and message handlers"""
        # Command handlers
        self.application.add_handler(CommandHandler("start", self.start_command))
        self.application.add_handler(CommandHandler("help", self.help_command))
        self.application.add_handler(CommandHandler("scanip", self.scan_single_ip_command))
        self.application.add_handler(CommandHandler("scanrange", self.scan_range_command))
        self.application.add_handler(CommandHandler("nlaips", self.scan_nla_command))
        self.application.add_handler(CommandHandler("scanfile", self.scan_file_command))
        self.application.add_handler(CommandHandler("get", self.get_valid_ips_command))
        self.application.add_handler(CommandHandler("status", self.status_command))
        self.application.add_handler(CommandHandler("stop", self.stop_command))
        
        # Document handler for file uploads
        self.application.add_handler(MessageHandler(filters.Document.ALL, self.handle_document))
        
        # Text message handler for non-commands
        self.application.add_handler(MessageHandler(filters.TEXT & ~filters.COMMAND, self.handle_text_message))
    
    async def post_init(self, application) -> None:
        """Initialize after the application starts"""
        # Start cleanup task
        asyncio.create_task(self.run_cleanup_task())
    
    async def run_cleanup_task(self) -> None:
        """Background task to clean up old files"""
        while True:
            try:
                file_handler.cleanup_old_files(max_age_hours=1)  # Clean files older than 1 hour
                await asyncio.sleep(3600)  # Run every hour
            except Exception as e:
                logger.error(f"Error in cleanup task: {e}")
                await asyncio.sleep(3600)
    
    def run(self) -> None:
        """Run the bot"""
        if not BOT_TOKEN:
            logger.error("BOT_TOKEN environment variable is required")
            return
        
        # Create application
        self.application = Application.builder().token(BOT_TOKEN).post_init(self.post_init).build()
        
        # Setup handlers
        self.setup_handlers()
        
        # Run the bot
        logger.info("Starting Telegram RDP Scanner Bot...")
        self.application.run_polling(allowed_updates=Update.ALL_TYPES)

def main():
    """Main function"""
    try:
        bot = TelegramRDPBot()
        bot.run()
    except KeyboardInterrupt:
        logger.info("Bot stopped by user")
    except Exception as e:
        logger.error(f"Fatal error: {e}")

if __name__ == "__main__":
    main()
