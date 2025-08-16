"""
RDP Scanner module for port scanning and NLA detection
"""
import socket
import asyncio
import struct
import ipaddress
from typing import List, Tuple, Dict, Optional, Any
import logging
# Use a relative import to reference config within the same package.  This
# avoids ModuleNotFoundError when the package is imported from outside the
# repository root or when executed as a module.
from .config import RDP_PORT, DEFAULT_TIMEOUT, MAX_CONCURRENT_SCANS

logger = logging.getLogger(__name__)

class RDPScanner:
    """Asynchronous RDP port scanner with optional NLA detection.

    The scanner limits concurrent network connections via a semaphore and
    utilises asyncio's non‑blocking I/O primitives to perform port probes and
    protocol negotiation.  This improves throughput compared to blocking
    socket calls and allows graceful cancellation when scans are halted.
    """

    def __init__(self, timeout: int = DEFAULT_TIMEOUT) -> None:
        # Runtime adjustable timeout for each connection attempt.  Casting to
        # float here allows e.g. "5.5" to be accepted from environment
        # variables.  Catch conversion errors upstream in config if needed.
        self.timeout: float = float(timeout)
        # Semaphore to limit number of concurrent connections as configured in
        # MAX_CONCURRENT_SCANS.  Without this semaphore tasks could create
        # thousands of connections in parallel, exhausting resources.
        self.semaphore = asyncio.Semaphore(MAX_CONCURRENT_SCANS)

    async def scan_single_ip(self, ip: str) -> Dict[str, Any]:
        """
        Scan a single IP address for RDP port availability and NLA status.

        This coroutine acquires the global semaphore before performing the
        scan.  It validates the provided IP address, attempts to establish a
        TCP connection to the RDP port using asyncio, and, if successful,
        negotiates minimal RDP to detect whether Network Level Authentication
        (NLA) is required.

        Args:
            ip: IP address to scan

        Returns:
            A dictionary describing the scan result with keys:
            ``ip`` (str), ``port_open`` (bool), ``nla_enabled`` (bool | str | None),
            and ``error`` (str | None).
        """
        async with self.semaphore:
            return await self._perform_scan(ip)

    async def _perform_scan(self, ip: str) -> Dict[str, Any]:
        """
        Internal implementation for scanning a single IP address.

        Performs address validation then attempts to open an asyncio connection
        within the configured timeout.  If the connection cannot be
        established within the timeout the ``error`` field is set to
        ``"Timeout"``.  When a connection is made, the port is considered
        open and the method proceeds to attempt NLA detection via a simple
        RDP negotiation sequence.  Any exception raised during NLA detection
        results in ``nla_enabled`` being set to "Unknown".

        Args:
            ip: IP address as a string

        Returns:
            A dictionary with scan result data
        """
        result: Dict[str, Any] = {
            'ip': ip,
            'port_open': False,
            'nla_enabled': None,
            'error': None
        }
        try:
            # Validate IP address; raises ValueError if invalid
            ipaddress.ip_address(ip)

            # Attempt to open a TCP connection asynchronously
            try:
                # Use asyncio.open_connection to respect cancellation.  Wrap
                # connection attempt in wait_for to enforce timeout.
                connect_coro = asyncio.open_connection(ip, RDP_PORT)
                reader, writer = await asyncio.wait_for(connect_coro, timeout=self.timeout)
            except asyncio.TimeoutError:
                # Timeout connecting to host
                result['error'] = "Timeout"
                return result
            except OSError as ose:
                # Any socket‑level error; treat as port closed (e.g. connection refused)
                result['port_open'] = False
                # Distinguish between errors that indicate a closed port and other network issues
                result['error'] = None  # Clear error to indicate graceful close
                return result
            except Exception as e:
                # Unexpected exceptions are recorded as errors
                result['error'] = str(e)
                return result

            # If we reach this point, the connection succeeded
            result['port_open'] = True
            try:
                # Attempt NLA detection using the asynchronous reader/writer
                nla_status = await self._detect_nla_async(reader, writer)
                result['nla_enabled'] = nla_status
            except Exception as e:
                logger.debug(f"NLA detection failed for {ip}: {e}")
                result['nla_enabled'] = "Unknown"
            finally:
                # Always close the writer to free socket resources
                try:
                    writer.close()
                    await writer.wait_closed()
                except Exception:
                    pass
        except ValueError:
            result['error'] = "Invalid IP address"
        except Exception as e:
            # Catch‑all for unexpected errors
            result['error'] = str(e)
            logger.error(f"Scan error for {ip}: {e}")
        return result
    
    async def _detect_nla(self, sock: socket.socket) -> Optional[bool]:
        """
        Detect if Network Level Authentication is enabled
        
        Args:
            sock: Connected socket
            
        Returns:
            True if NLA is enabled, False if disabled, None if unknown
        """
        try:
            # RDP Connection Request packet (simplified)
            # This is a basic RDP negotiation to detect NLA
            rdp_request = (
                b'\x03\x00\x00\x13'  # TPKT Header
                b'\x0e\xe0\x00\x00'  # X.224 Connection Request
                b'\x00\x00\x00\x01'  # RDP NEG_REQ
                b'\x00\x08\x00\x03'  # Protocols: SSL, CredSSP
                b'\x00'
            )
            
            sock.send(rdp_request)
            
            # Read response
            response = sock.recv(1024)
            
            if len(response) >= 19:
                # Check for CredSSP (NLA) support in response
                # If CredSSP is required, NLA is enabled
                if b'\x03\x00\x00' in response and len(response) > 15:
                    # Look for protocol selection in response
                    if b'\x02' in response[15:19]:  # CredSSP selected
                        return True
                    elif b'\x01' in response[15:19]:  # SSL only
                        return False
            
            return None
            
        except Exception as e:
            logger.debug(f"NLA detection error: {e}")
            return None

    async def _detect_nla_async(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> Optional[bool]:
        """
        Perform NLA detection over an established asyncio stream.

        This method sends a minimal RDP negotiation request and reads the
        response asynchronously.  The logic mirrors the synchronous
        ``_detect_nla`` but utilises asyncio primitives and includes its
        own timeout control.  Returning ``True`` means NLA (CredSSP) is
        required; ``False`` means SSL only; and ``None`` indicates the
        status could not be determined.

        Args:
            reader: StreamReader obtained from asyncio.open_connection
            writer: StreamWriter obtained from asyncio.open_connection

        Returns:
            Optional[bool]: True if NLA enabled, False if disabled, None if unknown
        """
        try:
            # Build a basic RDP negotiation packet.  This binary blob is the
            # same as used in the synchronous detector: TPKT header,
            # X.224 connection request and a NEG_REQ specifying SSL and
            # CredSSP protocols.
            rdp_request = (
                b'\x03\x00\x00\x13'
                b'\x0e\xe0\x00\x00'
                b'\x00\x00\x00\x01'
                b'\x00\x08\x00\x03'
                b'\x00'
            )

            # Send the request and flush the writer
            writer.write(rdp_request)
            await writer.drain()

            # Attempt to read the response with a timeout.  We reuse
            # self.timeout here for symmetry; this read timeout is separate
            # from the connection timeout in _perform_scan.
            response = await asyncio.wait_for(reader.read(1024), timeout=self.timeout)

            # A valid RDP negotiation response should be at least 19 bytes.
            if len(response) >= 19:
                # The response will include a TPKT header (\x03) and a length,
                # followed by an X.224 header.  To detect NLA we inspect the
                # RDP Negotiation Response field which starts around byte 15.
                # If the selected protocol field contains 0x02 then CredSSP
                # (NLA) is required; if it contains 0x01 then SSL only is
                # offered.
                if b'\x03\x00\x00' in response and len(response) > 18:
                    proto_field = response[15:19]
                    if b'\x02' in proto_field:
                        return True
                    elif b'\x01' in proto_field:
                        return False
            return None
        except asyncio.TimeoutError:
            # No response within timeout means NLA status is unknown
            return None
        except Exception as e:
            logger.debug(f"Asynchronous NLA detection error: {e}")
            return None
    
    async def scan_ip_list(self, ip_list: List[str], progress_callback=None) -> List[Dict[str, Any]]:
        """
        Scan a list of IP addresses concurrently
        
        Args:
            ip_list: List of IP addresses to scan
            progress_callback: Optional callback function for progress updates
            
        Returns:
            List of scan results
        """
        results: List[Dict[str, Any]] = []
        total_ips: int = len(ip_list)

        # Precreate tasks for each IP.  Maintaining a separate list of IPs
        # allows us to report progress in the original order even though
        # individual tasks may complete out of order.
        tasks: List[asyncio.Task] = [asyncio.create_task(self.scan_single_ip(ip)) for ip in ip_list]

        # Iterate sequentially over the tasks but respect the order of the IP
        # list.  After each task completes we update progress and, if the
        # progress callback returns False, we cancel the remaining tasks.
        for idx, (ip, task) in enumerate(zip(ip_list, tasks)):
            try:
                result = await task
            except Exception as e:
                logger.error(f"Task error for {ip}: {e}")
                result = {
                    'ip': ip,
                    'port_open': False,
                    'nla_enabled': None,
                    'error': str(e)
                }

            results.append(result)

            # Compute progress based on completed tasks
            if progress_callback:
                try:
                    progress: float = (len(results) / total_ips) * 100 if total_ips else 100.0
                    cont = await progress_callback(progress, ip, result)
                    # If the callback indicates scanning should stop, cancel remaining tasks
                    if cont is False:
                        # Cancel any pending tasks
                        for remaining_task in tasks[idx + 1:]:
                            remaining_task.cancel()
                        break
                except Exception as cb_err:
                    # Log callback errors but do not abort scanning
                    logger.error(f"Progress callback error for {ip}: {cb_err}")

        return results
    
    async def scan_ip_range(self, start_ip: str, end_ip: str, progress_callback=None) -> List[Dict[str, Any]]:
        """
        Scan a range of IP addresses
        
        Args:
            start_ip: Starting IP address
            end_ip: Ending IP address
            progress_callback: Optional callback function for progress updates
            
        Returns:
            List of scan results
        """
        try:
            # Validate and convert IP addresses
            start_addr = ipaddress.ip_address(start_ip)
            end_addr = ipaddress.ip_address(end_ip)
            
            if int(start_addr) > int(end_addr):
                raise ValueError("Start IP must be less than or equal to end IP")
            
            # Generate IP list
            ip_list = []
            current_addr = start_addr
            while int(current_addr) <= int(end_addr):
                ip_list.append(str(current_addr))
                current_addr += 1
                
                # Limit the range to prevent abuse
                if len(ip_list) > 1000:
                    raise ValueError("IP range too large. Maximum 1000 IPs allowed.")
            
            return await self.scan_ip_list(ip_list, progress_callback)
            
        except Exception as e:
            logger.error(f"Range scan error: {e}")
            raise
    
    def format_results(self, results: List[Dict[str, Any]], include_nla: bool = False) -> str:
        """
        Format scan results as text
        
        Args:
            results: List of scan results
            include_nla: Whether to include NLA information
            
        Returns:
            Formatted text string
        """
        lines = []
        open_count = 0
        
        for result in results:
            ip = result['ip']
            
            if result['error']:
                status = f"Error: {result['error']}"
            elif result['port_open']:
                open_count += 1
                if include_nla and result['nla_enabled'] is not None:
                    nla_status = "NLA Enabled" if result['nla_enabled'] else "NLA Disabled"
                    if result['nla_enabled'] == "Unknown":
                        nla_status = "NLA Unknown"
                    status = f"Open - {nla_status}"
                else:
                    status = "Open"
            else:
                status = "Closed"
            
            lines.append(f"{ip} - {status}")
        
        # Add summary
        total_scanned = len(results)
        lines.append(f"\n--- Summary ---")
        lines.append(f"Total IPs Scanned: {total_scanned}")
        lines.append(f"Open RDP Ports: {open_count}")
        lines.append(f"Closed/Error: {total_scanned - open_count}")
        
        return "\n".join(lines)

def validate_ip_address(ip: str) -> bool:
    """
    Validate if a string is a valid IP address
    
    Args:
        ip: IP address string to validate
        
    Returns:
        True if valid, False otherwise
    """
    try:
        ipaddress.ip_address(ip.strip())
        return True
    except ValueError:
        return False

def validate_ip_range(start_ip: str, end_ip: str) -> bool:
    """
    Validate if IP range is valid
    
    Args:
        start_ip: Starting IP address
        end_ip: Ending IP address
        
    Returns:
        True if valid range, False otherwise
    """
    try:
        start_addr = ipaddress.ip_address(start_ip.strip())
        end_addr = ipaddress.ip_address(end_ip.strip())
        return int(start_addr) <= int(end_addr)
    except ValueError:
        return False
