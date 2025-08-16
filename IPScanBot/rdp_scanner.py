"""
RDP Scanner module for port scanning and NLA detection.

This module provides asynchronous functions to scan individual IP
addresses, lists of addresses and ranges for open Remote Desktop
Protocol (RDP) ports.  It includes a lightweight Network Level
Authentication (NLA) detector based on the RDP security negotiation
request defined in [MS-RDPBCGR].  If the server negotiates the
HYBRID protocol, NLA is assumed to be enabled; if it negotiates
standard RDP or TLS only, NLA is considered disabled.  Errors
during detection result in an unknown NLA status.

Two convenience functions, ``validate_ip_address`` and
``validate_ip_range``, are provided for validating IP strings and
ranges.  These helpers are imported by the main bot module.
"""

import asyncio
import ipaddress
import logging
from typing import List, Dict, Optional, Any, Callable

from .config import RDP_PORT, DEFAULT_TIMEOUT, MAX_CONCURRENT_SCANS

# Initialize a module-level logger
logger = logging.getLogger(__name__)


def validate_ip_address(ip: str) -> bool:
    """Return True if ``ip`` is a valid IPv4 or IPv6 address.

    :param ip: IP address string to validate.
    :return: True if valid, False otherwise.
    """
    try:
        ipaddress.ip_address(ip)
        return True
    except Exception:
        return False


def validate_ip_range(start_ip: str, end_ip: str) -> bool:
    """Return True if ``start_ip`` and ``end_ip`` form a valid inclusive range.

    A range is valid when both endpoints are valid IP addresses and the
    numerical value of ``start_ip`` is less than or equal to
    ``end_ip``.

    :param start_ip: Starting IP address.
    :param end_ip: Ending IP address.
    :return: True if the range is valid, False otherwise.
    """
    try:
        start_addr = ipaddress.ip_address(start_ip)
        end_addr = ipaddress.ip_address(end_ip)
        return int(start_addr) <= int(end_addr)
    except Exception:
        return False


class RDPScanner:
    """Asynchronous RDP port scanner with optional NLA detection.

    Each instance controls its own concurrency via an asyncio
    semaphore.  The timeout for network operations can be set via the
    ``timeout`` parameter (defaults to ``DEFAULT_TIMEOUT`` from
    :mod:`config`).
    """

    def __init__(self, timeout: Optional[float] = DEFAULT_TIMEOUT) -> None:
        # Convert None to a large number for unlimited timeout
        if timeout is None:
            timeout = float('inf')
        self.timeout = float(timeout)
        # Use a semaphore to limit concurrent network connections
        self.semaphore = asyncio.Semaphore(MAX_CONCURRENT_SCANS)

    async def _perform_scan(self, ip: str) -> Dict[str, Any]:
        """Perform an RDP port scan and optionally detect NLA.

        A low‑level helper invoked by :meth:`scan_single_ip`.  It
        returns a result dictionary with keys ``ip``, ``port_open``,
        ``nla_enabled`` and ``error``.  ``nla_enabled`` will be
        ``True`` if NLA appears enabled, ``False`` if disabled, and
        ``None`` if the status cannot be determined.

        :param ip: IP address to scan.
        :return: Result dictionary describing the scan outcome.
        """
        result: Dict[str, Any] = {
            'ip': ip,
            'port_open': False,
            'nla_enabled': None,
            'error': None
        }
        try:
            # Validate IP address early
            ipaddress.ip_address(ip)
            try:
                connect_coro = asyncio.open_connection(ip, RDP_PORT)
                if self.timeout and self.timeout != float('inf'):
                    reader, writer = await asyncio.wait_for(connect_coro, timeout=self.timeout)
                else:
                    reader, writer = await connect_coro
            except asyncio.TimeoutError:
                result['error'] = 'Timeout'
                return result
            except OSError:
                # Connection refused or network unreachable implies closed port
                result['port_open'] = False
                return result
            except Exception as exc:
                result['error'] = str(exc)
                return result

            # If we reach here, the TCP connection succeeded
            result['port_open'] = True
            try:
                nla_status = await self._detect_nla_async(reader, writer)
                result['nla_enabled'] = nla_status
            except Exception as exc:
                # Log and fall back to unknown status on detection failure
                logger.debug(f'NLA detection failed for {ip}: {exc}')
                result['nla_enabled'] = None
            finally:
                try:
                    writer.close()
                    await writer.wait_closed()
                except Exception:
                    pass
        except ValueError:
            result['error'] = 'Invalid IP address'
        except Exception as exc:
            result['error'] = str(exc)
            logger.error(f'Scan error for {ip}: {exc}')
        return result

    async def _detect_nla_async(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> Optional[bool]:
        """Attempt to detect Network Level Authentication status for an open RDP port.

        This method sends an RDP Negotiation Request advertising support for
        standard RDP, TLS, and NLA.  It reads the server's negotiation
        response and interprets the ``selectedProtocol`` field: if the
        HYBRID protocol bit is set, NLA is required; if only SSL or
        standard RDP is selected, NLA is disabled.  If detection fails
        or the server responds unexpectedly, ``None`` is returned.

        :param reader: StreamReader for the established TCP connection.
        :param writer: StreamWriter for the established TCP connection.
        :return: True if NLA appears enabled, False if disabled, or None if unknown.
        """
        try:
            # TPKT header: version=3, reserved=0, total length=19 (0x13)
            tpkt = b"\x03\x00\x00\x13"
            # X.224 CR TPDU: length=11, type=0xe0 (connect request), dstRef=0x0000,
            # srcRef=0x0000, class=0x00
            x224 = b"\x0b\xe0\x00\x00\x00\x00\x00"
            # RDP Negotiation Request: type=1, flags=0, length=8,
            # requestedProtocols=0x00000007 (RDP|SSL|HYBRID)
            rdp_neg_req = b"\x01\x00\x08\x00\x07\x00\x00\x00"
            packet = tpkt + x224 + rdp_neg_req
            writer.write(packet)
            await writer.drain()
            # Expect at least the same length back; read a small chunk for analysis
            data = await asyncio.wait_for(reader.read(19), timeout=2.0)
            if not data or len(data) < 11:
                return None
            # Find the negotiation response (type 0x02)
            try:
                index = data.index(b"\x02")
            except ValueError:
                return None
            # Extract selectedProtocol (4 bytes at offset +4)
            if len(data) >= index + 8:
                selected_bytes = data[index + 4:index + 8]
                if len(selected_bytes) == 4:
                    selected = int.from_bytes(selected_bytes, byteorder='little')
                    # PROTOCOL_HYBRID (0x2) => NLA enabled
                    if selected & 0x02:
                        return True
                    # PROTOCOL_SSL (0x1) => TLS only, NLA disabled
                    if selected & 0x01:
                        return False
                    # PROTOCOL_RDP (0x0) => classic RDP, NLA disabled
                    if selected == 0:
                        return False
            return None
        except Exception:
            return None

    async def scan_single_ip(self, ip: str) -> Dict[str, Any]:
        """Scan a single IP address for open RDP port and NLA status.

        Uses the class semaphore to limit concurrent scans.  Returns a
        dictionary describing the result (see :meth:`_perform_scan`).

        :param ip: IP address to scan.
        :return: Result dictionary.
        """
        async with self.semaphore:
            return await self._perform_scan(ip)

    async def scan_ip_list(self, ip_list: List[str], progress_callback: Callable[[float, str, Dict[str, Any]], Any]) -> List[Dict[str, Any]]:
        """Scan an arbitrary list of IP addresses concurrently.

        :param ip_list: Iterable of IP addresses to scan.
        :param progress_callback: Async callable invoked after each scan with
            parameters (progress, ip, result).  The callback may return a
            truthy value to continue or falsy to request cancellation.
        :return: List of result dictionaries for each IP scanned.  The order
            corresponds to the completion order rather than the input order.
        """
        total = len(ip_list)
        results: List[Dict[str, Any]] = []
        if total == 0:
            return results
        completed = 0
        cancel = False

        async def worker(ip: str) -> Optional[Dict[str, Any]]:
            nonlocal completed, cancel
            res = await self.scan_single_ip(ip)
            completed += 1
            progress = (completed / total) * 100.0
            try:
                cont = await progress_callback(progress, ip, res)
            except Exception:
                cont = True
            if not cont:
                cancel = True
            return res

        tasks = [asyncio.create_task(worker(ip)) for ip in ip_list]
        try:
            for fut in asyncio.as_completed(tasks):
                res = await fut
                if res is not None:
                    results.append(res)
                if cancel:
                    for t in tasks:
                        if not t.done():
                            t.cancel()
                    break
        finally:
            for t in tasks:
                try:
                    await t
                except asyncio.CancelledError:
                    pass
                except Exception:
                    pass
        return results

    async def scan_ip_range(self, start_ip: str, end_ip: str, progress_callback: Callable[[float, str, Dict[str, Any]], Any]) -> List[Dict[str, Any]]:
        """Scan all IPs from ``start_ip`` to ``end_ip`` inclusive.

        :param start_ip: Starting IP address in the range.
        :param end_ip: Ending IP address in the range.
        :param progress_callback: Async callable invoked after each scan.
        :return: List of result dictionaries for each IP scanned.
        :raises ValueError: If the range is invalid.
        """
        if not validate_ip_range(start_ip, end_ip):
            raise ValueError('Invalid IP range')
        start_addr = ipaddress.ip_address(start_ip)
        end_addr = ipaddress.ip_address(end_ip)
        ip_list = [str(ipaddress.ip_address(i)) for i in range(int(start_addr), int(end_addr) + 1)]
        return await self.scan_ip_list(ip_list, progress_callback)

    def format_results(self, results: List[Dict[str, Any]], include_nla: bool = False) -> str:
        """Return a human‑readable summary of scan results.

        Each result is printed on its own line as ``IP - STATUS``.  If
        ``include_nla`` is True and the port is open, the NLA status is
        appended.  Errors are reported with the error message.

        :param results: List of result dictionaries.
        :param include_nla: Whether to include NLA information for open ports.
        :return: A newline‑separated string of formatted results.
        """
        lines: List[str] = []
        for res in results:
            ip = res.get('ip', '')
            error = res.get('error')
            if error:
                lines.append(f"{ip} - Error: {error}")
                continue
            if res.get('port_open'):
                line = f"{ip} - Open"
                if include_nla:
                    nla = res.get('nla_enabled')
                    if nla is True:
                        line += ' - NLA Enabled'
                    elif nla is False:
                        line += ' - NLA Disabled'
                    else:
                        line += ' - NLA Unknown'
            else:
                line = f"{ip} - Closed"
            lines.append(line)
        return "\n".join(lines)
