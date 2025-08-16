"""
RDP Scanner module for port scanning and NLA detection
"""
import socket
import asyncio
import struct
import ipaddress
from typing import List, Tuple, Dict, Optional, Any
import logging
from .config import RDP_PORT, DEFAULT_TIMEOUT, MAX_CONCURRENT_SCANS

logger = logging.getLogger(__name__)

class RDPScanner:
    """Asynchronous RDP port scanner with optional NLA detection."""

    def __init__(self, timeout: int = DEFAULT_TIMEOUT) -> None:
        # Ensure timeout is always a valid float, even if None is passed
        if timeout is None:
            timeout = 999999  # Set a very large timeout (in seconds)
        self.timeout = float(timeout)
        self.semaphore = asyncio.Semaphore(MAX_CONCURRENT_SCANS)

    async def scan_single_ip(self, ip: str) -> Dict[str, Any]:
        """Scan a single IP address for RDP port availability and NLA status."""
        async with self.semaphore:
            return await self._perform_scan(ip)

    async def _perform_scan(self, ip: str) -> Dict[str, Any]:
        """Perform scanning for a single IP address."""
        result: Dict[str, Any] = {
            'ip': ip,
            'port_open': False,
            'nla_enabled': None,
            'error': None
        }
        try:
            ipaddress.ip_address(ip)  # Validate IP address

            try:
                connect_coro = asyncio.open_connection(ip, RDP_PORT)
                if self.timeout:
                    reader, writer = await asyncio.wait_for(connect_coro, timeout=self.timeout)
                else:
                    reader, writer = await connect_coro
            except asyncio.TimeoutError:
                result['error'] = "Timeout"
                return result
            except OSError:
                result['port_open'] = False
                result['error'] = None
                return result
            except Exception as e:
                result['error'] = str(e)
                return result

            result['port_open'] = True
            try:
                nla_status = await self._detect_nla_async(reader, writer)
                result['nla_enabled'] = nla_status
            except Exception as e:
                logger.debug(f"NLA detection failed for {ip}: {e}")
                result['nla_enabled'] = "Unknown"
            finally:
                try:
                    writer.close()
                    await writer.wait_closed()
                except Exception:
                    pass
        except ValueError:
            result['error'] = "Invalid IP address"
        except Exception as e:
            result['error'] = str(e)
            logger.error(f"Scan error for {ip}: {e}")
        return result
