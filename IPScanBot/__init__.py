"""
IPScanBot package
=================

This file marks the ``IPScanBot`` directory as a Python package and allows
relative imports within the package to work correctly when the code is
executed as a module or installed as a dependency.  Without this file,
Python's import machinery may treat the directory as a namespace package
depending on the execution context, which can cause module resolution
problems when running scripts directly.  The package exposes no public
symbols by default.
"""

# Expose key classes and functions at the package level for convenience
from .rdp_scanner import RDPScanner, validate_ip_address, validate_ip_range  # noqa: F401
from .file_handler import FileHandler, format_scan_summary  # noqa: F401