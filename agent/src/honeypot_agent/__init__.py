"""Honeypot-Dashboard ingestion agent.

A small daemon that runs on the honeypot host, tails ``cowrie.json`` and ships
the events to the backend over TLS 1.3.
"""

__version__ = "0.1.0"
