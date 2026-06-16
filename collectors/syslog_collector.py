"""
Syslog collectors for receiving logs via UDP and TCP.

Supports RFC 3164 and RFC 5424 syslog formats received over network.
"""

import socket
import threading
import logging
from .base import BaseCollector, CollectorResult, CollectorStatus

logger = logging.getLogger(__name__)


class SyslogCollector(BaseCollector):
    """Base syslog collector supporting both UDP and TCP."""

    def __init__(self, name="syslog", host="0.0.0.0", port=514, protocol="udp",
                 buffer_size=65536, config=None):
        super().__init__(name=name, source=f"syslog://{host}:{port}/{protocol}",
                         config=config or {})
        self.host = host
        self.port = port
        self.protocol = protocol.lower()
        self.buffer_size = buffer_size
        self._socket = None
        self._client_socks = []

    def _create_socket(self):
        """Create the listening socket."""
        sock_type = socket.SOCK_DGRAM if self.protocol == "udp" else socket.SOCK_STREAM
        family = socket.AF_INET6 if ":" in self.host else socket.AF_INET

        sock = socket.socket(family, sock_type)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

        # Set receive buffer size
        try:
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 1048576)
        except (socket.error, AttributeError):
            pass

        sock.bind((self.host, self.port))
        sock.settimeout(1.0)

        if self.protocol == "tcp":
            sock.listen(self.config.get("backlog", 128))

        return sock

    def _on_start(self):
        """Create socket when collector starts."""
        try:
            self._socket = self._create_socket()
            logger.info("Syslog collector %s listening on %s:%d (%s)",
                       self.name, self.host, self.port, self.protocol.upper())
        except socket.error as exc:
            logger.error("Failed to bind syslog collector %s: %s", self.name, exc)
            self.status = CollectorStatus.ERROR
            raise

    def _on_stop(self):
        """Clean up sockets when collector stops."""
        for client_sock in self._client_socks:
            try:
                client_sock.close()
            except Exception:
                pass
        self._client_socks.clear()
        if self._socket:
            try:
                self._socket.close()
            except Exception:
                pass
            self._socket = None

    def collect(self):
        """Collect is handled by _run_loop; this is a no-op for network collectors."""
        return CollectorResult(success=True, events_collected=0)

    def _run_loop(self):
        """Override run loop for network-based collection."""
        self._on_start()
        if self.protocol == "udp":
            self._run_udp()
        else:
            self._run_tcp()

    def _run_udp(self):
        """Run UDP collection loop."""
        self.status = CollectorStatus.RUNNING
        while not self._stop_event.is_set():
            try:
                data, addr = self._socket.recvfrom(self.buffer_size)
                if data:
                    self._handle_message(data, addr)
            except socket.timeout:
                continue
            except socket.error as exc:
                if not self._stop_event.is_set():
                    logger.error("UDP socket error in collector %s: %s", self.name, exc)
                    self._stats["errors"] += 1
                    time.sleep(0.1)

    def _run_tcp(self):
        """Run TCP collection loop with client handling."""
        self.status = CollectorStatus.RUNNING

        while not self._stop_event.is_set():
            try:
                self._socket.settimeout(1.0)
                client_sock, addr = self._socket.accept()
                client_sock.settimeout(1.0)
                self._client_socks.append(client_sock)
                thread = threading.Thread(
                    target=self._handle_tcp_client,
                    args=(client_sock, addr),
                    daemon=True
                )
                thread.start()
            except socket.timeout:
                continue
            except socket.error as exc:
                if not self._stop_event.is_set():
                    logger.error("TCP accept error in collector %s: %s", self.name, exc)
                    time.sleep(0.1)

    def _handle_tcp_client(self, client_sock, addr):
        """Handle a single TCP client connection."""
        buffer = b""
        try:
            while not self._stop_event.is_set():
                try:
                    data = client_sock.recv(self.buffer_size)
                    if not data:
                        break
                    buffer += data
                    # Process complete messages (newline or octet-counting delimited)
                    while b"\n" in buffer:
                        line, buffer = buffer.split(b"\n", 1)
                        if line:
                            self._handle_message(line, addr)
                except socket.timeout:
                    continue
                except socket.error:
                    break
        finally:
            try:
                client_sock.close()
            except Exception:
                pass
            if client_sock in self._client_socks:
                self._client_socks.remove(client_sock)

    def _handle_message(self, data, addr):
        """Handle a single syslog message."""
        try:
            raw_data = data.decode("utf-8", errors="replace").strip()
            if not raw_data:
                return

            metadata = {
                "remote_addr": addr[0] if addr else None,
                "remote_port": addr[1] if addr else None,
                "protocol": self.protocol,
            }
            self._emit(raw_data, metadata)
            self._stats["events_collected"] += 1
            self._stats["bytes_collected"] += len(data)
        except Exception as exc:
            logger.error("Error handling syslog message in %s: %s", self.name, exc)
            self._stats["errors"] += 1


class UDPSyslogCollector(SyslogCollector):
    """UDP-specific syslog collector."""

    def __init__(self, name="syslog_udp", host="0.0.0.0", port=514, config=None):
        super().__init__(name=name, host=host, port=port, protocol="udp", config=config)


class TCPSyslogCollector(SyslogCollector):
    """TCP-specific syslog collector."""

    def __init__(self, name="syslog_tcp", host="0.0.0.0", port=514, config=None):
        super().__init__(name=name, host=host, port=port, protocol="tcp", config=config)


# Import time at module level for error handling
import time
