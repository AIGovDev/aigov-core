"""A TCP forwarder between an executor process and PostgreSQL, which a test can cut and restore.

It stands in for a network interruption between the executor and the database. ``cut`` closes every connection and stops
listening; ``restore`` listens again on the same port. Test-only.
"""

from __future__ import annotations

import socket
import threading


class TcpProxy:
    def __init__(self, target_host: str, target_port: int) -> None:
        self._target = (target_host, target_port)
        self._lock = threading.Lock()
        self._sockets: set[socket.socket] = set()
        self._listener: socket.socket | None = None
        self._stop = False
        self.port = 0

    def start(self) -> int:
        self._stop = False
        self._listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._listener.bind(("127.0.0.1", self.port))
        self.port = self._listener.getsockname()[1]
        self._listener.listen(64)
        threading.Thread(target=self._accept, args=(self._listener,), daemon=True).start()
        return self.port

    def _accept(self, listener: socket.socket) -> None:
        while not self._stop:
            try:
                client, _ = listener.accept()
            except OSError:
                return
            try:
                server = socket.create_connection(self._target, timeout=5)
            except OSError:
                client.close()
                continue
            with self._lock:
                self._sockets.update({client, server})
            for a, b in ((client, server), (server, client)):
                threading.Thread(target=self._pipe, args=(a, b), daemon=True).start()

    def _pipe(self, src: socket.socket, dst: socket.socket) -> None:
        try:
            while True:
                data = src.recv(65536)
                if not data:
                    break
                dst.sendall(data)
        except OSError:
            pass
        finally:
            self._close_pair(src, dst)

    def _close_pair(self, *socks: socket.socket) -> None:
        with self._lock:
            for s in socks:
                self._sockets.discard(s)
        for s in socks:
            try:
                s.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
            try:
                s.close()
            except OSError:
                pass

    def cut(self) -> None:
        self._stop = True
        if self._listener is not None:
            try:
                self._listener.close()
            except OSError:
                pass
        with self._lock:
            socks = list(self._sockets)
            self._sockets.clear()
        for s in socks:
            try:
                s.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
            try:
                s.close()
            except OSError:
                pass

    def restore(self) -> None:
        self.start()
