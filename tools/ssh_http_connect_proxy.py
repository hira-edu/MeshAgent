#!/usr/bin/env python3
"""Open an HTTP CONNECT tunnel for OpenSSH ProxyCommand.

Proxy credentials are intentionally read from a local proxy-list file at runtime
instead of being stored in SSH config. Expected line format:

    host:port:username:password
"""

from __future__ import annotations

import argparse
import base64
import os
import pathlib
import select
import socket
import sys
import threading


def default_proxy_files() -> list[pathlib.Path]:
    home = pathlib.Path.home()
    return [
        home / "Downloads" / "Webshare 50 proxies (1).txt",
        home / "Downloads" / "Webshare 50 proxies.txt",
    ]


def parse_proxy_lines(proxy_file: pathlib.Path) -> list[tuple[str, int, str, str]]:
    proxies: list[tuple[str, int, str, str]] = []
    with proxy_file.open("r", encoding="utf-8", errors="replace") as handle:
        for raw in handle:
            line = raw.strip()
            if not line or line.startswith("#"):
                continue
            parts = line.split(":")
            if len(parts) < 4:
                continue
            try:
                port = int(parts[1])
            except ValueError:
                continue
            proxies.append((parts[0], port, parts[2], ":".join(parts[3:])))
    return proxies


def resolve_proxy_file(explicit: str | None) -> pathlib.Path:
    candidates = [pathlib.Path(explicit)] if explicit else []
    env_path = os.environ.get("MESHCENTRAL_PROXY_LIST")
    if env_path and not explicit:
        candidates.append(pathlib.Path(env_path))
    candidates.extend(default_proxy_files())
    for candidate in candidates:
        if candidate.exists():
            return candidate
    raise FileNotFoundError("No proxy list found. Set MESHCENTRAL_PROXY_LIST or place the Webshare list in Downloads.")


def connect_via_proxy(proxy: tuple[str, int, str, str], target_host: str, target_port: int, timeout: float):
    host, port, username, password = proxy
    sock = socket.create_connection((host, port), timeout=timeout)
    sock.settimeout(timeout)
    token = base64.b64encode(f"{username}:{password}".encode("utf-8")).decode("ascii")
    request = (
        f"CONNECT {target_host}:{target_port} HTTP/1.1\r\n"
        f"Host: {target_host}:{target_port}\r\n"
        f"Proxy-Authorization: Basic {token}\r\n"
        "Proxy-Connection: keep-alive\r\n\r\n"
    )
    sock.sendall(request.encode("ascii"))

    received = b""
    while b"\r\n\r\n" not in received and len(received) < 8192:
        chunk = sock.recv(1024)
        if not chunk:
            break
        received += chunk

    header, separator, remainder = received.partition(b"\r\n\r\n")
    status_line = header.splitlines()[0].decode("iso-8859-1", errors="replace") if header else ""
    if not separator or " 200 " not in status_line:
        sock.close()
        raise ConnectionError(status_line or "proxy CONNECT failed")
    sock.settimeout(None)
    return sock, remainder


def set_binary_stdio() -> None:
    if os.name != "nt":
        return
    import msvcrt

    msvcrt.setmode(sys.stdin.fileno(), os.O_BINARY)
    msvcrt.setmode(sys.stdout.fileno(), os.O_BINARY)


def pipe_stdin_to_socket(sock: socket.socket) -> None:
    try:
        while True:
            data = os.read(sys.stdin.fileno(), 32768)
            if not data:
                break
            sock.sendall(data)
    except OSError:
        pass
    finally:
        try:
            sock.shutdown(socket.SHUT_WR)
        except OSError:
            pass


def pipe_socket_to_stdout(sock: socket.socket, initial: bytes) -> None:
    try:
        if initial:
            os.write(sys.stdout.fileno(), initial)
        while True:
            data = sock.recv(32768)
            if not data:
                break
            os.write(sys.stdout.fileno(), data)
    except OSError:
        pass


def main() -> int:
    parser = argparse.ArgumentParser(description="Open an HTTP CONNECT tunnel for OpenSSH ProxyCommand.")
    parser.add_argument("host")
    parser.add_argument("port", type=int)
    parser.add_argument("--proxy-list")
    parser.add_argument("--timeout", type=float, default=10.0)
    args = parser.parse_args()

    proxy_file = resolve_proxy_file(args.proxy_list)
    proxies = parse_proxy_lines(proxy_file)
    if not proxies:
        raise RuntimeError(f"No usable proxies found in {proxy_file}")

    last_error: Exception | None = None
    for proxy in proxies:
        try:
            sock, remainder = connect_via_proxy(proxy, args.host, args.port, args.timeout)
            break
        except Exception as exc:
            last_error = exc
    else:
        raise RuntimeError(f"No proxy could connect to {args.host}:{args.port}: {last_error}")

    set_binary_stdio()
    sender = threading.Thread(target=pipe_stdin_to_socket, args=(sock,), daemon=True)
    sender.start()
    pipe_socket_to_stdout(sock, remainder)
    try:
        sock.close()
    except OSError:
        pass
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
