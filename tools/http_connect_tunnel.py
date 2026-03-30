#!/usr/bin/env python3
import base64
import os
import socket
import sys
import threading


def usage():
    return (
        "usage: http_connect_tunnel.py <proxy_host> <proxy_port> <proxy_user> "
        "<proxy_pass> <target_host> <target_port>\n"
        "   or: http_connect_tunnel.py --proxy-file <proxy_file> <target_host> <target_port>"
    )


def set_binary_stdio():
    if os.name != "nt":
        return
    try:
        import msvcrt

        msvcrt.setmode(sys.stdin.fileno(), os.O_BINARY)
        msvcrt.setmode(sys.stdout.fileno(), os.O_BINARY)
    except Exception:
        pass


def read_http_response(sock):
    response = b""
    while b"\r\n\r\n" not in response and len(response) < 32768:
        chunk = sock.recv(4096)
        if not chunk:
            break
        response += chunk
    return response


def pump_stdin_to_socket(sock):
    try:
        while True:
            chunk = os.read(sys.stdin.fileno(), 32768)
            if not chunk:
                break
            sock.sendall(chunk)
    finally:
        try:
            sock.shutdown(socket.SHUT_WR)
        except OSError:
            pass


def connect_tunnel(proxy_host, proxy_port, proxy_user, proxy_pass, target_host, target_port):
    try:
        sock = socket.create_connection((proxy_host, int(proxy_port)), timeout=20)
    except OSError as exc:
        raise RuntimeError(f"{proxy_host}:{proxy_port} connect failed: {exc}") from exc

    try:
        token = base64.b64encode(f"{proxy_user}:{proxy_pass}".encode("utf-8")).decode("ascii")
        request = (
            f"CONNECT {target_host}:{target_port} HTTP/1.1\r\n"
            f"Host: {target_host}:{target_port}\r\n"
            f"Proxy-Authorization: Basic {token}\r\n"
            "Proxy-Connection: Keep-Alive\r\n"
            "\r\n"
        )
        sock.sendall(request.encode("ascii"))
        response = read_http_response(sock)
        status_line = response.split(b"\r\n", 1)[0].decode("iso-8859-1", errors="replace")
        if not status_line.startswith("HTTP/1.0 200") and not status_line.startswith("HTTP/1.1 200"):
            raise RuntimeError(f"{proxy_host}:{proxy_port} tunnel failed: {status_line}")

        sock.settimeout(None)

        header_sep = response.find(b"\r\n\r\n")
        if header_sep >= 0:
            buffered = response[header_sep + 4 :]
            if buffered:
                sys.stdout.buffer.write(buffered)
                sys.stdout.buffer.flush()

        stdin_thread = threading.Thread(target=pump_stdin_to_socket, args=(sock,), daemon=True)
        stdin_thread.start()

        while True:
            chunk = sock.recv(32768)
            if not chunk:
                break
            sys.stdout.buffer.write(chunk)
            sys.stdout.buffer.flush()
    finally:
        try:
            sock.close()
        except OSError:
            pass

    return 0


def load_proxy_candidates(argv):
    if len(argv) == 6:
        proxy_host, proxy_port, proxy_user, proxy_pass, target_host, target_port = argv
        return [(proxy_host, proxy_port, proxy_user, proxy_pass)], target_host, target_port

    if (len(argv) == 4) and (argv[0] == "--proxy-file"):
        proxy_file, target_host, target_port = argv[1:]
        proxies = []
        with open(proxy_file, "r", encoding="utf-8", errors="replace") as handle:
            for raw_line in handle:
                line = raw_line.strip()
                if not line:
                    continue
                parts = line.split(":", 3)
                if len(parts) != 4:
                    continue
                proxies.append(tuple(parts))
        if not proxies:
            raise RuntimeError(f"no usable proxies found in {proxy_file}")
        return proxies, target_host, target_port

    raise RuntimeError(usage())


def main():
    set_binary_stdio()

    try:
        proxies, target_host, target_port = load_proxy_candidates(sys.argv[1:])
    except RuntimeError as exc:
        print(str(exc), file=sys.stderr)
        return 2

    errors = []
    for proxy_host, proxy_port, proxy_user, proxy_pass in proxies:
        try:
            return connect_tunnel(proxy_host, proxy_port, proxy_user, proxy_pass, target_host, target_port)
        except RuntimeError as exc:
            errors.append(str(exc))

    if errors:
        print(errors[-1], file=sys.stderr)
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
