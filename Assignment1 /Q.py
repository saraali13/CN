import socket
import os
import sys
from urllib.parse import urlparse

BUFFER_SIZE = 8192
MAX_PROCESSES = 100

active_children = 0

# Error Responses
def send_error(client_socket, code, message):
    response = f"HTTP/1.0 {code} {message}\r\n\r\n"
    client_socket.sendall(response.encode())
    print(f"Error sent: {code} {message}")

# Parse headers from request
def parse_headers(lines):
    headers = {}
    for line in lines[1:]:
        if line == "":
            break
        if ": " in line:
            key, value = line.split(": ", 1)
            headers[key] = value
    return headers

# Handle Each Client
def handle_client(client_socket):
    remote_socket = None
    try:
        request = client_socket.recv(BUFFER_SIZE).decode()

        if not request:
            client_socket.close()
            return

        lines = request.split("\r\n")

        # Validate request line
        if len(lines) < 1:
            print("Empty request")
            send_error(client_socket, 400, "Bad Request")
            client_socket.close()
            return

        request_line = lines[0].split()

        if len(request_line) != 3:
            print("Invalid Request Line")
            send_error(client_socket, 400, "Bad Request")
            client_socket.close()
            return

        method, url, version = lines[0].split()

        # Only GET allowed
        if method != "GET":
            print("Invalid Method:", method)
            send_error(client_socket, 501, "Not Implemented")
            client_socket.close()
            return

        # Parse headers
        headers = parse_headers(lines)

        # URL must be absolute (for proxy requests)
        if not url.startswith("http://") and not url.startswith("https://"):
            print("Not an absolute URL: ", url)
            send_error(client_socket, 400, "Bad Request")
            client_socket.close()
            return

        # Parse URL
        parsed = urlparse(url)

        host = parsed.hostname
        port = parsed.port if parsed.port else 80
        path = parsed.path if parsed.path else "/"

        if parsed.query:
            path += "?" + parsed.query

        if not host:
            send_error(client_socket, 400, "Bad Request")
            client_socket.close()
            return

        print(f"Forwarding request to {host}:{port}{path}")

        # Connect to Remote Server
        remote_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        remote_socket.settimeout(30)  # Add timeout

        try:
            remote_socket.connect((host, port))
        except Exception as e:
            print(f"Connection failed to {host}:{port} - {e}")
            send_error(client_socket, 502, "Bad Gateway")
            client_socket.close()
            return

        # Forward Request to Server
        # Use HTTP/1.0 as specified in assignment
        new_request = f"GET {path} HTTP/1.0\r\nHost: {host}\r\n"
        
        # Forward relevant headers (Connection, User-Agent, etc.)
        for key, value in headers.items():
            if key.lower() not in ['host', 'connection', 'proxy-connection']:
                new_request += f"{key}: {value}\r\n"
        
        new_request += "Connection: close\r\n\r\n"
        
        remote_socket.sendall(new_request.encode())

        # Forward Response to Client
        while True:
            data = remote_socket.recv(BUFFER_SIZE)
            if not data:
                break
            client_socket.sendall(data)

    except socket.timeout:
        print("Socket timeout")
        try:
            send_error(client_socket, 504, "Gateway Timeout")
        except:
            pass
    except Exception as e:
        print(f"Error handling client: {e}")
        try:
            send_error(client_socket, 500, "Internal Server Error")
        except:
            pass
    finally:
        if remote_socket:
            remote_socket.close()
        try:
            client_socket.close()
        except:
            pass

# Main Proxy Server
def main():
    global active_children

    if len(sys.argv) != 2:
        print("Usage: python3 Ques.py <port>")
        sys.exit(1)

    try:
        port = int(sys.argv[1])
    except ValueError:
        print("Port must be a number")
        sys.exit(1)

    # Create server socket
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    
    try:
        server_socket.bind(("", port))
        server_socket.listen(100)
    except Exception as e:
        print(f"Failed to bind to port {port}: {e}")
        sys.exit(1)

    print(f"Proxy running on port {port} (PID: {os.getpid()})")
    print(f"Max processes: {MAX_PROCESSES}")

    while True:
        try:
            client_socket, addr = server_socket.accept()
            print(f"Accepted connection from {addr}")

            # Limit processes
            if active_children >= MAX_PROCESSES:
                print("Max processes reached, rejecting connection")
                client_socket.close()
                continue

            pid = os.fork()

            if pid == 0:
                # Child process
                server_socket.close()
                handle_client(client_socket)
                os._exit(0)
            elif pid > 0:
                # Parent process
                active_children += 1
                client_socket.close()
                print(f"Created child process {pid}, active children: {active_children}")
            else:
                # Fork failed
                print("Fork failed")
                client_socket.close()

            # Clean zombie processes (non-blocking)
            while True:
                try:
                    finished_pid, status = os.waitpid(-1, os.WNOHANG)
                    if finished_pid == 0:
                        break
                    active_children -= 1
                    print(f"Child process {finished_pid} finished, active children: {active_children}")
                except ChildProcessError:
                    break
                except:
                    break

        except KeyboardInterrupt:
            print("\nShutting down proxy...")
            break
        except Exception as e:
            print(f"Error in main loop: {e}")

    server_socket.close()
    print("Proxy terminated")

if __name__ == "__main__":
    main()
