import argparse
import masscan
import socket
import threading
from queue import Queue

print_lock = threading.Lock()

def check_vnc_authentication_disabled(host, port):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.connect((host, port))

        version = sock.recv(12).decode('ascii')
        if "RFB" not in version:
            return False
        
        sock.sendall(version.encode('ascii'))

        num_security_types = ord(sock.recv(1))
        security_types = sock.recv(num_security_types)

        if 1 in security_types:
            return True
        else:
            return False
    except Exception as e:
        return False
    finally:
        sock.close()

def worker(queue):
    while not queue.empty():
        host, port = queue.get()
        if check_vnc_authentication_disabled(host, port):
            with print_lock:
                print(f"Authentication disabled on VNC server at {host}:{port}")
        queue.task_done()

def scan_vnc_servers(iprange, ports):
    try:
        mas = masscan.PortScanner()
        mas.scan(iprange, ports=ports, arguments='--max-rate 100000')
        scan_results = mas.scan_result["scan"]
        queue = Queue()

        for ip, result in scan_results.items():
            for port in result['tcp']:
                queue.put((ip, port))

        for _ in range(min(1000, queue.qsize())):
            thread = threading.Thread(target=worker, args=(queue,))
            thread.start()

        queue.join()
    except Exception as e:
        with print_lock:
            print(f"Error scanning for VNC servers: {e}")

def main():
    parser = argparse.ArgumentParser(description="Scan for VNC servers with authentication disabled.")
    parser.add_argument("iprange", help="IP address or CIDR range to scan")
    parser.add_argument("--ports", default="5900,5901", help="Comma separated list of ports to scan (default: 5900,5901)")

    args = parser.parse_args()

    scan_vnc_servers(args.iprange, args.ports)

if __name__ == "__main__":
    main()
