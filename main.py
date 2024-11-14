import socket
import threading
import time
import random
from queue import Queue

# Here is the Target host and port range
target_host = 'localhost'
start_port = 1
end_port = 1024

# Queue used for storing ports to be scanned
port_queue = Queue()

# List to store results of open ports
open_ports = []

# Dictionary of well-known ports and services for easy identification
well_known_ports = {
    20: 'FTP Data', 21: 'FTP Control', 22: 'SSH', 23: 'Telnet', 25: 'SMTP',
    53: 'DNS', 80: 'HTTP', 110: 'POP3', 143: 'IMAP', 443: 'HTTPS',
    3306: 'MySQL', 3389: 'RDP', 5432: 'PostgreSQL', 6379: 'Redis', 8080: 'HTTP-Proxy'
}

# Setting a timeout in seconds for each socket connection attempt
socket_timeout = 1


# Function to perform TCP scanning on a port
def scan_tcp_port(port):
    """
    Scans a specific port using the TCP protocol.
    If the connection is successful, the port is open.
    """
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(socket_timeout)
        result = sock.connect_ex((target_host, port))
        if result == 0:
            service = well_known_ports.get(port, 'Unknown Service')
            print(f"TCP Port {port} is open - Service: {service}")
            open_ports.append((port, 'TCP', service))
        sock.close()
    except Exception as e:
        print(f"Error scanning TCP port {port}: {e}")


# Function to perform UDP scanning on a port
def scan_udp_port(port):
    """
    Scans a specific port using the UDP protocol.
    Sends a small packet to check if the port is open or closed.
    """
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(socket_timeout)
        sock.sendto(b'', (target_host, port))  # Sending empty packet
        response, _ = sock.recvfrom(1024)
        service = well_known_ports.get(port, 'Unknown Service')
        print(f"UDP Port {port} is open - Service: {service}")
        open_ports.append((port, 'UDP', service))
    except socket.timeout:
        pass  # Timeout implies no response; UDP port likely closed or filtered
    except Exception as e:
        print(f"Error scanning UDP port {port}: {e}")
    finally:
        sock.close()


# Worker function to pull ports from the queue and scan them
def worker():
    """
    Worker function for threading. Pulls ports from the queue and scans each for both TCP and UDP.
    Adds random sleep to avoid simple firewall detection.
    """
    while not port_queue.empty():
        port = port_queue.get()

        # Random delay to avoid firewall detection
        time.sleep(random.uniform(0.1, 0.3))

        # Scan both TCP and UDP for the given port
        scan_tcp_port(port)
        scan_udp_port(port)

        port_queue.task_done()


# Main function to initialize the port scanner
def port_scanner():
    """
    Main function to set up and start the port scanner.
    Uses multithreading for faster scanning.
    """
    # Populate the queue with ports to scan
    for port in range(start_port, end_port + 1):
        port_queue.put(port)

    # Number of threads for concurrent scanning
    num_threads = 100
    threads = []

    # Here, I create and start threads
    for _ in range(num_threads):
        thread = threading.Thread(target=worker)
        threads.append(thread)
        thread.start()

    # Wait for all tasks in the queue to be completed
    port_queue.join()

    # Waiting for all threads to finish
    for thread in threads:
        thread.join()

    # Logging results to a report file
    with open("port_scan_report.txt", "w") as report:
        report.write(f"Scan Report for {target_host}\n")
        report.write(f"Scanned Ports: {start_port}-{end_port}\n\n")
        for port, protocol, service in open_ports:
            report.write(f"Port {port} ({protocol}) - Open - Service: {service}\n")

    print("Scanning completed. Report saved as port_scan_report.txt")


# Run the port scanner
if __name__ == "__main__":
    print(f"Starting scan on host: {target_host} from port {start_port} to {end_port}")
    port_scanner()
