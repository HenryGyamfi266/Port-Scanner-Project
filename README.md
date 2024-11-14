# Port-Scanner-Project

## Project Overview
In this project, I build a multithreaded port scanner with python. This scanner will:
Scan a range of ports on a target host.
Identify whether each port is open or closed.
Include multithreading to speed up the scan.

## Project Description
Explanation of Project Features
TCP and UDP Scanning:
The scan_tcp_port function uses a TCP socket to check if a port is open.
The scan_udp_port function uses a UDP socket to check if a UDP port is open, though UDP scanning is trickier due to the lack of feedback on closed ports.

### Timeout Handling:
The socket_timeout variable sets a timeout for each socket connection to prevent long waits on closed ports.
In scan_udp_port, a timeout typically indicates a closed or filtered port, as UDP doesn’t always respond like TCP.

### Firewall Avoidance:
time.sleep(random.uniform(0.1, 0.3)) introduces a small randomized delay between scans, which can help avoid detection by basic firewall rules that detect rapid scanning.

### Service Identification:
well_known_ports maps commonly used ports to their typical services, allowing the script to print and log the probable service for each open port.

### Logging:
Results are saved to a file port_scan_report.txt, logging each open port along with its protocol (TCP or UDP) and the likely associated service.

When Running the Script,you can:
Set target_host to the IP or hostname you want to scan.
Adjust start_port and end_port for the range of ports.
Run the script. It will print the results to the console and save them to port_scan_report.txt.
