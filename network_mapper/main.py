import ipaddress
import subprocess
import sys
import socket
import os


import tkinter as tk
from concurrent.futures import ThreadPoolExecutor
import threading

THREAD_POOL_SIZE = 100


class NetworkScannerGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("Network Scanner")
        self.root.geometry("600x600")

        self.create_widgets()

    def create_widgets(self):
        # IP Address Entry
        self.ip_label = tk.Label(self.root, text="IP Address with subnet mask (e.g. 10.10.10.10/24)")
        self.ip_label.pack()

        self.ip_entry = tk.Entry(self.root)
        self.ip_entry.pack()

        # Scan Button
        self.scan_button = tk.Button(self.root, text="Scan", command=self.start_scan)
        self.scan_button.pack()

        # Scan Results
        self.results_text = tk.Text(self.root, height=32, width=72)
        self.results_text.pack()

    def ping_host(self, target_host):
        try:
            # Use the appropriate 'ping' command based on the operating system
            if sys.platform.startswith('win'):
                # Windows platform
                result = subprocess.run(['ping', '-n', '1', '-w', '1000', target_host], capture_output=True)
            else:
                # Unix-like platform
                result = subprocess.run(['ping', '-c', '1', '-W', '1', target_host], capture_output=True)

            if result.returncode == 0:
                return target_host  # Host is up

        except subprocess.CalledProcessError:
            pass  # Ignore the exception and treat host as down

    def scan_network(self):
        self.results_text.delete('1.0', tk.END)

        network = self.ip_entry.get()
        try:
            network = ipaddress.IPv4Network(network)
        except ipaddress.AddressValueError:
            self.results_text.insert(tk.END, "Invalid IP Address")
            return

        live_hosts = []  # List to store live hosts

        with ThreadPoolExecutor(max_workers=THREAD_POOL_SIZE) as executor:
            host_pings = [executor.submit(self.ping_host, str(host)) for host in network.hosts()]

            for ping in host_pings:
                result = ping.result()
                if result:
                    live_hosts.append(result)  # Add live host to the list

        self.results_text.insert(tk.END, "Scanning started...\n")

        if live_hosts:
            self.results_text.insert(tk.END, "Live Hosts:\n")
            self.results_text.insert(tk.END, "\n".join(live_hosts))

            self.write_to_file("live_hosts.txt", live_hosts)  # Write live hosts to file

            self.scan_ports(live_hosts)  # Start port scanning for live hosts
        else:
            self.results_text.insert(tk.END, "No live hosts found.\n")

        self.results_text.insert(tk.END, "Scanning completed.\n")

    def scan_ports(self, hosts):
        top_ports = range(1, 1001)  # Adjust the range of ports to scan as needed

        for host in hosts:
            self.results_text.insert(tk.END, f"Scanning ports for host: {host}\n")
            open_ports = []
            with ThreadPoolExecutor() as executor:
                port_scans = [executor.submit(self.scan_port, host, port) for port in top_ports]
                for scan in port_scans:
                    result = scan.result()
                    if result:
                        open_ports.append(result)

            if open_ports:
                self.results_text.insert(tk.END, f"Open Ports for host {host}:\n")
                self.results_text.insert(tk.END, "\n".join(open_ports))

                filename = f"scan_results/{host}.txt"
                self.write_to_file(filename, open_ports)
                self.results_text.insert(tk.END, f"Scan results saved to {filename}\n")
            else:
                self.results_text.insert(tk.END, f"No open ports found for host: {host}\n")

    def scan_port(self, host, port):
        try:
            # Create a socket object
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1)

            # Attempt to connect to the target host and port
            result = sock.connect_ex((host, port))

            if result == 0:
                # Port is open
                service = socket.getservbyport(port)
                return f"Port {port}/tcp is open ({service})"

            sock.close()

        except socket.error:
            pass  # Ignore errors

    def write_to_file(self, filename, data):
        os.makedirs("scan_results", exist_ok=True)

        with open(filename, "w") as file:
            file.write("\n".join(data))

    def start_scan(self):
        threading.Thread(target=self.scan_network).start()


if __name__ == "__main__":
    root = tk.Tk()
    app = NetworkScannerGUI(root)
    root.mainloop()
