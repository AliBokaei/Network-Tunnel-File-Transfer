import tkinter as tk
from tkinter import filedialog, messagebox
from scapy.all import *
import threading
import os
import subprocess
import platform

class NetworkTunnelApp:
    def __init__(self, master):
        self.master = master
        master.title("Network Tunnel File Transfer")
        master.geometry("600x500")

        # Frame for file selection
        self.file_frame = tk.Frame(master)
        self.file_frame.pack(padx=10, pady=10, fill='x')

        self.file_path_var = tk.StringVar()
        self.file_path_entry = tk.Entry(self.file_frame, textvariable=self.file_path_var, width=50)
        self.file_path_entry.pack(side='left', expand=True, fill='x', padx=(0, 10))

        self.browse_button = tk.Button(self.file_frame, text="Select File", command=self.browse_file)
        self.browse_button.pack(side='right')

        # Frame for IP settings
        self.ip_frame = tk.Frame(master)
        self.ip_frame.pack(padx=10, pady=10, fill='x')

        tk.Label(self.ip_frame, text="Source IP:").pack(side='right', padx=(0, 10))
        self.src_ip_var = tk.StringVar(value='192.168.80.128')
        self.src_ip_entry = tk.Entry(self.ip_frame, textvariable=self.src_ip_var, width=15)
        self.src_ip_entry.pack(side='right', padx=(0, 10))

        tk.Label(self.ip_frame, text="Destination IP:").pack(side='right', padx=(0, 10))
        self.dest_ip_var = tk.StringVar(value='192.168.80.130')
        self.dest_ip_entry = tk.Entry(self.ip_frame, textvariable=self.dest_ip_var, width=15)
        self.dest_ip_entry.pack(side='right', padx=(0, 10))

        # Send button
        self.send_button = tk.Button(master, text="Send File", command=self.send_file, state='disabled')
        self.send_button.pack(pady=10)

        # Packet display window
        self.packet_text = tk.Text(master, height=20, width=70)
        self.packet_text.pack(padx=10, pady=10)

        # Packet reception control variables
        self.received_packets = {}
        self.total_packets_received = 0
        self.is_last_packet_received = False
        
        # Threading lock for thread-safe operations
        self.packet_lock = threading.Lock()

    def is_host_reachable(self, host):
        """Check if host is reachable using ping"""
        try:
            # Determine the ping command based on the operating system
            param = '-n' if platform.system().lower() == 'windows' else '-c'
            
            # Run ping command with 2 packets and 2 seconds timeout
            command = ['ping', param, '2', '-W', '2', host]
            
            # Suppress output
            with open(os.devnull, 'w') as devnull:
                result = subprocess.run(command, stdout=devnull, stderr=devnull)
            
            return result.returncode == 0
        except Exception as e:
            print(f"Error checking host: {e}")
            return False

    def browse_file(self):
        filename = filedialog.askopenfilename(title="Select File")
        if filename:
            self.file_path_var.set(filename)
            self.send_button['state'] = 'normal'
            self.packet_text.delete('1.0', tk.END)

    def create_tunnel_packet(self, line, dest_ip, src_ip, sequence_number, total_packets):
        
        flags = "MF" if sequence_number < total_packets else 0  # "More Fragments" 
        inner_ip = IP(dst=dest_ip, src=src_ip , flags =flags)
        inner_payload = f"{sequence_number}:{line.strip()}".encode('utf-8')
        inner_packet = inner_ip / Raw(load=inner_payload)
    
        
        outer_ip = IP(dst=dest_ip, src=src_ip, flags=flags)
        outer_packet = outer_ip / inner_packet
    
        
        return outer_packet

    def send_file_through_tunnel(self, filename, dest_ip, src_ip):
        try:
            # First, check if destination is reachable
            if not self.is_host_reachable(dest_ip):
                messagebox.showerror("Connection Error", 
                    f"Destination IP {dest_ip} is not reachable. Please check the network connection.")
                return

            with open(filename, 'r', encoding='utf-8') as file:
                lines = file.readlines()
            
            total_packets = len(lines)
            
            for sequence_number, line in enumerate(lines, 1):
                tunnel_packet = self.create_tunnel_packet(line, dest_ip, src_ip, sequence_number, total_packets)
                
                # Thread-safe text update
                with self.packet_lock:
                    self.packet_text.insert(tk.END, f"Sent (Sequence {sequence_number}): {line.strip()}\n")
                    self.packet_text.see(tk.END)
                
                try:
                    send(tunnel_packet, verbose=False)  # Removed timeout argument
                except Exception as send_error:
                    # Thread-safe error logging
                    with self.packet_lock:
                        self.packet_text.insert(tk.END, f"Send Error (Sequence {sequence_number}): {send_error}\n")
                        self.packet_text.see(tk.END)
                    
        except IOError as file_error:
            messagebox.showerror("File Error", str(file_error))
        except Exception as e:
            messagebox.showerror("Unexpected Error", str(e))

    def send_file(self):
        filename = self.file_path_var.get()
        dest_ip = self.dest_ip_var.get()
        src_ip = self.src_ip_var.get()

        if not filename or not dest_ip or not src_ip:
            messagebox.showwarning("Warning", "Please fill in all fields")
            return

        # Validate IP format (basic check)
        if not self.validate_ip(dest_ip) or not self.validate_ip(src_ip):
            messagebox.showerror("IP Error", "Invalid IP address format")
            return

        # Reset reception variables
        with self.packet_lock:
            self.received_packets.clear()
            self.total_packets_received = 0
            self.is_last_packet_received = False

        # Start sending in a separate thread
        sender_thread = threading.Thread(target=self.send_file_through_tunnel, 
                                         args=(filename, dest_ip, src_ip))
        sender_thread.start()

        # Start receiving in another thread
        receiver_thread = threading.Thread(target=self.receive_packets)
        receiver_thread.start()

    def validate_ip(self, ip):
        """Basic IP address validation"""
        try:
            parts = ip.split('.')
            return len(parts) == 4 and all(0 <= int(part) < 256 for part in parts)
        except:
            return False

    def receive_packets(self):
        def packet_handler(packet):
            if IP in packet and Raw in packet:
                try:
                    # Attempt UTF-8 decoding with error handling
                    try:
                        payload = packet[Raw].load.decode('utf-8', errors='ignore')
                    except Exception:
                        # Fallback to latin-1 if UTF-8 fails
                        payload = packet[Raw].load.decode('latin-1', errors='ignore')
                    
                    sequence_number, text = payload.split(':', 1)
                    sequence_number = int(sequence_number)
                    
                    # Thread-safe packet reception
                    with self.packet_lock:
                        if sequence_number not in self.received_packets:
                            self.received_packets[sequence_number] = text
                            self.total_packets_received += 1
                            self.packet_text.insert(tk.END, f"Received (Sequence {sequence_number}): {text}\n")
                            self.packet_text.see(tk.END)

                        # Check "More Fragments" bit
                        if packet[IP].flags.MF == 0:
                            self.is_last_packet_received = True

                        # If all packets are received
                        if (self.is_last_packet_received and 
                            self.total_packets_received == len(self.received_packets)):
                            self.show_final_result()
                            return True

                except Exception as e:
                    # Thread-safe error logging
                    print("")
                    # with self.packet_lock:
                    #     self.packet_text.insert(tk.END, f"Receive Error: {e}\n")
                    #     self.packet_text.see(tk.END)

        try:
            # Sniff packets with a timeout
            sniff(prn=packet_handler, filter="ip", store=0, timeout=10,
                  stop_filter=lambda x: (self.is_last_packet_received and 
                                         self.total_packets_received == len(self.received_packets)))
        except Exception as sniff_error:
            print("")
            # messagebox.showerror("Sniffing Error", str(sniff_error))

    def show_final_result(self):
        def show_result():
            result = "\nAll packets received:\n"
            for seq_num in sorted(self.received_packets):
                result += f"Received (Sequence {seq_num}): {self.received_packets[seq_num]}\n"
            messagebox.showinfo("Transfer Complete", result)

        self.master.after(0, show_result)

def main():
    root = tk.Tk()
    app = NetworkTunnelApp(root)
    root.mainloop()

if __name__ == "__main__":
    main()