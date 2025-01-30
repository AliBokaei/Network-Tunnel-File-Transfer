from scapy.all import *
import threading
import tkinter as tk
from tkinter import scrolledtext

# IP
DEST_IP = '192.168.80.130'  # IP System 2
SRC_IP = '192.168.80.128'  # IP System 1

def receive_tunneled_packets(log_widget):
    "Receiving tunneled packets and processing them"

    def packet_callback(packet):
        if IP in packet and packet[IP].dst == DEST_IP:
            inner_packet = packet.payload

        
            if Raw in inner_packet:
                raw_data = inner_packet[Raw].load  
                try:
                    
                    payload_data = raw_data.decode('utf-8')
                except UnicodeDecodeError:
                   
                    payload_data = raw_data.hex()
            else:
                payload_data = "<No Raw Payload>"

            
            log_widget.insert(tk.END, f"Received Packet:\n{inner_packet}\n")
            log_widget.insert(tk.END, f"Payload Content:\n{payload_data}\n{'-'*50}\n")
            log_widget.see(tk.END)

            
            send(inner_packet, verbose=False)

    
    sniff(
    prn=packet_callback,
    filter=f"ip and dst host {DEST_IP} and src host 192.168.80.128",
    store=0
    )

def start_sniffing(log_widget):
   
    sniff_thread = threading.Thread(target=receive_tunneled_packets, args=(log_widget,))
    sniff_thread.daemon = True
    sniff_thread.start()

def clear_logs(log_widget):
    
    log_widget.delete('1.0', tk.END)

def main():
   
    root = tk.Tk()
    root.title("Packet Sniffer")

  
    log_widget = scrolledtext.ScrolledText(root, width=80, height=20, wrap=tk.WORD)
    log_widget.pack(padx=10, pady=10)

   
    start_button = tk.Button(root, text="Start Sniffing", command=lambda: start_sniffing(log_widget))
    start_button.pack(pady=5)

    clear_button = tk.Button(root, text="Clear Logs", command=lambda: clear_logs(log_widget))
    clear_button.pack(pady=5)

    root.mainloop()

if __name__ == "__main__":
    main()

