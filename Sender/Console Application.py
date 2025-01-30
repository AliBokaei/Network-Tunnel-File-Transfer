from scapy.all import *
from scapy.all import IP
import threading


def read_file_lines(filename):
    with open(filename, 'r', encoding='utf-8') as file:
        return file.readlines()


def create_tunnel_packet(line, dest_ip, src_ip, sequence_number, total_packets):

    flags = "MF" if sequence_number < total_packets else 0 
    inner_ip = IP(dst=dest_ip, src=src_ip , flags =flags)
    inner_payload = f"{sequence_number}:{line.strip()}".encode('utf-8')
    inner_packet = inner_ip / Raw(load=inner_payload)
    
    outer_ip = IP(dst=dest_ip, src=src_ip, flags=flags)
    outer_packet = outer_ip / inner_packet
    
    # Packet.show(outer_packet)
    # packet.show(inner_packet)
    return outer_packet

def send_file_through_tunnel(filename, dest_ip):
    src_ip = '192.168.80.128'  
    lines = read_file_lines(filename)
    total_packets = len(lines)  
    
    for sequence_number, line in enumerate(lines, 1):
        tunnel_packet = create_tunnel_packet(line, dest_ip, src_ip, sequence_number, total_packets)
        print(f"Sent (Number {sequence_number}): {line.strip()}")
        send(tunnel_packet, verbose=False)
        

def receive_packets():
    received_packets = {}
    total_packets_received = 0
    is_last_packet_received = False

    def packet_handler(packet):
        nonlocal is_last_packet_received, total_packets_received
        if IP in packet and Raw in packet:
            try:
                payload = packet[Raw].load.decode('utf-8')
                sequence_number, text = payload.split(':', 1)
                sequence_number = int(sequence_number)
                
                if sequence_number not in received_packets:
                    received_packets[sequence_number] = text
                    total_packets_received += 1

                if packet[IP].flags.MF == 0:
                    is_last_packet_received = True

                if is_last_packet_received and total_packets_received == len(received_packets):
                    print("\nAll packets received:")
                    for seq_num in sorted(received_packets):
                        print(f"Received (number of {seq_num}): {received_packets[seq_num]}")
                    return True
            except Exception as e:
                pass
    
    sniff(prn=packet_handler, filter="ip", store=0, stop_filter=lambda x: is_last_packet_received and total_packets_received == len(received_packets))


if __name__ == "__main__":
    filename = "sample.txt"
    dest_ip = "192.168.80.130"
    sender_thread = threading.Thread(target=send_file_through_tunnel, args=(filename, dest_ip))
    sender_thread.start()
    receive_packets()
