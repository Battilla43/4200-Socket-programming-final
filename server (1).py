# TO RUN SERVER: python server.py -p <PORT> -l /<NAME OF FOLDER>
# TODO: Reformat logging for handshake
# TODO: Figure out why recv(12) is not working

import struct
import socket
import argparse
import logging
import os
import sys


def create_packet(**kwargs): #We need to send packets to the server
    packet = struct.pack('!I', kwargs.get('sequence_number',0)) #pack the sequence number
    packet += struct.pack('!I', kwargs.get('ack_number', 0))  # pack the ack number
    packet += struct.pack('!I', kwargs.get('unused_bits', 0))  # pack the unused bits
    packet += struct.pack('!c', kwargs.get('ack', b'\x00'))  # pack the ACK
    packet += struct.pack('!c', kwargs.get('syn', b'\x00'))  # pack the SYN
    packet += struct.pack('!c', kwargs.get('fin', b'\x00'))  # pack the FIN
    
    payload = kwargs.get('payload', b'') #The packet is the data + payload
    logging.info(f"<SEND> {kwargs.get('sequence_number',0)} {kwargs.get('ack_number', 0)} {kwargs.get('ack', 0)} {kwargs.get('syn', 0)} {kwargs.get('fin', 0)}")
    packet += payload
    
    return packet

def handshake(conn, addr):
    syn_packet = conn
    if syn_packet:
        print("Packet received")
        syn_num, ack_num, unused_bits, ack, syn, fin, payload = un_pack(syn_packet)
        if syn == b'\x01':
            syn_ack_packet = create_packet(sequence_number=syn_num, ack_number=syn_num + 1, ack=b'\x01', syn=b'\x01')
            sequence = syn_num
            s.sendto(syn_ack_packet, addr) # Use s.sendto() instead of conn.send() to work with UDP instead of TCP
            try:
                ack_packet, addr = s.recvfrom(1024)
            except socket.error as e:
                logging.error(f"Error receiving packet: {e}")
            try:
                syn_num, ack_num, unused_bits, ack, syn, fin, payload = un_pack(ack_packet)
                if ack == b'\x01':
                    return sequence + syn_num
                else:
                    logging.error(f"Received packet with invalid ACK bit")
                    return None
            except UnboundLocalError:
                logging.error(f"Did not receive ACK packet")
                return None
        else:
            logging.error(f"Received packet with invalid SYN bit")
            return None
        

def un_pack(packet):
    syn_num = struct.unpack('!I', packet[0:4])[0]
    print("syn is ", type(syn_num))
    ack_num = struct.unpack('!I', packet[4:8])[0]
    unused_bits = struct.unpack('!I', packet[8:12])[0]
    ack = struct.unpack('!c', packet[12:13])[0]
    syn = struct.unpack('!c', packet[13:14])[0]
    fin = struct.unpack('!c', packet[14:15])[0]
    payload = packet[15:]
    
    if b',' in payload:
        duration, numBlinks = map(int, payload.decode().split(','))
        logging.info(f"RECV [{syn_num}] [{ack_num}] [{ack}] [{syn}] [{fin}] [{duration}] [{numBlinks}]")
        return duration, numBlinks
    else:
        return syn_num, ack_num, unused_bits, ack, syn, fin, payload
    
def handle_interactions(conn, addr, sequence):
    duration_packet, addr = s.recvfrom(1024)
    duration, numBlinks = un_pack(duration_packet)
    # Create an acknowledgement packet for the duration packet
    ack_packet = create_packet(sequence_number=sequence, ack_number=sequence + 1, ack=b'\x01')
    s.sendto(ack_packet, addr)
    while True:
        try:
            motion_packet = s.recv(1024)
        except socket.error as e:
            logging.error(f"Error receiving packet: {e}")
        if motion_packet.strip() == b'Motion Detected':
            logging.info(f"RECV [{motion_packet}]")
            logging.info("Motion Detected")
        else:
            logging.info("Motion Not Detected")
            
            break
            
if __name__ == '__main__':
    parser = argparse.ArgumentParser(description="Client for packet creation and sending.")
    parser.add_argument('-p', type=int, required=True, help='Server port')
    parser.add_argument('-l', type=str, required=True, help='Location of the logfile')

    port = parser.parse_args().p
    log_location = parser.parse_args().l

    if port < 1024:
        print("Invalid port: " + port)
        print("Your port number must be above 1024")
        sys.exit(1)


    os.makedirs(os.path.dirname(log_location), exist_ok=True)

    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(message)s",
        handlers=[
            logging.FileHandler(log_location),
            logging.StreamHandler()
        ]
    )


    host = "192.168.56.1" #PUT YOUR COMPUTER'S IP HERE TO TEST

    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:  # Utilize SOCK_DGRAM for UDP
        s.bind((host, port))
        print("Server listening on port " + str(port))
        try:
            conn, addr = s.recvfrom(1024) # Use s.recvfrom() instread of conn.recv() because we are using UDP instead of TCP
        except socket.error as e:
            logging.error(f"Error receiving packet: {e}")
        while conn is not None:
                print("Received connection from (IP:PORT) " + str(addr[0]) + ":" + str(addr[1]))
                with open(log_location, "a+"):
                    logging.info(f"Received connection from (IP:PORT) " + str(addr[0]) + ":" + str(addr[1]))
                sequence = handshake(conn, addr)
                if sequence is not None:
                    handle_interactions(conn, addr, sequence)
                    