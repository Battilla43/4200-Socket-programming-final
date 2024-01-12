# TO RUN CLIENT: python client.py -s <IP> -p <PORT> -l <NAME OF LOG FILE>
import time
import socket
import struct
import argparse
import logging
import RPi.GPIO as GPIO
import time


def create_packet(**kwargs): #We need to send packets to the server
        
    packet = struct.pack('!I', kwargs.get('sequence_number',0)) #pack the sequence number
    packet += struct.pack('!I', kwargs.get('ack_number', 0))  # pack the ack number
    packet += struct.pack('!I', 0) #pack the unused field
    packet += struct.pack('!c', kwargs.get('ack', b'\x00'))  # pack the ACK
    packet += struct.pack('!c', kwargs.get('syn', b'\x00'))  # pack the SYN
    packet += struct.pack('!c', kwargs.get('fin', b'\x00'))  # pack the FIN
    
    payload = kwargs.get('payload', b'') #The packet is the data + payload
    logging.info(f"<SEND> {kwargs.get('sequence_number',0)} {kwargs.get('ack_number', 0)} {kwargs.get('ack', 0)} {kwargs.get('syn', 0)} {kwargs.get('fin', 0)}")
    packet += payload
    
    return packet

def handshake(conn): # Create a function to handle all of the handshakes
    # First, send a SYN
    SYNPacket = create_packet(sequence_number = 234, syn=b'\x01')
    conn.send(SYNPacket)
    SynAck = conn.recv(1024) 
    syn_num, ack_num, unused_bits, ack, syn, fin, payload = un_Pack(SynAck)
    if syn == b'\x01' and ack == b'\x01':
        AckPacket = create_packet(ack_number = syn_num + 1, ack=b'\x01')
        conn.send(AckPacket)
        return syn_num + 1
    else:
        logging.error(f"Received packet with invalid SYN or ACK bit")
        return None

def un_Pack(packet): # Create a function to unpack the packets
    syn_num = struct.unpack('!I', packet[0:4])[0]
    ack_num = struct.unpack('!I', packet[4:8])[0]
    unused_bits = struct.unpack('!I', packet[8:12])[0]
    ack = struct.unpack('!c', packet[12:13])[0]
    syn = struct.unpack('!c', packet[13:14])[0]
    fin = struct.unpack('!c', packet[14:15])[0]
    logging.info(f"RECV [{syn_num}] [{ack_num}] [{ack}] [{syn}] [{fin}]")
    payload = packet[15:]
    return syn_num, ack_num, unused_bits, ack, syn, fin, payload

def send_duration_packet(conn, duration, numBlinks):
    duration_packet = create_packet(payload = f"{duration},{numBlinks}".encode())
    conn.send(duration_packet)
    logging.info(f"Sent duration packet with duration {duration} and numBlinks {numBlinks}")
    
    try:
        ack_packet = conn.recv(1024)
    except socket.error as e:
        logging.error(f"Error receiving packet: {e}")
        return False
    ack = un_Pack(ack_packet)
    if ack[3] == b'\x01':
        logging.info(f"Received ACK for duration packet")
        print("Now attempting to receive motion packet...")
        return True
    else:
        logging.error(f"Did not receive ACK for duration packet")
        return False
        
def send_motion_packet(conn, motion):
    motion_packet = create_packet(payload = motion.encode())
    conn.send(motion_packet)
    logging.info(f"Sent motion packet with motion {motion}")
    
    try:
        ack_packet = conn.recv(1024)
    except socket.error as e:
        logging.error(f"Error receiving packet: {e}")
    ack = un_Pack(ack_packet)
    if ack[3] == b'\x01':
        logging.info(f"Received ACK for motion packet")
    else:
        logging.error(f"Did not receive ACK for motion packet")


if __name__ == '__main__':   
    parser = argparse.ArgumentParser(description="Client for packet creation and sending.")
    parser.add_argument('-s', type=str, required=True, help='Server ip')
    parser.add_argument('-p', type=int, required=True, help='Server port')
    parser.add_argument('-l', type=str, required=True, help='Location of the logfile')

    args = parser.parse_args()
    server_ip = args.s
    port = args.p
    log_location = args.l
    
    logging.basicConfig(
            level=logging.INFO,
            format="%(asctime)s [%(levelname)s] %(message)s",
            handlers=[
                logging.FileHandler(log_location),
                logging.StreamHandler()
            ]
        )

host = "192.168.56.1" #PUT YOUR COMPUTER'S IP HERE TO TEST

with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s: # Utilize SOCK_DGRAM for UDP

    s.connect((server_ip, port))
    with open(log_location, "a+"):
        logging.info(f"Received connection from (IP:PORT) " + str(server_ip) + ":" + str(port))
        # Initiate the 3-way handshake:
        # Send SYN
        sequence = handshake(s) # This is where the handshake ends. The sequence number is established
        if sequence is not None:
            duration = 5
            numBlinks = 10
            if send_duration_packet(s, duration, numBlinks) == True:
                while True:
                    
                    GPIO.setmode(GPIO.BOARD) #Set GPIO to bread board
                    pir = 8 #Assign pin 8 to PIR
                    led = 10 #Assign pin 10 to LED
                    GPIO.setup(pir, GPIO.IN) #PIR as input
                    GPIO.setup(led, GPIO.OUT) #LED as output
                    time.sleep(2) #Give sensor time to startup
                    print ("Active")
                    try:
                        while True:
                            count = 0
                            if GPIO.input(pir) == True: #If PIR pin goes high, motion is detected
                                logging.info("Motion Detected!")
                                send_motion_packet(s, "Motion Detected")
                                GPIO.output(led, True) #Turn on LED
                                time.sleep(4) #Keep LED on for 4 seconds
                                GPIO.output(led, False) #Turn off LED
                                time.sleep(1)
                                count = count + 1
                                if count == numBlinks:
                                    break
                    except KeyboardInterrupt:
                             GPIO.output(led, False) #Turn off LED
                             GPIO.cleanup() #reset
                             print ("Program ended")
                        