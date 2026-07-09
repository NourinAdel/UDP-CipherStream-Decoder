import socket
import json
import os
import time

class udp:
    def __init__(self, ip, port):
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.socket.bind((ip, port))
        self.socket.settimeout(3)

        self.seq = 0
        self.expected_seq = 0

    # Send raw packet
    def send_packet(self, packet, addr):
        data = json.dumps(packet).encode()
        self.socket.sendto(data, addr)

    # Receive raw comments
    def receive_packet(self):
        try:
            data, addr = self.socket.recvfrom(4096)
            return json.loads(data.decode()), addr

        except ConnectionResetError:
            print("Connection reset error\n")
            return None, None

    # Calculate checksum to detect corruption
    def checksum(self, packet):
        temp = packet.copy()
        temp["checksum"] = 0
        return sum(bytearray(json.dumps(temp, sort_keys=True).encode()))

    # Check if packet is valid
    def valid(self, packet):
        return (
                isinstance(packet, dict)
                and "checksum" in packet
                and self.checksum(packet) == packet["checksum"]
        )

    def handshake_client(self, addr):
        print("Sending SYN\n")

        syn = {"flag": "SYN", "seq": self.seq}
        syn["checksum"] = self.checksum(syn)

        while True:
            self.send_packet(syn, addr)  # Send SYN

            try:
                pkt, _ = self.receive_packet()  # Receive SYNACK
                if not self.valid(pkt):
                    continue

                if pkt["flag"] == "SYNACK":
                    print("Received SYNACK\n")

                    ack = {"flag": "ACK", "seq": self.seq}
                    ack["checksum"] = self.checksum(ack)

                    self.send_packet(ack, addr)  # Send ACK
                    print("Handshake completed (Client)\n")
                    return

            except socket.timeout:
                print("Handshake timeout, retrying SYN\n")

    def handshake_server(self):
        while True:
            try:
                pkt, addr = self.receive_packet()  # Receive SYN

                if not self.valid(pkt):
                    continue

                if pkt["flag"] == "SYN":
                    print("Received SYN\n")

                    print("Sending SYNACK\n")
                    synack = {"flag": "SYNACK", "seq": self.seq}
                    synack["checksum"] = self.checksum(synack)

                    while True:
                        self.send_packet(synack, addr)  # Sending SYNACK

                        try:
                            ack, _ = self.receive_packet()  # Receive ACK

                            if not self.valid(ack):
                                continue

                            if ack["flag"] == "ACK":
                                print("Handshake completed (Server)\n")
                                return addr

                        except socket.timeout:
                            continue

            except socket.timeout:
                continue

    def send_data(self, data, addr):

        while True:
            packet = {
                "flag": "DATA",
                "seq": self.seq,
                "data": data,
            }

            packet["checksum"] = self.checksum(packet)
            print(f"Sending packet with seq={self.seq}")
            self.send_packet(packet, addr)

            try:
                print("Waiting for ACK")
                ack, _ = self.receive_packet()

                if not self.valid(ack):
                    print("\nInvalid ACK received")
                    continue

                if ack["flag"] == "ACK" and ack["ack"] == self.seq:
                    print(f"\nValid ACK received for seq={self.seq}")
                    self.seq += 1  # if valid, increase sequence number
                    return True
                else:
                    print(f"Wrong ACK: expected {self.seq}, but got {ack.get('ack')}")  # Keep sequence number

            except socket.timeout:
                print("TIMEOUT, Retransmitting\n")
                continue

    def receive_data(self):
        while True:
            try:
                pkt, addr = self.receive_packet()

                if not self.valid(pkt):
                    continue

                if pkt["flag"] == "FIN":  # Closing connection

                    ack = {
                        "flag": "ACK",
                        "ack": pkt["seq"],
                        "seq": 0,
                    }
                    ack["checksum"] = self.checksum(ack)
                    self.send_packet(ack, addr)
                    return "FIN", addr

                if pkt["flag"] != "DATA":
                    continue

                ack = {
                    "flag": "ACK",
                    "ack": pkt["seq"],
                    "seq": 0,
                }
                ack["checksum"] = self.checksum(ack)
                self.send_packet(ack, addr)

                if pkt["seq"] == self.expected_seq:
                    self.expected_seq += 1
                    return pkt["data"], addr
                else:
                    print("DUPLICATE, ignored")

            except socket.timeout:
                continue

    def close(self, addr):  # Closing connection
        fin = {"flag": "FIN", "seq": self.seq}
        fin["checksum"] = self.checksum(fin)

        while True:
            self.send_packet(fin, addr)

            try:
                pkt, _ = self.receive_packet()

                if self.valid(pkt) and pkt["flag"] == "ACK":
                    break

            except socket.timeout:
                continue

        self.socket.close()
        print("UDP connection closed.\n")


def start_server():
    sentences = [
        "Firewall rules updated successfully",
        "Admin password is set to default",
        "Database backup completed",
        "Intrusion detected on port eighty",
        "Security token expires in one hour",
        "Deploying patch to production server",
        "Unauthorized access to root folder",
        "Network traffic monitored by admin"
    ]

    max_len = max(len(s) for s in sentences)
    padded_sentences = [s.ljust(max_len, ' ') for s in sentences]

    key = os.urandom(max_len)
    print(f"Generated Random Key: {key.hex()}\n")

    # Encrypt all sentences with the same key
    hex_ciphertexts = []
    for s in padded_sentences:
        s_bytes = s.encode('utf-8')
        # XOR corresponding bytes to encrypt
        encrypted = bytes(b ^ k for b, k in zip(s_bytes, key))
        hex_ciphertexts.append(encrypted.hex().upper())

    # Initialise server
    server = udp('127.0.0.1', 5000)
    target_address = ('127.0.0.1', 5001)

    print("UDP Server on 127.0.0.1:5000")
    print("Broadcasting encrypted data to port 5001.\n")

    try:
        while True:
            for index, cipher in enumerate(hex_ciphertexts):
                # Create a packet
                packet = {
                    "flag": "DATA",
                    "sentence_id": index, # To keep track of which sentence this is
                    "data": cipher
                }

                # Add the checksum
                packet["checksum"] = server.checksum(packet)

                server.send_packet(packet, target_address)
                print(f"Sent Packet {index}: {cipher[:20]}")

                time.sleep(2)  # Wait 2 seconds before sending the next packet
    except KeyboardInterrupt:
        print("\nShutting down server.")
        server.socket.close()


if __name__ == "__main__":
    start_server()