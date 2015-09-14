# COMP90043 Cryptography and Security
# Research Project Part A2
# Man in the Middle Client a.k.a Malicious Client "Mallory"
# 
# Reference Implementation
# 
# Authored by R. Yang
# Authorised by Prof. Udaya Parampalli
# 
# Instructions:
# You may alter any code for the entire package as you please. 
# However, you must follow the protocol as prescribed in the 
# specificaitons released. 
#####################################################

from mitmref.network.protocol.client import ClientProtocol
from mitmref.network.protocol.server import ServerProtocol

import socket

NETWORK_DEBUG = False
COMM_DEBUG = False

class MitMClient:
	def __init__(self, dest_host, dest_port, listen_port):
		self.client_protocol = ClientProtocol()
		self.server_procotol = ServerProtocol()
		
		# Socket Networking
		self.inSock = socket.socket()
		self.inSock.bind(('', listen_port))
		self.inSock.listen(1)

		self.outSock = socket.socket()
		self.outSock.connect((dest_host, dest_port))		

	# ===== NETWORKING CODE FOR YOUR CONVENIENCE =====
	# CHANGE/ALTERATION PERMITTED

	# A Better send function for sockets with error handling
    def send(self, msg):
        totalsent = 0
        while totalsent < len(msg):
            sent = self.sock.send(msg[totalsent:])
            if sent == 0:
                raise RuntimeError("Socket Connection Broken")
            totalsent = totalsent + sent

        if NETWORK_DEBUG is True:
            print "SENT: " + msg

    # A Better Socket Receiver with Error Handling
    def strict_receive(self, reqlen):
        bytestr = b''
        bytes_recd = 0
        while bytes_recd < reqlen:
            chunk = self.sock.recv(min(reqlen - bytes_recd, 4096))
            if chunk == b'':
                raise RuntimeError("Socket connection broken")
            bytestr += chunk
            bytes_recd = bytes_recd + len(chunk)
        result = self.serverProtocol.parse(bytestr)

        if NETWORK_DEBUG is True:
            print "RECEIVED: " + str(result)
        return result

    def receive(self):
        msg = self.sock.recv(4096)
        if key is not None:
            msg = decrypt(msg, key)
        msg = self.serverProtocol.parse(msg)

        if NETWORK_DEBUG is True:
            print "RECEIVED: " + str(msg)
        return msg

    def encrypt(self, msg):
        return self.stream_cipher.encrypt(msg)

    def decrypt(self, msg):
        return self.stream_cipher.decrypt(msg)

    def send_line(self, line_number, text):
        # Send TEXT Message Length
        cipher_text = self.encrypt(text)
        text_msg = self.serverProtocol.text(line_number, cipher_text)
        len_msg = self.serverProtocol.next_message_length(line_number, text_msg)
        self.send(len_msg)

        # Length Acknowledgement
        while True:
            msg = self.receive()
            if msg["type"] == "CLIENT_NEXT_LENGTH_RECV" and msg["id"] == line_number:
                break
            else:
                self.send(len_msg)

        # Send TEXT Message
        if COMM_DEBUG is True:
            print "SERVER_TEXT >>>>>>>>>>>>>> ID: " + str(line_number)
            print "Plain Text: \n" + text
            print "Cipher Text: \n" + cipher_text
        self.send(text_msg)

        # Wait Acknowledgement of CLIENT_TEXT_RECV
        while True:
            msg = self.receive()
            if msg["type"] == "CLIENT_TEXT_RECV" and msg["id"] == line_number:
                break
            else:
                self.encrypt_send(msg)

        return True

    def picklines(self, whatlines):
        fp = open(self.server_corpus_path)
        results = [(i, x) for i, x in enumerate(fp) if i in whatlines]
        fp.close()
        return results

    def send_all_lines(self):
        for item in self.picklines(self.out_lines):
            self.send_line(item[0], item[1])
        return True

    def recv_line(self):
        # Get TEXT Message Length
        while True:
            msg = self.receive()
            if msg["type"] == "CLIENT_NEXT_LENGTH":
                message_length = msg["length"]
                line_number = msg["id"]
                break
            elif msg["type"] == "CLIENT_TEXT_DONE":
                return True
            else:
                self.send(self.serverProtocol.require_message_length(line_number))

        # Send Acknowledgement of Message Length
        self.send(self.serverProtocol.next_message_length_received(line_number))

        # Get complete TEXT Message.
        msg = self.strict_receive(message_length)
        decrypted_body = self.decrypt(msg["body"])

        if COMM_DEBUG is True:
            print "CLIENT_TEXT <<<<<<<<<<<< ID: " + str(msg["id"])
            print "Cipher Text: \n" + msg["body"]
            print "Plain Text: \n" + decrypted_body

        self.client_lines.append(decrypted_body)

        # Inform Client TEXT Message Received
        self.send(self.serverProtocol.text_recv(msg["id"]))

        return False

    def recv_all_lines(self):
        haveWeReceivedAllLines = False
        while not haveWeReceivedAllLines:
            if self.recv_line():
                break
        return True

    # ===== END NETWORKING CODE =====

	# ===== STUDENT IMPLEMENTATION GOES HERE =====

	def contact_phase(self):

		pass

	def dhex_phase(self):
		pass

	def specification_phase(self):
		pass

	def communication_phase(self):
		pass

	def exit_phase(self):
		pass

	# ===== STUDENT IMPLEMENTATION ENDS HERE =====

def main(sid, host, port):
	mitm = MitMClient()

