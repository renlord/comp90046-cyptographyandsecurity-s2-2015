# COMP90043 Cryptography and Security Server Worker Implementation
# University of Melbourne
# For use in Project 
# 
# Commissioned by Prof. Assoc. Udaya P.
# Authored by Renlord Y.
# 
# 23 Jul 2015
#
# NOTE: All verification and testing is now delegated to unit-testing

import os, sys, random, time, csv, socket

from protocol import *
from cryptoserver.crypto.custom import *
from cryptoserver.util.error import *

import cryptoserver.crypto.stream


DEBUG = False
NETWORK_DEBUG = False
COMM_DEBUG = False

LOG_TOGGLE = False

# Corpus No. of Lines:
CLIENT_CORPUS_LINES = 5776
SERVER_CORPUS_LINES = 10670
# Corpus Paths
CLIENT_CORPUS_PATH = "cryptoserver/corpus/client_corpus.txt"
SERVER_CORPUS_PATH = "cryptoserver/corpus/server_corpus.txt"
# Final Attempt Log Path
FINAL_LOG_PATH = "cryptoserver/final_logs/"
# Logs Path
LOG_PATH = "cryptoserver/logs/"

class WorkerServer:
    def __init__(self, socket, g, p):
        self.sock = socket
        # 5 Second Socket Timeout
        self.sock.settimeout(30)
        self.serverProtocol = ServerProtocol(g, p)
        # Diffie Hellman Stuff.
        self.dh_g = g
        self.dh_p = p
        self.sharedKey = None
        # Student ID
        self.student_id = None
        # Used to store what lines are coming in and what lines are going out.
        # List of Ints
        self.in_lines = []
        self.out_lines = []
        # Used to store the lines in plain text.
        # List of Strings
        self.client_lines = []
        self.server_lines = []
        self.server_corpus_path = SERVER_CORPUS_PATH
        self.client_corpus_path = CLIENT_CORPUS_PATH
        # CIPHERs
        p1 = 73 # Temporary 64bit Prime Number 
        p2 = 29 # Temporary 64bit Prime Number
        self.stream_keys = (p1, p2)
        self.stream_cipher = None

    def log_attempt(self, status="OK", err_msg=None):
        log_path = LOG_PATH + str(self.student_id) + ".log"
        if os.path.isfile(log_path) is False:
            fp = open(log_path, "w")
            header = ["timestamp", "status", "err_msg"]
            writer = csv.writer(fp)
            writer.writerow(header)
        else: 
            fp = open(log_path, "a")

        if err_msg is None and status == "OK":
            new_row = time.strftime("%c") + "," + "OK" + "," + "ALL PASSED\n" 
        else:
            new_row = time.strftime("%c") + "," + status + "," + err_msg + "\n"
        fp.write(new_row)
        fp.close()
        return True

    def random_corpus_lines(self):
        random.seed(int(time.time()) ^ self.sharedKey)
        n_in = random.randint(3, 10)
        n_out = random.randint(3, 10)
        in_lines = []
        out_lines = []
        for i in range(0, n_in):
            in_lines.append(random.randint(0, CLIENT_CORPUS_LINES))

        for i in range (0, n_out):
            out_lines.append(random.randint(0, SERVER_CORPUS_LINES))

        return (in_lines, out_lines)

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
    def strict_receive(self, reqlen, key=None):
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

    def receive(self, key=None):
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

    def contact_phase(self):
        while True:
            msg = self.receive()
            try:
                if msg["type"] == "CLIENT_HELLO":
                    self.student_id = msg["id"]
                    break
            except KeyError:
                print("KeyError: Message does not contain all required fields")
                os._exit(1) 

        print("Student {0} Connected on Process {1}".format(self.student_id, os.getpid()))
        self.send(self.serverProtocol.hello())
        self.serverProtocol.counter += 1
        return True 

    def exchange_phase(self):
        while True:
            # Expecting CLIENT_DHEX_START
            msg = self.receive()
            if msg["type"] == "CLIENT_DHEX_START":    
                break 
        # Generate own Secret Key = Xs
        self.dh_Xs = generate_private_key(self.dh_p)

        # Random decision if Client Secret Key should be generated = Xc
        if decide_provide_Xc():
            self.dh_Xc = generate_private_key(self.dh_p)
            self.send(self.serverProtocol.dhex(dh_compute_public(self.dh_g, self.dh_Xs, self.dh_p), self.dh_Xc))
        else: 
            self.dh_Xc = None
            self.send(self.serverProtocol.dhex(dh_compute_public(self.dh_g, self.dh_Xs, self.dh_p)))
        self.serverProtocol.counter += 1

        while True:
            try:
                msg = self.receive()
                if msg["type"] == "CLIENT_DHEX":
                    if self.dh_Xc is not None:
                        expected_dh_Yc = dh_compute_public(self.dh_g, self.dh_Xc, self.dh_p)
                        if int(msg["dh_Yc"]) != expected_dh_Yc:
                            raise InvalidDHComputation(expected_dh_Yc, int(msg["dh_Yc"]))
                    else:
                        self.dh_Yc = int(msg["dh_Yc"])

                    break
            except InvalidDHComputation as e:
                err_msg = e.errorMessage()
                self.log_attempt("FAIL. Exchange Phase", err_msg)
                os._exit(1) 
            except socket.timeout:
                err_msg = "CLIENT_DHEX Response Timed Out"
                self.log_attempt("FAIL. Exchange Phase", err_msg)
                os._exit(1) 

        self.sharedKey = compute_dh_key(self.dh_Yc, self.dh_Xs, self.dh_p)  

        if DEBUG is True:
            print("This Client-Server DH Shared Key is {0}".format(self.sharedKey))

        while True:
            try :
                self.send(self.serverProtocol.dhex_done())
                msg = self.receive()
                if msg["type"] == "CLIENT_DHEX_DONE":
                    if int(msg["dh_key"]) == self.sharedKey:
                        self.serverProtocol.counter += 1
                        break
                    else:
                        raise NonMatchingDHSharedKey(int(msg["dh_key"]), self.sharedKey) 
            except NonMatchingDHSharedKey as e:
                self.send(self.serverProtocol.dhex_error())
                err_msg = e.errorMessage()
                self.log_attempt("FAIL. Exhcange Phase", err_msg)
                os._exit(1)
            except socket.timeout:
                err_msg = "CLIENT_DHEX_DONE Response Timed Out"
                self.log_attempt("FAIL. Exchange Phase", err_msg)
                os._exit(1) 

        self.stream_cipher = cryptoserver.crypto.stream.CustomStream(self.sharedKey, self.dh_p, self.stream_keys[0], self.stream_keys[1])

        return True

    def specification_phase(self):
        # ALL MESSAGES AFTER THIS MUST BE ENCRYPTED AND DECRYPTED
        # Specification Random Generator
        self.in_lines, self.out_lines = self.random_corpus_lines()
        self.send(self.serverProtocol.spec(self.in_lines, self.out_lines, self.stream_keys[0], self.stream_keys[1]))
        self.serverProtocol.counter += 1

        while True:
            msg = self.receive()
            try:
                if msg["type"] == "CLIENT_SPEC_DONE":    
                    break
            except KeyError:
                print("KeyError: Message does not contain all required fields")
                os._exit(1) 
        return True

    def communication_phase(self):
        # SEND ALL OUT TEXT
        self.send_all_lines()
        self.send(self.serverProtocol.text_done())
        self.stream_cipher.reset()
        # RECEIVE ALL IN TEXT
        self.recv_all_lines()
        self.send(self.serverProtocol.comm_end())
        while True:
            msg = self.receive()
            try:
                if msg["type"] == "CLIENT_COMM_END":
                    break
            except KeyError:
                print("Message does not containt `type` field")
                os._exit(1)

        return True

    def exit(self):
        self.send(self.serverProtocol.finish())
        print("Student {0} completed attempt. Process {1} ending...".format(self.student_id, os.getpid()))
        os._exit(1)

def project_one(ws):
    ws.exchange_phase() 
    ws.exit()
    ws.log_attempt()
    return True

def project_two(ws):
    ws.exchange_phase()
    ws.specification_phase()
    ws.communication_phase()
    ws.exit()
    ws.log_attempt()
    return True

def worker(client, g, p, part=None):
    print("Client Connected... Process {0} initialised.".format(os.getpid()))
    ws = WorkerServer(client, g, p)
    ws.contact_phase()
    if part == "one":
        project_one(ws)
    else:
        project_two(ws)

    return None
