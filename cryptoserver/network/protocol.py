import json

class ServerProtocol:
    def __init__(self, g, p):
        self.g = g
        self.p = p
        self.counter = 1

    def busy(self):
        msg = { "type": "SERVER_BUSY", "n": self.counter}
        return json.dumps(msg)

    def finish(self):
        msg = { "type": "SERVER_FINISH", "n": self.counter }
        return json.dumps(msg)

    def hello(self):
        msg = { "type": "SERVER_HELLO", "n": self.counter}
        return json.dumps(msg)

    def dhex(self, Ys, Xc=None):
        if Xc is None:
            msg = { "type": "SERVER_DHEX", 
                    "dh_g": str(self.g),
                    "dh_p": str(self.p),    
                    "dh_Ys": str(Ys),
                    "n": self.counter
                  }
        else:
            msg = { "type": "SERVER_DHEX", 
                    "dh_g": str(self.g),
                    "dh_p": str(self.p),
                    "dh_Ys": str(Ys),
                    "dh_Xc": str(Xc),
                    "n": self.counter
                  }
        return json.dumps(msg)

    def dhex_done(self):
        msg = { "type": "SERVER_DHEX_DONE", "n": self.counter}
        return json.dumps(msg)

    def dhex_error(self):
        msg = { "type": "SERVER_DHEX_ERROR", "err": "Client provided shared key is different to Server shared key."}
        return json.dumps(msg)

    def spec(self, in_lines, out_lines, p1, p2):
        msg = { "type": "SERVER_SPEC", 
                "in_lines": in_lines,
                "out_lines": out_lines,
                "p1": str(p1),
                "p2": str(p2),
                "n": self.counter
              }
        return json.dumps(msg)

    def text(self, line_number, body):
        msg = { "type": "SERVER_TEXT", "id": line_number, "body": body, "n": self.counter}
        return json.dumps(msg, ensure_ascii=False).decode('latin1')

    def text_recv(self, line_number):
        msg = { "type": "SERVER_TEXT_RECV", "id": line_number }
        return json.dumps(msg)

    def text_done(self):
        msg = { "type": "SERVER_TEXT_DONE" }
        return json.dumps(msg)

    def comm_end(self):
        msg = { "type": "SERVER_COMM_END", "msg": "Thank you for your submission. Attempt logged." }
        return json.dumps(msg)

    def require_message_length(self):
        msg = { "type": "SERVER_NEXT_LENGTH_REQUEST", "n": self.counter}
        return json.dumps(msg)

    def next_message_length(self, line_number, m):
        msg = { "type": "SERVER_NEXT_LENGTH", "length": len(m), "id": line_number, "n": self.counter}
        return json.dumps(msg)

    def next_message_length_received(self, line_number):
        msg = { "type": "SERVER_NEXT_LENGTH_RECV", "n": self.counter, "id": line_number}
        return json.dumps(msg)
    
    def parse(self, msg):
        try:
            return json.loads(msg)
        except UnicodeDecodeError:
            return json.loads(msg)