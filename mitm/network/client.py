# COMP90043 Cryptography and Security
# Research Project Part A2
# Man in the Middle Client a.k.a Malicious Client "Mallory"
# 
# Reference Implementation
# 
# Authored by R. Yang
# Authorised by Prof. Udaya Parampalli
#####################################################

from mitm.network.protocol.client import ClientProtocol
from mitm.network.protocol.server import ServerProtocol

class MitMClient:
	def __init__(self):
		self.client_protocol = ClientProtocol()
		self.server_procotol = ServerProtocol()

