import socketserver
import struct
import io
import atexit
import os
import secrets

import dhparams as dh
import rsa
import sha

class SSHHandler(socketserver.StreamRequestHandler):
	ID_STR = b"SSH-2.0-DavidSSH_0.0.1"

	SSH_MSG_DISCONNECT				= 0x01
	SSH_MSG_IGNORE						= 0x02
	SSH_MSG_UNIMPLEMENTED			= 0x03
	SSH_MSG_DEBUG							= 0x04
	SSH_MSG_SERVICE_REQUEST		= 0x05
	SSH_MSG_SERVICE_ACCEPT		= 0x06
	SSH_MSG_KEXINIT						= 0x14
	SSH_MSG_NEWKEYS						= 0x15
	SSH_MSG_KEXDH_INIT				= 0x1E
	SSH_MSG_KEXDH_REPLY				= 0x1F

	mac_enabled = False
	cipher_block_size = False # False used because coercion to int is desired, and I'm lazy.
	kex_started = False
	shared_secret = None
	
	kexinfo_keys = [
		"kex_algorithms",
		"server_host_key_algorithms",
		"encryption_algorithms_client_to_server",
		"encryption_algorithms_server_to_client",
		"mac_algorithms_client_to_server",
		"mac_algorithms_server_to_client",
		"compression_algorithms_client_to_server",
		"compression_algorithms_server_to_client",
		"languages_client_to_server",
		"languages_server_to_client",
	]
	
	client_kexinfo = {}
	
	server_kexinfo = {
		"kex_algorithms": ["diffie-hellman-group14-sha1"],
		"server_host_key_algorithms": ["ssh-rsa"],
		"encryption_algorithms_client_to_server": ["aes128-cbc"],
		"encryption_algorithms_server_to_client": ["aes128-cbc"],
		"mac_algorithms_client_to_server": ["hmac-sha1"],
		"mac_algorithms_server_to_client": ["hmac-sha1"],
		"compression_algorithms_client_to_server": ["none"],
		"compression_algorithms_server_to_client": ["none"],
		"languages_client_to_server": [],
		"languages_server_to_client": [],
	}
	
	def handle(self):
		self.exchange_SSH_banner()		
		self.write_SSH_kexinit()
		
		while True:
			payload = io.BytesIO(self.read_SSH_packet())
			msgid = struct.unpack("B", payload.read(1))[0]
			if self.kex_started and msgid == self.SSH_MSG_KEXDH_INIT:
				self.do_SSH_dhkex(payload)
			elif msgid == self.SSH_MSG_NEWKEYS:
				self.kex_started = False
				print("Key exchange completed sucessfully!")
				self.cipher_block_size = 16 # XXX hardcoded
				self.mac_enabled = True
				print(hex(self.shared_secret))
				print(self.rfile.read(16))
				#return
			elif msgid == self.SSH_MSG_KEXINIT:
				self.read_SSH_kexinit(payload)
				self.kex_started = True
			else:
				print("Exiting: Invalid MSGID 0x%x" % msgid)
				return
	
	
	# Receiving stuff:
	
	def read_SSH_banner(self):
		client_banner = b""
		while True:
			client_banner += self.rfile.read(1)
			if client_banner.endswith(b"\r\n"):
				break
		self.client_id_str = client_banner.strip(b"\r\n")
		return self.client_id_str
	
	def read_SSH_kexinit(self, payload):
		self.client_kexinit = payload.getbuffer()
		cookie = payload.read(16)
		for key in self.kexinfo_keys:
			self.client_kexinfo[key] = self.read_SSH_namelist(payload)
		first_kex_packet_follows, reserved = struct.unpack("!BI", payload.read(1+4))
		#print(self.client_kexinfo)
		#print(first_kex_packet_follows, reserved)
	
	def read_SSH_namelist(self, payload):
		length = struct.unpack("!I", payload.read(4))[0]
		data = payload.read(length).decode("ASCII")
		data_list = data.split(",")
		return data_list
	
	def read_SSH_mpint(self, payload): # only works for positive ints!
		length = struct.unpack("!I", payload.read(4))[0]
		if length > 0:
			value = struct.unpack("b", payload.read(1))[0]
			length -= 1
			while length > 0:
				value <<= 8
				value += struct.unpack("B", payload.read(1))[0]
				length -= 1
			return value
		else:
			return 0
	
	def read_SSH_packet(self):
		packet_length, padding_length = struct.unpack("!IB", self.rfile.read(4+1))
		payload = self.rfile.read(packet_length - padding_length - 1)
		padding = self.rfile.read(padding_length)
		if self.mac_enabled == True:
			pass
		#print(payload)
		return payload
	
	
	# Sending stuff:
	
	def write_SSH_packet(self, packet):
		padding_factor = max(8, self.cipher_block_size)
		notpadding_len = 5 + len(packet)
		padding_len = padding_factor - (notpadding_len % padding_factor)
		if padding_len < 4:
			padding_len += padding_factor
		self.wfile.write(struct.pack("!IB", padding_len + len(packet) + 1, padding_len))
		self.wfile.write(packet)
		self.wfile.write(os.urandom(padding_len))
		if self.mac_enabled == True:
			pass
	
	def write_SSH_kexinit(self):
		packet = struct.pack("B", self.SSH_MSG_KEXINIT)
		packet += os.urandom(16)
		for key in self.kexinfo_keys:
			packet += self.make_SSH_namelist(self.server_kexinfo[key])
		packet += struct.pack("!BI", 0, 0)
		self.server_kexinit = packet
		self.write_SSH_packet(packet)
	
	
	# Protocol building blocks

	def make_SSH_namelist(self, namelist):
		commalist = ",".join(namelist).encode("ASCII")
		data = struct.pack("!I", len(commalist))
		data += commalist
		return data
	
	def make_SSH_string(self, string):
		return struct.pack("!I", len(string)) + string
	
	def make_SSH_mpint(self, bigint): # only works for positive ints!
		body = b""
		while bigint:
			body = struct.pack("B", bigint & 0xFF) + body
			bigint >>= 8
		
		if body[0] & 0x80:
			body = b"\x00" + body
		
		return self.make_SSH_string(body)
			
			
			
	# Misc:
	
	def exchange_SSH_banner(self):
		self.wfile.write(self.ID_STR + b"\r\n")		
		self.client_id_str = self.read_SSH_banner()
		print("Client version: {}".format(self.client_id_str.decode("ASCII")))
	
	
	# Key exchange stuff:
	
	def do_SSH_dhkex(self, payload):
		e = self.read_SSH_mpint(payload)
		#print(payload.getbuffer())
		#print(self.make_SSH_mpint(e))
		y = secrets.randbits(512)
		f = pow(dh.g, y, dh.p)
		K = pow(e, y, dh.p)
		self.shared_secret = K
		
		#print("Shared secret: {}".format(hex(K)))
		
		prehash = self.make_SSH_string(self.client_id_str)
		prehash += self.make_SSH_string(self.ID_STR)
		prehash += self.make_SSH_string(self.client_kexinit)
		prehash += self.make_SSH_string(self.server_kexinit)
		prehash += self.make_SSH_pubkeystr()
		prehash += self.make_SSH_mpint(e)
		prehash += self.make_SSH_mpint(f)
		prehash += self.make_SSH_mpint(K)
		
		print(prehash)
		
		H = sha.sha1(prehash)
		
		#print(H)
		
		packet = struct.pack("B", self.SSH_MSG_KEXDH_REPLY)
		packet += self.make_SSH_pubkeystr()
		packet += self.make_SSH_mpint(f)
		packet += self.make_SSH_rsasig(H)
		
		self.write_SSH_packet(packet)
		self.write_SSH_packet(struct.pack("B", self.SSH_MSG_NEWKEYS))
	
	def make_SSH_pubkeystr(self):
		content = self.make_SSH_string(b"ssh-rsa")
		content += self.make_SSH_mpint(rsakey.e)
		content += self.make_SSH_mpint(rsakey.n)
		return self.make_SSH_string(content)
	
	def make_SSH_rsasig(self, m):
		content = self.make_SSH_string(b"ssh-rsa")
		content += self.make_SSH_string(rsa.sign(m, rsakey.d, rsakey.n))
		return self.make_SSH_string(content)
		
def cleanup():
	print("Stopping server...")
	server.server_close()

if __name__ == "__main__":
	RSA_KEYFILE = "rsakey.py"
	if not os.path.isfile(RSA_KEYFILE):
		rsa.gen_keypair(RSA_KEYFILE)
	
	import rsakey

	HOST, PORT = "0.0.0.0", 1234
	server = socketserver.TCPServer((HOST, PORT), SSHHandler)
	atexit.register(cleanup)
	server.serve_forever()
