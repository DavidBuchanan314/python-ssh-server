import struct

ONES = 0xFFFFFFFF

def _leftrotate(x, n): # assumes 32-bit words
	return ( x << n | x >> 32-n ) & ONES

def sha1(m):
	h0, h1, h2, h3, h4 = 0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0
	
	message_len = len(m)
	padding_len = 64 - ((message_len + 1 + 8) % 64)
	m += b"\x80" + (b"\x00"*padding_len) + struct.pack(">Q", message_len * 8)
	
	while m:
		w = list(struct.unpack(">" + "I"*16, m[:64]))
		m = m[64:]
		
		for i in range(16, 80):
			w.append(_leftrotate(w[i-3] ^ w[i-8] ^ w[i-14] ^ w[i-16], 1))
		
		a, b, c, d, e = h0, h1, h2, h3, h4
		
		for i in range(80):
			if 0 <= i < 20:
				f = d ^ (b & (c ^ d))
				k = 0x5A827999
			elif 20 <= i < 40:
				f = b ^ c ^ d
				k = 0x6ED9EBA1
			elif 40 <= i < 60:
				f = (b & c) | (b & d) | (c & d) 
				k = 0x8F1BBCDC
			elif 60 <= i < 80:
				f = b ^ c ^ d
				k = 0xCA62C1D6
    
			a, b, c, d, e = (_leftrotate(a, 5) + f + e + k + w[i]) & ONES, a, _leftrotate(b, 30), c, d
    
		h0 = (h0 + a) & ONES
		h1 = (h1 + b) & ONES 
		h2 = (h2 + c) & ONES
		h3 = (h3 + d) & ONES
		h4 = (h4 + e) & ONES
	
	return struct.pack(">" + "I"*5, h0, h1, h2, h3, h4)
