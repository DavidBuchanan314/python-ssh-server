import math
import random
import secrets
import struct

import sha

def multiplicative_inverse(e, phi):
	"""For some reason, this is the only implementation I can find that
	actually works."""
	
	d, x1, x2, y1 = 0, 0, 1, 1
	original_phi = phi
	
	while e > 0:
		temp1 = phi // e
		phi, e  = e, phi % e
		x2, x1 = x1, (x2 - temp1 * x1)
		d, y1 = y1, (d  - temp1 * y1)
    
	return d % original_phi

def rabin_miller(p):
	s = p - 1
	t = 0
	while s & 1 == 0:
		s >>= 1
		t +=1
	
	for _ in range(64): # probably overkill, but doesn't hurt much
		a = random.randrange(2, p - 1)
		v = pow(a,s,p)
		if v != 1:
			i = 0
			while v != (p - 1):
				if i == (t - 1):
					return False
				else:
					i += 1
					v = pow(v, 2, p)
	return True

def is_prime(p):
	low_primes = [3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47, 53, 59, 61, 67, 71, 73, 79, 83, 89, 97, 101, 103, 107, 109, 113, 127, 131, 137, 139, 149, 151, 157, 163, 167, 173, 179, 181, 191, 193, 197, 199, 211, 223, 227, 229, 233, 239, 241, 251, 257, 263, 269, 271, 277, 281, 283, 293, 307, 311, 313, 317, 331, 337, 347, 349, 353, 359, 367, 373, 379, 383, 389, 397, 401, 409, 419, 421, 431, 433, 439, 443, 449, 457, 461, 463, 467, 479, 487, 491, 499, 503, 509, 521, 523, 541, 547, 557, 563, 569, 571, 577, 587, 593, 599, 601, 607, 613, 617, 619, 631, 641, 643, 647, 653, 659, 661, 673, 677, 683, 691, 701, 709, 719, 727, 733, 739, 743, 751, 757, 761, 769, 773, 787, 797, 809, 811, 821, 823, 827, 829, 839, 853, 857, 859, 863, 877, 881, 883, 887, 907, 911, 919, 929, 937, 941, 947, 953, 967, 971, 977, 983, 991, 997]
	for prime in low_primes:
		if p % prime == 0:
			return False
	return rabin_miller(p)
	
def gen_prime(length):
	while True:
		p = secrets.randbits(length) # requires python version >= 3.6
		p |= 1 # might as well only choose odd numbers
		if is_prime(p):
			return p

def gen_keypair(filename):
	print("Generating p...")
	p = gen_prime(1024)
	print("Generating q...")
	q = gen_prime(1024)
	
	n = p * q
	phi = (p - 1) * (q - 1)
	e = 0x10001
	print("Generating d...")
	d = multiplicative_inverse(e, phi)
	
	# sanity check:
	plaintext = 1337
	testenc = pow(plaintext, e, n)
	testdec = pow(testenc, d, n)
	if plaintext == testdec:
		print("Sanity check passed.")
	else:
		print("Sanity check failed. Aborting!")
		return

	# probably not the ideal storage format, but I want to do everything from scratch.
	keyfile = open(filename, "w")
	keyfile.write("e = {}\n".format(hex(e)))
	keyfile.write("p = {}\n".format(hex(p)))
	keyfile.write("q = {}\n".format(hex(q)))
	keyfile.write("n = {}\n".format(hex(n)))
	keyfile.write("d = {}\n".format(hex(d)))
	keyfile.close()

def sign(m, d, n):
	OIDSTR = 	b"\x30\x21\x30\x09\x06\x05\x2b\x0e\x03\x02\x1a\x05\x00\x04\x14"
	h = sha.sha1(m)
	padded = b"\x00\x01" + b"\xFF"*(256-23-len(OIDSTR)) + b"\x00" + OIDSTR + h
	c = 0
	for x in padded:
		c <<= 8
		c |= x
	sig = pow(c, d, n)
	output = b""
	for _ in range(2048//8):
		output = struct.pack("B", sig & 0xFF) + output
		sig >>= 8
	return output
