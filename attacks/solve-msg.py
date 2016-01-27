#!/bin/env python3
import base64, os, sys, subprocess

oracle_prog = './oracle-msg.sh'

salt = sys.argv[1]

cipher = base64.b64decode(bytes(sys.argv[2], 'UTF-8'))

def oracle(msg):
	x = base64.b64encode(msg).decode('UTF-8')
	o = subprocess.check_output([oracle_prog, '-S', salt, '-m', x])
	return base64.b64decode(o)

plain = bytearray(len(cipher))

for i in range(len(plain)):
	result = oracle(plain[:i+1])
	plain[i] = result[i] ^ cipher[i]
	print(base64.b64encode(plain[:i+1]).decode('UTF-8'), file=sys.stderr)

print(base64.b64encode(plain).decode('UTF-8'))
