#!/bin/env python3
import os, sys, base64

jumps = 2
if len(sys.argv) > 1:
	jumps = int(sys.argv[1])

length = 128
if len(sys.argv) > 2:
	length = int(sys.argv[2])

k = jumps.to_bytes(1, byteorder='little')
k += length.to_bytes(2, byteorder='little')
k += os.urandom(8 + length)

print(base64.b64encode(k).decode('UTF-8'))
