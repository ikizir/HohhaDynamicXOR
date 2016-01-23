#!/bin/env python3
import os, sys, base64

length = 128
if len(sys.argv) > 1:
	length = int(sys.argv[1])

m = os.urandom(length)

print(base64.b64encode(m).decode('UTF-8'))
