#!/bin/env python3
import os, sys, subprocess

oracle_prog = './oracle-length.sh'

def grain(s, h):
	return str((s >> h) & 0xff)

def salt(s1, s2):
	return ' '.join((
		grain(s1, 0), grain(s1, 8),
		grain(s1, 16), grain(s1, 24),
		grain(s2, 0), grain(s2, 8),
		grain(s2, 16), grain(s2, 24)))

def oracle(s1, s2):
	x = salt(s1, s2);
	o = subprocess.check_output([oracle_prog, '-S', x, '-m', 'AA=='])

	print(o)

	return o


s1_count = 0

# lengths as small as zero to 128 are detected
s1 = 0x01000000
s2 = 0x01000000
tgt = oracle(0, s2)
while tgt != oracle(s1, s2):
	s1 <<= 1
	s1_count += 1

# lengths 256 to 32K are detected
if s1 & 0xffffffff == 0:
	s1 = 0x02000000
	s2 = 0x80000000
	tgt = oracle(0, s2)
	while tgt != oracle(s1, s2):
		s1 <<= 1
		s1_count += 1

print("s1_effect: " + str(s1_count))

print("key_length: " + str(1 << s1_count))
