#!/bin/env python3
import os, sys, subprocess

oracle_prog = './oracle-jumps.sh'

def grain(s, h):
	return str((s >> h) & 0xff)

def salt(s1, s2):
	return ' '.join((
		grain(s1, 0), grain(s1, 8),
		grain(s1, 16), grain(s1, 24),
		grain(s2, 0), grain(s2, 8),
		grain(s2, 16), grain(s2, 24)))

def oracle(s1, s2):
	# just this is enough to solve the key jumps most of the time
	x = salt(s1, s2);
	o = subprocess.check_output([oracle_prog, '-S', x, '-m', 'AA=='])

	# call it with several variations, to avoide some output collisions
	x1 = salt(s1|0x2, s2|0x2);
	o1 = subprocess.check_output([oracle_prog, '-S', x1, '-m', 'AA=='])
	x2 = salt(s1|0x4, s2|0x4);
	o2 = subprocess.check_output([oracle_prog, '-S', x2, '-m', 'AA=='])
	x3 = salt(s1|0x8, s2|0x8);
	o3 = subprocess.check_output([oracle_prog, '-S', x3, '-m', 'AA=='])
	x4 = salt(s1|0x10, s2|0x10);
	o4 = subprocess.check_output([oracle_prog, '-S', x4, '-m', 'AA=='])
	x5 = salt(s1|0x20, s2|0x20);
	o5 = subprocess.check_output([oracle_prog, '-S', x5, '-m', 'AA=='])
	x6 = salt(s1|0x40, s2|0x40);
	o6 = subprocess.check_output([oracle_prog, '-S', x6, '-m', 'AA=='])

	print (o, o1, o2, o3, o4, o5, o6)

	return o, o1, o2, o3, o4, o5, o6

tgt = oracle(0, 0)

s1 = 0x00000100
s1_count = 0

while tgt != oracle(s1, 0):
	s1 <<= 1
	s1_count += 1

s2 = 0x80000000
s2_count = 0

while tgt != oracle(0, s2):
	s2 >>= 1
	s2_count += 1

print("s1_effect: " + str(s1_count))
print("s2_effect: " + str(s2_count))

if s2_count < s1_count:
	s2_count = s1_count
if s1_count < s2_count:
	s1_count = s2_count - 1

print("key_jumps: " + str(s1_count + s2_count))
