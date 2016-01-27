#!/bin/env python3
import os, sys, base64

length = 8

s = os.urandom(length)

print(' '.join(map(str, s)))
