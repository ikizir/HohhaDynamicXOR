#!/bin/bash

PROGR=$(dirname $0)/gensalt.py
TIMES=$1

for ((I=0; I<TIMES; ++I)); do
	"$PROGR" > "$I-salt.txt"
done
