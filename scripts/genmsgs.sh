#!/bin/bash

PROGR=$(dirname $0)/genmsg.py
TIMES=$1

for ((I=0; I<TIMES; ++I)); do
	"$PROGR" "${@:2}" > "$I-plain.txt"
done
