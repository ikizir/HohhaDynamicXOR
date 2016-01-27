#!/bin/bash

PROGR=$(dirname $0)/genkey.py
TIMES=$1

for ((I=0; I<TIMES; ++I)); do
	"$PROGR" "${@:2}" > "$I-key.txt"
done
