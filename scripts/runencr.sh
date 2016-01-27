#!/bin/bash

PROGR=$1
TIMES=$2

for ((I=0; I<TIMES; ++I)); do
	K=$(cat "$I-key.txt")
	S=$(cat "$I-salt.txt")
	M=$(cat "$I-plain.txt")
	"$PROGR" -e -K "$K" -S "$S" -m "$M" > "$I-cipher.txt"
done
