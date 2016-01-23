#!/bin/bash

PROGR=$1
TIMES=$2

for ((I=0; I<TIMES; ++I)); do
	K=$(cat "$I-key.txt")
	S=$(cat "$I-salt.txt")
	M=$(cat "$I-cipher.txt")
	"$PROGR" -d -K "$K" -S "$S" -m "$M" > "$I-plain.txt"
done
