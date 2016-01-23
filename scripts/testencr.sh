#!/bin/bash

PROGR=$1
TIMES=$2

FAILCOUNT=0

for ((I=0; I<TIMES; ++I)); do
	K=$(cat "$I-key.txt")
	S=$(cat "$I-salt.txt")
	M=$(cat "$I-plain.txt")
	EXPECT=$(cat "$I-cipher.txt")
	ACTUAL=$("$PROGR" -e -K "$K" -S "$S" -m "$M")
	if [ "$EXPECT" == "$ACTUAL" ]; then
		echo "test encr $I: pass"
	else
		echo "test encr $I: fail"
		FAILCOUNT=$((FAILCOUNT + 1))
	fi
done

exit $FAILCOUNT
