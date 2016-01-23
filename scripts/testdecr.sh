#!/bin/bash

PROGR=$1
TIMES=$2

FAILCOUNT=0

for ((I=0; I<TIMES; ++I)); do
	K=$(cat "$I-key.txt")
	S=$(cat "$I-salt.txt")
	M=$(cat "$I-cipher.txt")
	EXPECT=$(cat "$I-plain.txt")
	ACTUAL=$("$PROGR" -d -K "$K" -S "$S" -m "$M")
	if [ "$EXPECT" == "$ACTUAL" ]; then
		echo "test decr $I: pass"
	else
		echo "test decr $I: fail"
		FAILCOUNT=$((FAILCOUNT + 1))
	fi
done

exit $FAILCOUNT
