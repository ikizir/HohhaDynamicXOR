#!/bin/bash
PROGR=$1
TIMES=10

for J in 2 3 4; do
	for K in 64 128 256; do
		D="j$J-k$K"
		mkdir -p "$D"
		cd "$D"
		../../scripts/genkeys.sh "$TIMES" "$J" "$K"
		../../scripts/gensalts.sh "$TIMES"
		../../scripts/genmsgs.sh "$TIMES" 128
		../../scripts/runencr.sh "../$PROGR" "$TIMES"
		cd ..
	done
done
