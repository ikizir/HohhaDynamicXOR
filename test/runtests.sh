#!/bin/bash
PROGR=$1
TIMES=10
FAILCOUNT=0

for D in */; do
	cd "$D"
	echo "running tests in $D"
	../../scripts/testencr.sh "../$PROGR" "$TIMES"
	FAILCOUNT=$((FAILCOUNT + $?))
	../../scripts/testdecr.sh "../$PROGR" "$TIMES"
	FAILCOUNT=$((FAILCOUNT + $?))
	cd ..
done

echo "fail count: $FAILCOUNT"
exit $FAILCOUNT
