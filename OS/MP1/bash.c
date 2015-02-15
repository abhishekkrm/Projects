#!/bin/bash 
COUNTER=0
echo "io forked"
while [  $COUNTER -lt 20 ]; do
    let COUNTER=COUNTER+1
    echo $COUNTER 
    python q03-timing.py io forked $COUNTER
done 
