#!/bin/bash

for i in {1..150}
do
    curl -w "@format.txt" -o /dev/null -s "http://192.168.178.37"
done
