#!/bin/sh
# ignore Control C
trap '' SIGINT
while `true`;
do
echo "announce route 192.0.2.1 next-hop 10.0.0.1"
sleep 10
echo "withdraw route 192.0.2.1 next-hop 10.0.0.1"
sleep 10
done
