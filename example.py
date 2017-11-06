#!/usr/bin/env python

from sys import stdout
from time import sleep

messages = [
'announce route 100.10.0.0/24 next-hop self',
'announce route 200.20.0.0/24 next-hop self'
]

sleep(5)

#Iterate through messages
for message in messages:
    stdout.write( message + '\n')
    stdout.flush()
    sleep(1)

#Loop endlessly to allow ExaBGP to continue running
while True:
    sleep(1)
