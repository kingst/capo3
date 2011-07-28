#!/usr/bin/python
import sys

print "hello world"

while True:
    data = sys.stdin.read(4)
    
    if not data:
        break;
    print "read byte"

