#!/bin/sh
echo "compiling 32-bit version"
gcc -O2 -m32 -Wall -std=c99 -o fsnotifier $FILES
echo "compiling 64-bit version"
gcc -O2 -m64 -Wall -std=c99 -o fsnotifier64 $FILES
