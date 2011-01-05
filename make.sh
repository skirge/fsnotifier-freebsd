#!/bin/sh
if [ `uname` = FreeBSD ]; then
	FILES="main.c util.c kqueue.c"
else
	FILES="main.c inotify.c util.c"
fi

echo "compiling 32-bit version"
gcc -O2 -m32 -Wall -std=c99 -o fsnotifier $FILES
echo "compiling 64-bit version"
gcc -O2 -m64 -Wall -std=c99 -o fsnotifier64 $FILES
