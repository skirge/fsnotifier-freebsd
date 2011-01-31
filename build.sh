#!/bin/sh
#
# $Id$
#
#

TARGET=i386 TARGET_ARCH=i386 OUTPUT=fsnotifier make -j 2
TARGET_ARCH=amd64 OUTPUT=fsnotifier64 make -j 2
