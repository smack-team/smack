#!/bin/sh -e

autoreconf --install --symlink
./configure --prefix="/usr" $@
