#!/bin/sh
_STDBUF_E=0 _STDBUF_I=0 _STDBUF_O=0 LD_PRELOAD=/usr/local/lib/libstdlib32/libstdbuf.so $1
