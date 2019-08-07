#!/bin/sh

# TODO actually learn makefiles and shit lul

gcc -g -Wall src/*.c `pkg-config fuse3 --cflags --libs` -lefence -o mcachefs
