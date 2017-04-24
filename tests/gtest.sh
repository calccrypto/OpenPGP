#!/usr/bin/env bash

# script to download and build GoogleTest
# not much better than git submodules, but there was never a need/want for the repo in this repo

cd ../..
git clone https://github.com/google/googletest.git
cd googletest
git reset --hard d62d6c6556d96dda924382547c54a4b3afedb22c
cmake CMakeLists.txt
make
