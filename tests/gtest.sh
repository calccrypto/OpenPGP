#!/usr/bin/env bash

# script to download and build GoogleTest
# not much better than git submodules, but there was never a need/want for the repo in this repo

cd ../..
git clone --depth=1 https://github.com/abseil/googletest.git
cd googletest
cmake CMakeLists.txt
make
