#!/usr/bin/env bash

# http://logan.tw/posts/2015/04/28/check-code-coverage-with-clang-and-lcov/
llvm-cov gcov "$@"
