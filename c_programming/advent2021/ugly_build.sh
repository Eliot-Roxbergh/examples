#!/bin/bash -eu
# ../ugly_build.sh 4.c  ../read_input.c

target="$@" #allow multiple source files
debug="-g -fasynchronous-unwind-tables -fexceptions -Wall -Werror -pedantic -Wconversion -Wextra -Wformat=2 -Wformat-truncation -Wunused -Werror=implicit-function-declaration -Werror=format-security"

gcc -std=c11 -Wall -Werror -pedantic -Wconversion ${debug} ${target} -o a.out && ./a.out
#echo "gcc -std=c11 -Wall -Werror -pedantic -Wconversion ${debug} ${target} -o a.out && ./a.out"

