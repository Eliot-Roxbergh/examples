#!/bin/bash -eu
#Quick script to build and run a C project with some useful debug flags
#Just a quick one, but just use cmake instead

target="$@" #allow multiple source files (from arguments) #shellcheck complains on this line: https://github.com/koalaman/shellcheck/wiki/SC2124

debug="-g -fasynchronous-unwind-tables -fexceptions -Wall -Werror -pedantic -Wconversion -Wextra -Wformat=2 -Wformat-truncation -Wunused -Werror=implicit-function-declaration -Werror=format-security"
#-Wunused-result seem to only warn for special functions return?

echo "Running:"
echo "gcc -std=c11 -Wall -Werror -pedantic -Wconversion ${debug} ${target} -o a.out && ./a.out"
echo
gcc -std=c11 -Wall -Werror -pedantic -Wconversion ${debug} ${target} -o a.out && ./a.out

