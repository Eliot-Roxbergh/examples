Advent of code 2021 <https://adventofcode.com/2021>

All these solutions are working,
insofar that they return the correct answer and have no memory leaks or memory errors.

Of course, don't take this too seriously. We are just here to learn and play around with some coding.


They all build successfully with the provided command:

_gcc -std=c11 -Wall -Werror -pedantic -Wconversion -g -fasynchronous-unwind-tables -fexceptions -Wall -Werror -pedantic -Wconversion -Wextra -Wformat=2 -Wformat-truncation -Wunused -Werror=implicit-function-declaration -Werror=format-security_

_valgrind --leak-check=full --show-leak-kinds=all --track-origins=yes_

gcc version 7.5.0

valgrind-3.13.0
