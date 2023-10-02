#!/bin/bash -eu
# Copyright (c) 2022 Eliot Roxbergh, Licensed under AGPLv3 as per separate LICENSE file.
# example on gcc building (see gcc_flags.md for notes and up-to-date comments)

source_files="$@" #(shellcheck warns: https://github.com/koalaman/shellcheck/wiki/SC2124)

#std: the latest should already the default
gcc_flags=" -O3 -std=gnu11 -fno-common "


gcc_flags_warnings=" -Wall -Wextra -pedantic -Werror -Wformat=2 -Wconversion -Wdouble-promotion -Wshadow -Wundef "
gcc_flags_security="-D_FORTIFY_SOURCE=2  -D_GLIBCXX_ASSERTIONS -fcf-protection=full -fstack-protector-strong -Wl,-z,noexecstack -Wl,-z,now -Wl,-z,relro -Wl,-z,defs "
gcc_flags_security_exec="-fpie -Wl,-pie"
gcc_flags_security_lib="-fpic"
#more="-fstack-clash-protection -mcet" # depends on GCC version and some are hw specific

#                      Debug                         #
# Enable when necessary, not to use in production !! #
#
gcc_flags_debug="-g -0g -fasynchronous-unwind-tables -fexceptions"
# Extra warnings
gcc_flags_extra_warnings=" -fanalyzer -Wcast-qual -Wcast-align -Wredundant-decls -Winline -Wdisabled-optimization -Wnested-externs -fstrict-aliasing " #more: -Wmissing-prototypes -Wmissing-declarations
# Runtime checks (fails will stop the program)
gcc_flags_runtime_checks=" -fsanitize=address,undefined "
# Apply new warnings to debug
gcc_flags_debug="$gcc_flags_debug $gcc_flags_extra_warnings $gcc_flags_runtime_checks"

# I) build library

#lib.o object file (-c Compile or assemble the source files, but do not link.)
gcc ${gcc_flags} ${gcc_flags_debug} ${gcc_flags_warnings} ${gcc_flags_security} -c -Wall libx.c
#lib.so dynamic library (-shared Produce a shared object which can then be linked with other objects to form an executable)
gcc ${gcc_flags} ${gcc_flags_debug} ${gcc_flags_warnings}  ${gcc_flags_security} ${gcc_flags_security_lib} -shared -o libx.so libx.o


# II) compile and link our program

# WHAT DOES FLAGS STAND FOR?
# 0) debug information (-g) and some warnings
# 1) build our program
# 2) set rpath, where to look for this library during RUNTIME (e.g. on customer machine)
#        we could also set LD_LIBRARY_PATH etc. but this way is easiest if we don't control the machine.
# 3) set path to library for static linker, we need it to build our library
# 4) use library x (-> libx.so)
gcc ${gcc_flags} ${gcc_flags_debug} ${gcc_flags_warnings} ${gcc_flags_security} ${gcc_flags_security_exec} \
    ${source_files} -o prog \
    -Wl,-rpath,/home/username/tmp/ \
    -L/home/username/tmp/\
    -lx

#Then can have symlinks, soname, have ldconfig update it ...
