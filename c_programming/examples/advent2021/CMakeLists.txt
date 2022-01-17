set(CMAKE_C_CLANG_TIDY
    clang-tidy;
    -header-filter=.;
    -checks=*;
   )
set(CMAKE_C_CPPCHECK
    cppcheck;
    --enable=warning;
    --inconclusive;
    --force;
    --inline-suppr;
    )
set(CMAKE_C_INCLUDE_WHAT_YOU_USE
    iwyu;
    )
set(CMAKE_LINK_WHAT_YOU_USE TRUE)

cmake_minimum_required(VERSION 3.6)

project(advent2021)

#TODO make a loop for these... (see foreach)
add_executable(1.out read_input.c 1/1.c)
add_executable(2.out read_input.c 2/2.c)
add_executable(3.out read_input.c 3/3.c)
add_executable(4.out read_input.c 4/4.c)

#NOTE! A bit messy... the binaries need to be placed in their own directory.
#       This is accomplished by the below lines, but ONLY by the command: make install
#   (TODO seems a bit messy)
install(TARGETS 1.out CONFIGURATIONS Debug RUNTIME DESTINATION 1/)
install(TARGETS 2.out CONFIGURATIONS Debug RUNTIME DESTINATION 2/)
install(TARGETS 3.out CONFIGURATIONS Debug RUNTIME DESTINATION 3/)
install(TARGETS 4.out CONFIGURATIONS Debug RUNTIME DESTINATION 4/)

include_directories(.)
