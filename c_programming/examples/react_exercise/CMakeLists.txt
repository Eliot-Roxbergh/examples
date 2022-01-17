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

#This exercise does not have main, only run with test suite from Exercism.io ..
#   Let's build as shared ("dynamic") library for now
add_library(react SHARED react.c)
add_library(react_alternative SHARED react_alternative.c)

include_directories(.)
