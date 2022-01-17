#simple example to build this: cmake --clean-first . && cmake --build .

set(C_STD c11)

### Static Analysis ###
# It is easy to automatically include additional testing with cmake.
# Below I include some static code analysis checks which are run at build time (cmake --build .).
#   My inspiration: https://www.kitware.com/static-checks-with-cmake-cdash-iwyu-clang-tidy-lwyu-cpplint-and-cppcheck/
#                   (https://www.youtube.com/watch?v=rLopVhns4Zs&t=4633s)
#   Requires: sudo apt install clang clang-tidy cppcheck iwyu #(not included: cpplint clazy)
#   For C++ change _C_ to _CXX_
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
    --std=${C_STD};
    #"--suppressions-list=${CMAKE_SOURCE_DIR}/CppCheckSuppressions.txt";
    )
set(CMAKE_C_INCLUDE_WHAT_YOU_USE
    iwyu;
    )
set(CMAKE_LINK_WHAT_YOU_USE TRUE)
### Not tried: ###
##Google style guide
#set(CMAKE_C_CPPLINT
#    cpplint;
#    --linelength=120;)
##Somewhat C++/Qt specific
#set(CMAKE_CXX_COMPILER
#    clazy;
#)
##################

cmake_minimum_required(VERSION 3.6)

project(examples)

#TODO we set debug (-g) here, should just use -DCMAKE_BUILD_TYPE=Debug instead .. or similar
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -std=${C_STD} -g -fasynchronous-unwind-tables -fexceptions -Wall -Werror -pedantic -Wconversion -Wextra -Wformat=2 -Wformat-truncation -Wunused -Werror=implicit-function-declaration -Werror=format-security")

add_executable(array         array.c)
add_executable(bit_manip     bit_manip.c)
add_executable(enum          enum.c)
add_executable(function_ptrs function_ptrs.c)
add_executable(ptrs          ptrs.c)
add_executable(ptrs2         ptrs2.c)

#Also build these projects
#add_subdirectory(advent2021)
#add_subdirectory(react_exercise)


