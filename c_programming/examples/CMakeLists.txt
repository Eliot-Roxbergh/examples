#simple example to build this: cmake --clean-first . && cmake --build .


# Can try different tools on these projects then, like unit tests + code coverage or static code analysis
#https://www.kitware.com/static-checks-with-cmake-cdash-iwyu-clang-tidy-lwyu-cpplint-and-cppcheck/
#https://ortogonal.github.io/cmake-clang-tidy/
#http://www.mariobadr.com/using-clang-tidy-with-cmake-36.html
set(CMAKE_CXX_CLANG_TIDY
    clang-tidy;
    -header-filter=.;
    -checks=*;)
#set(CMAKE_CXX_CLANG_TIDY clang-tidy -checks=-*,readability-*)
#or
#cmake "-DCMAKE_CXX_CLANG_TIDY=/usr/bin/clang-tidy;-checks=*" .
#cmake "-DCMAKE_CXX_CPPCHECK=/usr/bin/cppcheck;–std=c++11" ../path/to/source
#cmake "-DCMAKE_CXX_CPPLINT=/usr/local/bin/cpplint;–linelength=79" ..
#cmake "-DCMAKE_CXX_INCLUDE_WHAT_YOU_USE=/usr/bin/iwyu;–transitive_includes_only" ..
#cmake -DCMAKE_LINK_WHAT_YOU_USE=TRUE ..

cmake_minimum_required(VERSION 3.0)

project(examples)

#TODO we set debug (-g) here, should just use -DCMAKE_BUILD_TYPE=Debug instead
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -g -fasynchronous-unwind-tables -fexceptions -Wall -Werror -pedantic -Wconversion -Wextra -Wformat=2 -Wformat-truncation -Wunused -Werror=implicit-function-declaration -Werror=format-security")

add_executable(array         array.c)
add_executable(bit_manip     bit_manip.c)
add_executable(enum          enum.c)
add_executable(function_ptrs function_ptrs.c)
add_executable(ptrs          ptrs.c)
add_executable(ptrs2         ptrs2.c)

#Also build these projects
add_subdirectory(advent2021)
add_subdirectory(react_exercise)


