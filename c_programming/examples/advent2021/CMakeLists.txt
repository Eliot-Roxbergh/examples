if (CLANG_TESTS)
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
endif()

cmake_minimum_required(VERSION 3.6)

project(advent2021)

#TODO make a loop for these... (see foreach)
add_executable(1.out read_input.c 1/1.c)
add_executable(2.out read_input.c 2/2.c)
add_executable(3.out read_input.c 3/3.c)
add_executable(4.out read_input.c 4/4.c)

#NOTE! A bit messy... the binaries need to be placed in their own directory as setup now
#       This is accomplished by the below lines and the command: make install (cmake --build does not "install")
#   (TODO how to do this with cmake instead of make install?)
install(TARGETS 1.out RUNTIME DESTINATION ${CMAKE_CURRENT_LIST_DIR}/1/)
install(TARGETS 2.out RUNTIME DESTINATION ${CMAKE_CURRENT_LIST_DIR}/2/)
install(TARGETS 3.out RUNTIME DESTINATION ${CMAKE_CURRENT_LIST_DIR}/3/)
install(TARGETS 4.out RUNTIME DESTINATION ${CMAKE_CURRENT_LIST_DIR}/4/)

include_directories(.)
