cmake_minimum_required(VERSION 3.0)

#This exercise does not have main, only run with test suite from Exercism.io ..
#   Let's build as shared ("dynamic") library for now
add_library(react SHARED react.c)
add_library(react_alternative SHARED react_alternative.c)

include_directories(.)
