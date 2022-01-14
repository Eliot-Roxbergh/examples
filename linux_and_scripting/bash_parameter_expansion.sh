#!/bin/bash -eu
# See Bash manual, shell parameter expansion, for more info
# Guide here https://wiki.bash-hackers.org/syntax/pe
#   See also POSIX bracket expressions (https://www.regular-expressions.info/posixbrackets.html)

MY_PATH=/a/b/foo.x.y
echo "${MY_PATH#*/}"  # -> a/b/foo.x.y
echo "${MY_PATH##*/}" # -> foo.x.y
echo "${MY_PATH%.*}"  # -> /a/b/foo.x
echo "${MY_PATH%%.*}" # -> /a/b/foo

echo "${MY_PATH%/*}"  # -> /a/b


#
# Match from beginning = #
#   (delete from start according to pattern)
# Match from end = %
#   (delete from end according to pattern)
#
# Greedy match, by using double # or % (## or %%)
#
#


#NOTE: for getting filename or directory name we have the two programs which should be included on UNIX:
#	basename
#	dirname
