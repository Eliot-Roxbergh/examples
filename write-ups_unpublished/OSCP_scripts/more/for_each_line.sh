#!/bin/bash -u
# Eliot Roxbergh 2024
#
# Run a command for each line in given file (ugly script).
# For instance to run a command for each username in file.
#
# Command is entered by user 'ph1' replaced by line in file
# Example: ./for_each_line.sh ip.txt "echo here is a line: ph1"
#

file=$1
# Rest of args as $command
shift
command=$*

# run for each line in file
# TODO: read without -r will mangle backslashes
while read line; do
        new_command=$(echo $command | sed "s|ph1|$line|g")
        echo
        echo "# Running the following command:"
        echo "#   $new_command"
        echo
        $new_command
done < "$file"


