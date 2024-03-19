#!/bin/bash -u
# Eliot Roxbergh 2024
#
# Combine lines from users_all.txt and passwords.txt
# This was used for web authentication pw bruteforce, which used this format

while IFS= read -r line1; do
    while IFS= read -r line2; do
        echo "$line1:$line2" | base64
    done < users_all.txt
done < passwords.txt
