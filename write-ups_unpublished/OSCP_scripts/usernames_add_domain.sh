#!/bin/bash
# Eliot Roxbergh 2024
#
# Simple add a domain to a username to construct a possible email (for phishing mainly)
awk '{print $0 "@relia.com"}' users.txt > users_email.txt
