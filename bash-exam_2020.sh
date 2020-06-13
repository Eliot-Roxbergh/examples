#!/bin/bash -e
#Bash exam 2020
#No warranty provided

# Price checker for imaginary items, has fake discount for elderly.
#   CTRL+C (SIGINT) enters admin mode which shows some host information,
#   assuming the correct password is supplied (read from file techpasswd)"

### PROVIDED FUNCTIONS ###
function user_mode {
    #terminal location provided by customer
    LOCATION=$1
    OPTION_1="Price Information"
    OPTION_2="Senior Rebate"

    echo "
        1) $OPTION_1
        2) $OPTION_2"

    #select output gets sent to stderr for some reason?
    select OPTION in "$OPTION_1" "$OPTION_2"
    do
        case $OPTION in
            "$OPTION_1")
                price_info
                #break
                ;;
            "$OPTION_2")
                senior_rebate
                #break
                ;;
            *)  ;;
        esac
    done
}

function price_info {
    while :
    do
        echo -e "Enter an article number: "
        read  ARTICLE

        #article code length (includes '\n')
        ARTICLE_LEN="$(echo "$ARTICLE" | wc -m )"
        if [ ! $ARTICLE_LEN -eq "8" ]; then
            echo "Invalid length of article code"
            echo "Expected 7, got $ARTICLE_LEN" 1>&2
            echo
            continue
        fi

        LOCATION_CODE="${ARTICLE:0:1}"
        PRICE_CODE="${ARTICLE:1:5}"
        CHECKSUM="${ARTICLE:6:6}"

        #Check if item location matches store location
        ERROR=0
        PRICE_MULTIPLIER="1"
        if [ "$LOCATION" = "G" ]; then
            if [ ! "$LOCATION_CODE" = "1" ]; then ERROR=1; fi
        elif [ "$LOCATION" = "S" ]; then
            #Stockholm tax
            PRICE_MULTIPLIER="1.15"
            if [ ! "$LOCATION_CODE" = "2" ]; then ERROR=1; fi
        elif [ "$LOCATION" = "M" ]; then
            if [ ! "$LOCATION_CODE" = "3" ]; then ERROR=1; fi
        else
            ERROR=1
        fi

        if [ "$ERROR" -eq "1" ]; then
            echo "Invalid location article code combination!"
            continue
        fi

        #checksum should be sum of digits modulus 7
        EXPECTED_CHECKSUM=$(echo "$PRICE_CODE" |\
            awk 'BEGIN{FIELDWIDTHS="1 1 1 1 1"}{print ($1+$2+$3+$4+$5)%7}')

        if [ ! $CHECKSUM -eq $EXPECTED_CHECKSUM ]; then
            echo "Invalid checksum!" 1>&2 #error
            echo -e "Invalid article\n"
            continue
        fi

        case "$PRICE_CODE" in
            "64964")
                PRICE=$(awk "BEGIN {print 120*${PRICE_MULTIPLIER}}")
                echo -e "$ARTICLE (USB stick): $PRICE kronor\n"
                #break
                ;;
            "59457")
                PRICE=$(awk "BEGIN {print 400*${PRICE_MULTIPLIER}}")
                echo -e "$ARTICLE (headset): $PRICE kronor\n"
                #break
                ;;
            *)
                echo -e "Hm, well I can't seem to find the product ($ARTICLE) in our system!\n"
                #break
                ;;
        esac
    done
}

#TODO the age calculation is probably not exact!
function senior_rebate {
    BIRTHDAY=""

    #Require 8 chars AND all digits
    while [ ! ${#BIRTHDAY} -eq 8 ] || [ ! -z "${BIRTH_YEAR##*[!0-9]*}" ]
    do
        echo -e "Enter your birthday (YYYYMMDD)"
        read BIRTHDAY
    done

    CURRENT_DATE=$(date +"%Y%m%d")
    let AGE=$CURRENT_DATE-$BIRTHDAY
    #Age in years
    AGE=${AGE:0:2}

    if [ $AGE -gt 64 ]; then
        echo "CONGRATULATIONS YOU ARE SENIOR REBATE ELIGABLE!"
    else
        echo "Good try kid, come back later"
    fi
}


#tech_mode is entered by a Trap
#(as long as we are in a trap no additional traps can be made)
function tech_mode {
    #Reset errors to tty
    exec 2>/dev/tty
    #Errors and warnings goes to both TTY and file
    exec > >(tee admin.log)

    FILE="techpasswd"

    if [[ ! -f "$FILE" ]]; then
        echo "ERROR: password file not found" 1>&2
        sleep 10
        return
    fi

    echo "Enter secret password:"
    read PASSWORD

    if [ "$PASSWORD" = "$( cat $FILE )" ]; then
        echo "CPU Model: $(  lscpu | awk -F:  '/Model name/ { print $2 }' | sed 's/^ *//g'  )"

        echo "Processes over 5000kB RSS: $(ps -eo rss --sort=-rss | awk '{ if ( $1 > 5000 ) {sum+=1}} {print sum}' | tail -n 1)"

        echo "System was last updated: $( stat /etc/redhat-release | awk '/Modify/ { print $2 " " $3 " (" $4 ")" }' )"

    else
        echo "Incorrect password" 1>&2
        sleep 10
    fi

    return
}

function help {
    echo -e "\\033[1m${0}\\033[0m usage:
    \\e[0;31m-h\\e[0m             Prints this help
    \\e[0;31m-shop G/S/M\\e[0m    Enter shop by specifying city Gothenburg, Stockholm, Malmo. Exactly one additional argument is required G, S, or M.

    Any other input will result in the printing of this help screen."
}


### PROGRAM STARTS HERE ###

#Hide errors from user, send to log file
exec 2>file.log

#CTRL+C triggers admin mode (requires password)
trap tech_mode SIGINT

#0-1 arguments always shows help
if [ $# -lt 2 ]; then
    help
#2 arguments check whether user wants to enter shop
elif [ $# -eq 2 ]; then
    case $1 in
        "-shop")
            user_mode $2
            #break
            ;;
        *)
            help
            #break
            ;;
    esac
#Too many arguments show help
else
    help
fi
