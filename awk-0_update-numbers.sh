#!/bin/bash -u
# © Eliot Roxbergh 2021
# Just learning awk.. feel free to give pointers.
# Example how to write a longer awk script.
#       Multiple queries are made for each line,
# Testing on a GNU/Linux system, so this was verified with gawk (4.1.4)

SAMPLE_INPUT=$(cat << EOL
here is some text we want to keep,
but not modify

/* This is important, and will change the num! */

blabla
#blabla

#change -> 1234 <- (should be 100)
#change -> 1234 <- (should be 200)
#change -> 1234 <- (should be 300)

/* This is important, and will change the num! */
#blabla
#change -> 1234 <- (should be 500)
#change -> 1234 <- (should be 600)
EOL
)


# awk script starts here!
echo "${SAMPLE_INPUT}" | awk '
function update_num(){
        if (new_num == 0) { print "ERROR: Document incorrectly formatted (expected /* .. */)"; exit 1 }
        new_num_to_write = new_num*100
}

BEGIN {
        new_num=0
        new_num_to_write = 0
        replace_me=1234

        #Optional we can set Field Separator (FS) here, default is split by whitespace (we are using fields later.. as in $3)
        #FS = ","
}

#awk, so for each line, do the following;

#Found comment, do X
/\/\*.+\*\// {
        new_num+=1
        update_num()
}

#Line begins with # and found our number in third field, do Y (this is the num we will update)
# /^#/ && gsub(replace_me, new_num_to_write, $3) { new_num+=1; update_num()} #note this will make the replacement FIRST, and then run our commands
        ### OR ###
/^#/ && $3 ~replace_me { $3 = new_num_to_write;  new_num+=1; update_num()}
# These commands can be quite powerful, we could also read the current value, compare it ($3 >= 100), modify it, and then update it... etc. All sorts of things.
#       (now we are replacing the placeholder $replace_me, could also do a more generic: /^[0-9]+/
#       (here, ~ means "contains")
# Of course we could also do a simpler, more naive query, without using field delimiter or our specific placeholder variable:
# /^#.+\s[0-9]+/ {$0 = "new line contents ..." ; new_num+=1; update_num();}

#Finally print current line, including any changes made (this will result in the new file output we want, which we can output it to a new file by redirection > )
/.*/ {print}

# Optional
#END {
#        print "Done."
#}

' #>result.txt #uncomment this to save to file instead of print to stdout
