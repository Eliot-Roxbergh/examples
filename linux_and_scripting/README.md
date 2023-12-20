# Text tools

**tr** - simple remove characters
```
# remove all ',' characters
tr -d , < test.json`
```

**cut** - simple get field by delimiter
```
# get the first field on each line, delimited by ","
cut -d , -f1 < test.json
```

**sed** - flexible text manipulation (see separate file)
```
#find lines ending with 'bash', on each hit perform search and replace
sed -E "/.*bash$/ { s/^(\w*).*$/\1/;p };d" < /etc/passwd
```

**awk** - (more advanced) flexible text manipulation (see separate file)
```
#If third argument delimted by : only contains digits add it to sum
awk -F ':' '$3 ~ /^[0-9]+$/ {sum+=$3} END {print sum}' < /etc/passwd
```

## Others

**grep** - find text or simple text manipulation (regex)

**sort** - sort (including randomize)

**uniq** - show only unique or duplicate lines

**paste** - merge files

(cat head tail wc tee)
