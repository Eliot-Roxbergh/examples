# JQ

TODO: this document is pseudo-formatted as markdown

Tip: use fzf to see live output of your commands

## Syntax

{} -> an object. An object can contain values/lists, or other objects.
[] -> a list. That is when an object has more than one value.

[].  -> get the all values of an array OR an object. So for an object the outmost key is removed, we "step in".
|=   -> the update operator: update a structure given a filter.
keys -> an example of a builtin function [1]


to_entries   ->
from_entries ->
             -> convert to/from key-value pairs ("key": "my-key", "value": "my-value").
                This makes it easier to get/change single values, e.g. by doing `select( .value | index("get") )`

select  ->  Keep only items that the given filter returns true for.
            For instance, `select(.value | index("get"))` to remove lines not containing "get" in which case index() returns null.


[1] - https://jqlang.github.io/jq/manual/v1.5/#builtin-operators-and-functions


# Examples

```
jq .paths openapi.json | jq  '.[]|=keys' | jq 'to_entries | map(select(.value | index("get"))) | from_entries'
```

## Keep only entries where value is "get"

index -> builtin function that outputs index of a value, or null if not present.

1. Use to_entries to format input where object value is put into pair {"key" : "object value"}
2. Use map to perform an action on each element of array, the result is then outputted.
3. Use select and index to only get values that match a given name (here "get")
-> In conclusion, non-matching lines are removed from input.

- Example
```
jq 'to_entries | map(select(.value | index("get"))) | from_entries' openapi.json
```

## Get keys of an object

Run a filter (the `keys` function) on each element of the input array or object:
```
jq .paths openapi.json | jq  'map_values(keys)'
```

Note that: `map_values(keys)` is equivalent to `.[] |= keys`
           Which might explain how both these commands work (below).

Note: use keys_unsorted instead to retain the input order (not guaranteed).

### How it works / further examples

- These are different:
```
# Get the key
jq .paths openapi.json | jq  '.|=keys'
    (equivalent with:)
    jq .paths openapi.json | jq  'keys'

# Go one level deep and get its key
jq .paths openapi.json | jq  '.[]|=keys'

# Go two levels deep and get its key
jq .paths openapi.json | jq  '.[][]|=keys'
```

As stated by the builtin function `keys` (see [1]):
If given an array/object, print valid indices and its (the array's/objects's) key.
Otherwise, just print the key.

So:
.[] -> Get all its values (indices) and its key => key : [ value0, value1 ]
      (deeper nested objects are ignored, not necessary in this construction)

Comment: One would then think that these are the same, which they are not,
```
jq .paths openapi.json | jq '.[] |= keys'
jq .paths openapi.json | jq '.[] | keys'
```
Presumably, with regular pipe the `keys` function is unaware of the parent key which we ignored by stepping into the list.
While, if given the complete input it's able to step into the array while still knowing its parent key.


[1] - https://jqlang.github.io/jq/manual/v1.5/#builtin-operators-and-functions
