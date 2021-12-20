#include <stdio.h>
#include <stdlib.h>
#include "read_input.h"

/*
 * Find all integers in text file
 *
 * Finds (up to) nr_of_lines integers (allocates memory for one integer per line).
 * One line may have any number of integers,
 * but if too many integers are found the last integers in file will be ignored.
 *
 * Caller frees int **output
 */
int read_ints (const char *file_name, unsigned int *entries, int **output)
{
    FILE *file = fopen(file_name,"r");
    unsigned int hits = 0;
    int *nums;

    if (!file) {
        nums = NULL;
        goto error;
    }

    while(1) {
        if (fgetc(file) == '\n') {
            hits++;
        }
        if (feof(file) != 0) {
            break; //done
        }
        if (ferror(file) != 0) {
            goto error;
        }
    }

    nums = malloc(sizeof(unsigned int)*hits);
    if (!nums || hits == 0) {
        goto error;
    }

    rewind(file);
    for(unsigned int i=0; i<hits; i++) {
        if (fscanf(file, "%d", &nums[i]) != 1) {
            hits = i; //found fewer ints than nr of lines, but OK
            goto ok;
        }
        if (feof(file) != 0) {
            hits = i;
            goto ok;
        }
        if (ferror(file) != 0) {
            goto error;
        }
    }
ok:
    *entries = hits;
    *output = nums; //caller frees
    fclose(file);
    return 0;
error:
    *entries = 0;
    *output = NULL;
    fclose(file);
    if (nums) {
        free(nums);
    }
    return 1;
}

/*
 * Find all: string (max 10 chars) followed by an integer
 */
int read_str_int (const char *file_name, unsigned int *entries, char ***out_strs, int **out_ints)
{
    FILE *file = fopen(file_name,"r");
    unsigned int lines=0, hits;
    int *nums = NULL;
    char **strs = NULL;

    if (!file) {
        goto error;
    }

    while(1) {
        if (fgetc(file) == '\n') {
            lines++;
        }
        if (feof(file) != 0) {
            break; //done
        }
        if (ferror(file) != 0) {
            goto error;
        }
    }
    if (lines == 0) {
        goto error;
    }

    nums = malloc(sizeof(unsigned int)*lines);
    strs = malloc(sizeof(char*)*lines);
    for (unsigned int i=0; i<lines; i++) {
        strs[i] = malloc(sizeof(char)*11);
    }

    rewind(file);
    for (unsigned int i=0; i<lines; i++) {
        //string max 10 chars
        if (fscanf(file, "%10s %d", strs[i], &nums[i]) != 2) {
            hits = i; //found fewer ints than nr of lines, but OK
            goto ok;
        }
        if (feof(file) != 0) {
            hits = i;
            goto ok;
        }
        if (ferror(file) != 0) {
            goto error;
        }
    }
    hits = lines;
ok:
    for (;lines>hits; lines--) {
        // if less hits found than memory allocated, free unused memory
        free(strs[lines-1]);
    }

    *entries = hits;
    //caller frees...
    *out_ints = nums;
    *out_strs = strs;
    fclose(file);
    return 0;
error:
    *entries = 0;
    *out_ints = NULL;
    *out_strs = NULL;
    fclose(file);
    if (nums) {
        free(nums);
    }
    if (strs) {
        for (unsigned int i=0; i<lines; i++) {
            free(strs[i]);
        }
        free(strs);
    }
    return 1;
}

/*
 * Find all: strings (max 20 chars per)
 */
int read_strs (const char *file_name, unsigned int *entries, char ***out_strs)
{
    FILE *file = fopen(file_name,"r");
    unsigned int lines=0, hits;
    char **strs = NULL;

    if (!file) {
        goto error;
    }

    while(1) {
        if (fgetc(file) == '\n') {
            lines++;
        }
        if (feof(file) != 0) {
            break; //done
        }
        if (ferror(file) != 0) {
            goto error;
        }
    }
    if (lines == 0) {
        goto error;
    }

    strs = malloc(sizeof(char*)*lines);
    for (unsigned int i=0; i<lines; i++) {
        strs[i] = malloc(sizeof(char)*21);
    }

    rewind(file);
    for (unsigned int i=0; i<lines; i++) {
        if (fscanf(file, "%s", strs[i]) != 1) {
            hits = i; //found fewer ints than nr of lines, but OK
            goto ok;
        }
        if (feof(file) != 0) {
            hits = i;
            goto ok;
        }
        if (ferror(file) != 0) {
            goto error;
        }
    }
    hits = lines;
ok:
    for (;lines>hits; lines--) {
        // if less hits found than memory allocated, free unused memory
        free(strs[lines-1]);
    }

    *entries = hits;
    //caller frees...
    *out_strs = strs;
    fclose(file);
    return 0;
error:
    *entries = 0;
    *out_strs = NULL;
    fclose(file);
    if (strs) {
        for (unsigned int i=0; i<lines; i++) {
            free(strs[i]);
        }
        free(strs);
    }
    return 1;
}


/*
 * Read ints split by line
 */
int read_ints_per_line (const char *file_name, unsigned int *entries, line_entry **out_ints)
{
    FILE *file = fopen(file_name,"r");
    unsigned int lines=0, hits;
    line_entry *ints= NULL;

    size_t line_width = 128;

    if (!file) {
        goto error;
    }

    // count lines
    while(1) {
        if (fgetc(file) == '\n') {
            lines++;
        }
        if (feof(file) != 0) {
            break; //done
        }
        if (ferror(file) != 0) {
            goto error;
        }
    }
    if (lines == 0) {
        goto error;
    }
    ints = calloc(lines, sizeof(line_entry));

    for (unsigned int i=0; i<lines; i++) {
        ints[i].elems = calloc(line_width, sizeof(int));
    }

    //find ints
    rewind(file);
    unsigned int line = 0;
    size_t index = 0;
    while (line<lines) {
        //continue on same line
        if (index < line_width) {
            ints[line].nr_elems++;
            if (fscanf(file, "%d", &ints[line].elems[index]) != 1) {
                hits = line; //done, no more integers
                goto ok;
            }
            if (feof(file) != 0) {
                hits = line;
                goto ok;
            }
            if (ferror(file) != 0) {
                goto error;
            }
            index++;
        } else {
            goto error;
        }
        //next line
        if (fgetc(file) == '\n') {
            index = 0;
            line++;
        }
        if (feof(file) != 0) {
            hits = line;
            goto ok;
        }
        if (ferror(file) != 0) {
            goto error;
        }
    }
    hits = lines;
ok:
    for (;lines>hits; lines--) {
        // if less hits found than memory allocated, free the difference (i.e. unused memory)
        free(ints[lines-1].elems);
    }

    *entries = hits;
    //caller frees...
    *out_ints = ints;
    fclose(file);
    return 0;
error:
    *entries = 0;
    *out_ints = NULL;
    fclose(file);
    if (ints) {
        for (unsigned int i=0; i<lines; i++) {
            free(ints[i].elems);
        }
        free(ints);
    }
    return 1;
}

/*
int read_ints (const char *file_name, unsigned int *entries, int **output)
{
    FILE *file = fopen(file_name,"r");
    unsigned int lines = 0, cur_line = 0;
    int num = 0;
    int *nums;
    int rv;

    if (!file) {
        nums = NULL;
        rv = 1;
        goto error;
    }

    while(1) {
        if (fgetc(file) == '\n') {
            lines++;
        }
        if (ferror(file) != 0) {
            rv = 1;
            goto error;
        }
        if (feof(file) != 0) {
            break; //eof
        }
    }

    nums = malloc(sizeof(unsigned int)*lines);
    if (!nums || lines == 0) {
        rv = 1;
        goto error;
    }

    rewind(file);
    // TODO can we read lines here instead? readline / fgets
    // TODO to be more general we should probably just return line as string
    //      or like move out fscanf lines to new function which is defined by main or whatever
    // see also fscanf_s
    while (1) {
        if(cur_line >= lines) {
            break; //buffer full
        }
        if (fscanf(file, "%d", &num) != 1) {
            goto ok;
        }
        nums[cur_line] = num;
        // cur_line is not really correct since it only means how many integers found and saved, not lines
        //  or rather it is correct only in the case that there is one integer per line
        if (feof(file) != 0) {
            break;
        }
        if (ferror(file) != 0) {
            rv = 1;
            goto error;
        }
        cur_line++;
    }
ok:
    rv = 0;
error:
    *entries = lines;
    *output = nums;
    fclose(file);
    return rv;
}
*/
