// Copyright 2022 Eliot Roxbergh. Licensed under AGPLv3 as per separate LICENSE file.
#include <stdio.h>
#include <stdlib.h>
#include "../read_input.h"

int main()
{
    int *input;
    unsigned int lines;
    if (read_ints("input", &lines, &input) != 0 || !input) {
        return 1;
    }

    // part1
    unsigned int count = 0;
    for (unsigned int i = 1; i < lines; i++) {
        if (input[i] > input[i - 1]) {
            count++;
        }
    }
    printf("%u measurements were larger than previous measurement\n", count);

    // part2
    count = 0;
    int prev_sum = input[0] + input[1] + input[2];
    int cur_sum = 0;

    for (unsigned int i = 1; i < lines - 2; i++) {
        cur_sum = input[i] + input[i + 1] + input[i + 2];
        if (cur_sum > prev_sum) {
            count++;
        }
        prev_sum = cur_sum;
    }
    printf("%u sums are larger than previous sum\n", count);

    free(input);
    return 0;
}
