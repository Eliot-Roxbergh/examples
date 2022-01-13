#include "../read_input.h"
#include <stdio.h>
#include <stdlib.h>



int main() {
    int lines, *input;
    if (read_ints("input", &lines, &input) != 0 || !input) {
        return 1;
    }

    free(input);
    return 0;
}
