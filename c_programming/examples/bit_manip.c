// Copyright 2022 Eliot Roxbergh. Licensed under AGPLv3 as per separate LICENSE file.
#include <assert.h>
#include <math.h>  //add -lm to build
#include <stdio.h>

/* Question:
 *  - why does shift (<<) and bit inverse (~) return int?
 *      Is it also not more reasonable to use unsigned char
 *      for bit manipulation anyway?
 *      https://stackoverflow.com/a/58845898 mentions that "Do not use bitwise
 * operators with signed operands"
 *  - Werror=conversion, seems quite odd? See examples below.
 *
 * Addendum:
 *        This makes more sense if we consider variables shorter than int
 *        are converted to int ("integer promotion") in arithmetic operations (such as * / % + - < > <= == & ^).
 *        Additionally, it seems from these examples that it's OK to do
 *        int big = INT_MAX; unsigned char a = big & CHAR_MAX; //(casting CHAR_MAX to int is also ok here)
 *        But the same does not work with &(CHAR_MAX+1) or &UCHAR_MAX, 
 *        not sure why, but could relate to integer promotions (where unsigned char may be promoted to int),
 *        or are there some special rules with the & operator?
 *
 */

int main()
{
    //127 = 0x7F = CHAR_MAX
    //255 = 0xFF = UCHAR_MAX
    unsigned char bits = 5;
    unsigned char bits_inverse = 0;
    bits_inverse = (unsigned char)~bits;  // compiles OK!
    bits_inverse =
        ((unsigned int)~bits) &
        (0xFF - 1);  // gcc says OK (but clang-tidy says [hicpp-signed-bitwise])
    bits_inverse =
        ~bits &
        0xF;  // gcc says OK (but clang-tidy says [hicpp-signed-bitwise])

    // BUT!
    // bits_inverse = ~bits;             //gcc says error: -Werror=conversion
    // bits_inverse = ~bits & (0xFF);  //gcc says error: -Werror=conversion
    printf("%u\n", bits_inverse);

    /*
    //longer example:
    printf("%d\n", bits);
    for (int i=1; i<8; i++) {
        // without cast; error conversion to ‘unsigned char’ from ‘int’ may
    alter its value [-Werror=conversion] bits = (unsigned char) (bits << 1);
        assert(bits == pow(2, i)); // although pow returns double, 'bits' can be
    promoted in comparison (unsigned char == double => double == double)

        bits_inverse = (unsigned char) ~bits;           //OK
        //bits_inverse = ((unsigned int) ~bits) & 255;  //OK
        //bits_inverse = ((unsigned int) ~bits) & 256;  //NOT OK
        //bits_inverse = (~bits) & 255;                 //NOT OK
        //bits_inverse = ~bits & 0xF ;                  //OK
        //bits_inverse = ~bits & 0xFF ;                 //NOT OK

        //unsigned char is promoted to int (%d)
        printf("%u (one complement is %u)\n", bits, bits_inverse);
    }
    */

    return 0;
}
