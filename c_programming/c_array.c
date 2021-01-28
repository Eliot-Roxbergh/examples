#include <stdio.h>
#include <stdlib.h>

int main() {
   int arr[5] = {1, 2, 3, 4, 6};
   int len = *(&arr + 1) - arr;
   printf("The length of the array is: %i elem\n", len); // 5
   printf("The length of the array is: %li Bytes\n", sizeof(arr)); //20 Bytes
   printf("This is the same as %p - %p\n", *(&arr+1),arr); //diff is 20 (Bytes)
   return 0;
}

