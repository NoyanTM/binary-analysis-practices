#include <stdio.h>
#include <stdlib.h>

void get_user_input() {
    char name[32];

    printf("Enter your name: ");
    
    // secure alternative due to bound checking - fgets
    gets(name);

    printf("Hello, %s!\n", name);
}

int main() {
    get_user_input();
    return 0;
}

// gcc ./data/example.c -o ./data/example.o --std=c99
// ./data/example.c: In function ‘get_user_input’:
// ./data/example.c:8:5: warning: implicit declaration of function ‘gets’; did you mean ‘fgets’? [-Wimplicit-function-declaration]
//     8 |     gets(name); // secure alternative due to bound checking - fgets
//       |     ^~~~
//       |     fgets
// /usr/bin/ld: /tmp/ccGWaxeg.o: in function `get_user_input':
// example.c:(.text+0x3c): warning: the `gets' function is dangerous and should not be used.