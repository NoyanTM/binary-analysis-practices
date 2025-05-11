#include <stdio.h>
#include <string.h>

void secret() {
    printf("Access granted! Exploit successful.\n");
    system("/bin/sh");
}

void vulnerable() {
    char buffer[64];
    printf("Enter your name: ");
    gets(buffer);  // vulnerable function
    printf("Hello, %s\n", buffer);
}

int main() {
    vulnerable();
    return 0;
}