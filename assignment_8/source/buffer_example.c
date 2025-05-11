#include <stdio.h>
#include <string.h>

// takes number of given parameters, pointer to those variables
int main(int argc, char** argv)
{
    // allocates some memory (500 characters) on the stack
    char buffer[500];
    
    // copies string from argv (command line parameter) into buffer
    // causes buffer overflow if string is larger than 500
    strcpy(buffer, argv[1]); // "string copy"

    printf("%s\n", buffer);
    return 0;
}

/*
gcc -g ./source/buffer_example.c -o ./build/buffer_example
-g - generate debug information and symbols

gdb
- file ./build/buffer_example
- list (shows compiled function compiler included this information along with executable)
- help disas
- disas main - disassemble machine code / CPU instruction
    - sub allocating buffer
- run hello

- python3, A * 510
- run $(python3 -c 'print("\x41" * 506)')
*/
