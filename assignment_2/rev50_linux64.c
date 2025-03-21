#include <stdio.h>
#include <string.h>
#include <stdlib.h>

void usage(const char* program_name)
{
    printf("USAGE: %s <password>\n", program_name);
    puts("try again!");
    exit(0);
}

// int argc - count of arguments (first argument is binary itself - like ./rev50_linux.o)
// char **argv / char *argv[] - arguments
int main(int argc, char **argv)
{
    if (argc != 2) {
        usage(argv[0]);
    }
    size_t arg1_length = strlen(argv[1]);
    
    // edited part
    puts("Nice job!!");
    printf("flag{%s}\n", argv[1]);
    
    // if (arg1_length == 10) {
    //     if (argv[1][4] == '@') {
    //         puts("Nice job!!");
    //         printf("flag{%s}\n", argv[1]);
    //     } else {
    //         usage(argv[0]);
    //     }
    // } else {
    //     usage(argv[0]);
    // }

    return 0;
}