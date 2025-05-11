#include <stdio.h>

// vulnerable to buffer overflow
int main(int argc, char** argv)
{
    char data_buffer[0x100];
    FILE *fp = fopen(argv[1], "r"); // path to file like "./data/some_file"

    // reads in HEX 100 more bytes than the buffer has room
    // real world scenario it can also happen for example when: calculating things in buffer space, remaining in a operation that requires multiple reads
    /*
    but when stack canaries enabled in GCC
    (if we give program mode data than it has room for the program,
    it will gracefully fail with stack overflow detected)
    */
    fgets(data_buffer, 0x200, fp);
    return 0;
}

/*
when we run this program - there will be stack smashing detected information
- instead of full crash, semi-gracefull fail
- 
*/