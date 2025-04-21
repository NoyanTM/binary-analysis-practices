#include <Windows.h>
#include <stdio.h>

int main() {
    if (IsDebuggerPresent()) {
        printf("Debugger detected!\n");
        return 1;
    } else {
        printf("Running normally.\n");
    }
    MessageBoxA(0, "Success", "Info", MB_OK);
    return 0;
}

/*
bool fs_chk(VOID)
{
    char IsDbgPresent = 0;
    __asm {
        // fs - segment register which allow to access TEB structure
        // there is reference to PEB structure in address 30h / 0x30 offset
        // store reference to / address of / pointer to PEB in eax
        mov eax, fs:[30h]

        // dereference eax with offset 0x02 (second byte of the structure), which is BeingDebugged field
        // store it in al, because single byte of the flag
        mov al, [eax + 2h]

        // store al to IsDbgPresent variable
        mov IsDbgPresent, al
    }
    if(IsDbgPresent)
    {
        return TRUE;
    }
    return FALSE;
}
*/
