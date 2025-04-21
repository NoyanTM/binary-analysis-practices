#include <windows.h>
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
Compile as test.exe.
4.2. Behavior
When run normally, the program shows "Success" in a message box.
When run in x64dbg, it prints "Debugger detected!" and exits.

4.3. Bypassing in a Debugger
Load test.exe in x64dbg.
Find the CALL IsDebuggerPresent instruction.
Patch the result to always return 0 or bypass the JNZ instruction.
Example:
CALL DWORD PTR DS:[<&KERNEL32.IsDebuggerPresent>]
TEST EAX, EAX
JNZ SHORT skip
→ Replace JNZ with JMP, or set EAX = 0 before TEST.
Continue execution – the message box should appear.

4.4. Patching the Binary
Let’s permanently disable anti-debugging by patching the binary.
Steps:
In x64dbg, find the address of CALL IsDebuggerPresent.
Replace the call and conditional jump with:
MOV EAX, 0
NOP
NOP
JMP <success_branch>
Or simply NOP out the call and force execution into the “normal” flow.
Save the patched executable via File → Patch file.
*/
