# Task 6 - Analyzing packers: packing and manula unpacking with UPX

## Description and theory
1. Objective: understand how executable packers work, use the UPX packer to compress an executable, and manually unpack it using a debugger.
2. Packer - software that is commonly used by both malware authors and by those wanting to protect their intellectual property. It works by obfuscating its code and compressing the binary to packed binary. 
3. Usually the the payload of the binary is either encrypted or encoded and is decoded or decrypted and then executed at run time. The packing process would usually follow the following oversimplified steps: packer compress the contents or payload of the binary -> packer then insert an unpacking stub which will be called to unpack the binary and return execution to the OEP (Original Entry Point) -> packer then modify the entry point of the binary to point to unpacking stub's location -> packer will produce a packed binary.
4. Unpacking stub: When the binary is executed, the Operating System will load the unpacking stub which in turn will unpack and load the original executable. Easy right? Let's dive in a bit deeper. The OEP (Original Entry Point) code will point to the location where the unpacking stub is stored. This means when the OEP is executed, it will jump to another region of code which will unpack the original executable and then resume execution of it.
5. Manual unpacking:
   - We will run the packed binary to let the unpacking stub unpack the binary for us and then dump the process to disc and manually fix the PE header. The general steps are:
     - Determine the OEP which is the first instruction before packing. We need to find the instruction that will jump to the OEP from within the packed binary.
     - Execute the program until we reach the OEP and then let the malware unpack itself in memory and pause execution at the OEP. This will land us right before the unpacked malicious code.
     - Next we will be able to dump the unpacked process in memory and save it to disc.
     - Lastly, we can fix the IAT table of the dumped file so that we can then resolve the imports.

## Solution and practice
1. Used [C compiler (MinGW for x86_32)](https://sourceforge.net/projects/mingw/), [UPX packer or other packer](https://github.com/upx/upx), [Debugger (x64dbg)](https://github.com/x64dbg/x64dbg), PE Analyzer ([PE-bear](https://github.com/hasherezade/pe-bear), CFF Explorer, or similar)
2. Write and compiler simple executable and run it: gcc example.c -o example.exe, .\example.exe
3. Apply packer to the binary file, it should still work normally even though the code is now packed: upx example.exe

4. Analyze the packed file with PE-bear (winget install pe-bear):
   - Sections UPX0, UPX1 indicate UPX-packed content (typical sections like .text, .data are no longer visible)
   - There are usefull indicators for initial assessment in order to determine if the binary is packed: overall high entropy. It is measure of randomness and the higher the entropy the more random the data is, usually indicating that it is encoded or encrypted. The rule of thumb is that, if the entropy is 6.5 and above this is an indicator that the sample may be packed. Another easy to spot indicator is the signature, which in this case is of UPX which hints that it may be UPX packed.

5. Debugging with x32dbg/x64dbg:
   - Obfuscated code with UPX stub (decompressor)
   - Checked with setting breackpoints at entry point and trace execution, until reaching real unpacked code (original entry point, OEP)
   - Manual unpacking
Keep tracing until the unpacked code is loaded into memory.
When you reach readable, meaningful assembly instructions, dump the memory:
In x64dbg: File → Dump Memory
Use an import fixer (e.g., [Scylla](https://github.com/x64dbg/ScyllaHide/) or Import REConstructor) to restore the IAT.
Save the final dump as hello_unpacked.exe.

6. Verifying the Result
Run hello_unpacked.exe to verify it behaves like the original.
Open it in a PE analyzer to confirm that typical sections like .text, .rdata, etc., are restored.
