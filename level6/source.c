// Level6 Source Code Reconstruction
// Based on GDB disassembly analysis

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// Target function - calls system() to get flag
// Address: 0x08048454
void n() {
    // movl $0x80485b0,(%esp) - load command string
    // call 0x8048370 <system@plt>
    system("/bin/cat /home/user/level7/.pass");
}

// Default function - prints "Nope"  
// Address: 0x08048468
void m() {
    // movl $0x80485d1,(%esp) - load string address
    // call 0x8048360 <puts@plt>  
    puts("Nope");
}

// Main function with heap vulnerability
int main(int argc, char **argv) {
    char *buffer1;        // First heap allocation: 64 bytes
    void (**funcptr)();   // Second heap allocation: 4 bytes (function pointer)
    
    // Allocate heap buffers
    buffer1 = malloc(64);         // malloc(0x40)
    funcptr = malloc(4);          // malloc(0x4)
    
    // Initialize function pointer to m() (default behavior)
    *funcptr = m;                 // mov $0x8048468,%edx; mov %edx,(%eax)
    
    // VULNERABILITY: Unchecked strcpy from user input
    // Can overflow buffer1 and overwrite funcptr
    strcpy(buffer1, argv[1]);     // strcpy(buffer1, argv[1])
    
    // Call the function pointer - this is what we want to hijack
    (*funcptr)();                 // call *%eax
    
    return 0;
}

/*
HEAP EXPLOITATION STRATEGY:
===========================

The key insight is the heap memory layout after the two malloc() calls:

Memory Layout (simplified):
┌─────────────────┬──────────────┬─────────────────┐
│   buffer1       │ heap metadata │    funcptr     │
│   (64 bytes)    │  (8 bytes)    │   (4 bytes)    │
└─────────────────┴──────────────┴─────────────────┘
                                        ^
                                   Overwrite target

The strcpy() vulnerability allows us to overflow buffer1 and overwrite
the function pointer stored in funcptr.

Attack Steps:
1. Calculate exact offset from buffer1 start to funcptr location
2. Create payload: padding + target_address
3. Target address = 0x08048454 (function n)
4. When (*funcptr)() executes, it calls n() instead of m()
5. Function n() calls system() to reveal the flag

Heap Metadata:
- On 32-bit systems, typical heap chunk header is 8 bytes
- So funcptr is likely at buffer1 + 64 + 8 = 72 bytes offset
- May need to test different offsets (68, 70, 72, 74, 76) to find exact location

The beauty of this attack:
- No need for shellcode injection
- No need for complex ROP chains  
- Simple function pointer overwrite
- Uses existing code (function n) to achieve our goal
*/