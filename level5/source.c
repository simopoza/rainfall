// Level5 Source Code Reconstruction
// Based on GDB disassembly analysis

#include <stdio.h>
#include <stdlib.h>

// Function o() - Target function that calls system()
// Address: 0x080484a4
void o() {
    // movl $0x80485f0,(%esp) - loads command string
    // call 0x80483b0 <system@plt>
    system("/bin/sh");  // Command at 0x80485f0 is likely "/bin/sh"
    
    // movl $0x1,(%esp)
    // call 0x8048390 <_exit@plt>
    _exit(1);
}

// Function n() - Main logic with vulnerability  
// Address: 0x080484c2
void n() {
    char buffer[512];   // Buffer size from: movl $0x200,0x4(%esp)
    
    // fgets(buffer, 512, stdin)
    fgets(buffer, 512, stdin);
    
    // VULNERABILITY: Direct printf without format specifier
    printf(buffer);
    
    // Program always exits here - we need to hijack this
    exit(1);
}

// Main function
// Address: 0x08048504  
int main() {
    // Simple call to n()
    n();
    return 0;
}

/*
EXPLOITATION STRATEGY:
======================

The key insight is that function o() exists but is never called in normal execution.
However, o() contains a system() call which is our goal.

The program flow is:
main() -> n() -> fgets() -> printf() -> exit(1)

The format string vulnerability in printf(buffer) allows us to write arbitrary 
values to arbitrary memory addresses using %n.

Attack Vector: GOT (Global Offset Table) Overwrite
- Overwrite the GOT entry for exit() to point to o() instead
- When exit(1) is called, execution jumps to o()
- o() calls system("/bin/sh") giving us a shell

Implementation:
1. Find GOT address of exit() (typically around 0x804a000 range)
2. Find stack position where our input buffer appears
3. Use format string %n to write address of o() (0x080484a4) to exit GOT
4. When exit(1) executes, it jumps to o() -> system() -> shell

This is more elegant than overwriting return addresses because:
- No need to calculate exact stack offsets
- GOT entries are at predictable, static addresses  
- The program naturally calls exit() for us
*/