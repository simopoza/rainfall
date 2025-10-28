# Level8 Analysis

## Program Structure

This is a command-line interface program that accepts 4 different commands:
- `auth <username>` 
- `service<service_name>`
- `reset`
- `login`

## Key Components

### Global Variables
- `auth` at 0x8049aac - pointer to malloc'd memory for authentication data
- `service` at 0x8049ab0 - pointer to malloc'd memory for service data

### Commands Analysis

#### 1. "auth " command (0x8048819)
- Allocates 4 bytes with `malloc(4)` 
- Sets `auth` pointer to this memory
- Initializes `*auth = 0`
- If username length <= 30 chars, copies username to `auth` using `strcpy()`
- **Vulnerability**: `strcpy()` with no bounds checking on 4-byte allocation!

#### 2. "reset" command (0x804881f)
- Calls `free(auth)` to deallocate auth memory
- Does NOT set `auth = NULL` (use-after-free vulnerability)

#### 3. "service" command (0x8048825) 
- Calls `strdup()` on input after "service" (position +7)
- Stores result in `service` global variable
- **Note**: `strdup()` allocates memory and copies string

#### 4. "login" command (0x804882d)
- **Critical check**: `if (auth[8] != 0)` at address 0x080486e7
- If condition passes: calls `system("/bin/sh")` 
- If condition fails: prints "Password:\\n"

## The Vulnerability

The key insight is in the `login` command check at `0x080486e7`:
```asm
mov    0x8049aac,%eax     ; Load auth pointer
mov    0x20(%eax),%eax    ; Load auth[32] (0x20 = 32 bytes offset)
test   %eax,%eax          ; Check if auth[32] != 0
```

This checks 32 bytes past the `auth` pointer, not the auth data itself!

## Heap Layout Discovery

From testing:
- `auth test` → auth = 0x804a008 (malloc(4))
- `service abc` → service = 0x804a018 (strdup allocation)
- Offset between them: 0x804a018 - 0x804a008 = 0x10 (16 bytes)

The login check looks at `auth + 0x20` (32 bytes), but service is only at `auth + 0x10` (16 bytes).

## Exploitation Strategies

### Strategy 1: Use-After-Free with Reset
1. `auth <name>` - allocate auth
2. `reset` - free auth (but pointer remains)
3. `service <data>` - might reuse freed auth memory
4. If service reuses auth memory + 32 bytes, login succeeds

### Strategy 2: Heap Overflow via strcpy
1. `auth <long_name>` - trigger strcpy overflow on 4-byte buffer
2. Overflow could overwrite heap metadata
3. Subsequent allocations might land at predictable offsets

### Strategy 3: Multiple Services
1. `auth <name>` 
2. Multiple `service` commands to allocate at the right offset
3. Need service allocation to land exactly at `auth + 32`

## Memory Layout Goal

```
auth (4 bytes) + 28 bytes heap data + service data (at auth+32)
```