# Level2 Analysis

## Binary Information
- 32-bit ELF executable with setuid bit (level3 privileges)
- Uses dangerous `gets()` function - classic buffer overflow vulnerability
- Stack canary protection: NO
- NX bit: Likely DISABLED (old system from 2016)

## Key Findings

### Buffer Overflow Details
- Buffer size: 76 bytes (allocated at -0x4c from ebp)
- Offset to EIP: 80 bytes (confirmed with pattern)
- Crash EIP: 0x37634136 (corresponds to "6Ac7" in the pattern)

### Security Mechanism
The program checks if the return address is in stack memory range:
```
ret_addr & 0xb0000000 == 0xb0000000
```
This prevents simple stack-based shellcode injection!

### Memory Layout
```
[buffer - 76 bytes][saved ebp - 4 bytes][return address - 4 bytes]
                   ^                     ^
                   offset 76            offset 80
```

## Vulnerability Analysis
1. **Buffer Overflow**: `gets()` allows unlimited input
2. **Stack Protection Bypass**: The check prevents stack addresses (0xbXXXXXXX)
3. **Heap Opportunity**: `strdup()` allocates our input on the heap

## Exploitation Strategy Options
1. **Return-to-libc**: Use addresses in libc (not stack)
2. **Heap Shellcode**: Place shellcode on heap via strdup(), jump to heap
3. **ROP Chain**: Return-oriented programming

The most elegant approach is **heap shellcode** since:
- Heap addresses start with 0x0XXXXXXX (bypass stack check)
- Our input gets copied to heap via strdup()
- We control both the shellcode content and return address

## Heap Address Discovery
**Heap base address: 0x804a008**
- Confirmed via GDB: `x/x $eax` after strdup() returns 0x804a008
- This address bypasses the stack check (0x0804XXXX != 0xb0000000)
- Our shellcode will be placed at this exact location