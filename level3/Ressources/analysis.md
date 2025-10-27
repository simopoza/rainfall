# Level3 Analysis

## Binary Information
- **File**: ELF 32-bit LSB executable, Intel 80386
- **Permissions**: -rwsr-s---+ 1 level4 users (SUID bit set for level4)
- **Size**: 5366 bytes
- **BuildID**: 09ffd82ec8efa9293ab01a8bfde6a148d3e86131

## Initial Behavior Analysis
- **Input/Output**: Program echoes back user input exactly
- **Buffer behavior**: No crash with very long inputs (tested with 600+ char pattern)
- **Functions**: printf(), fgets(), fwrite(), system()

## Assembly Analysis

### Main Function:
```asm
0x0804851a <+0>:    push   %ebp
0x0804851b <+1>:    mov    %esp,%ebp  
0x0804851d <+3>:    and    $0xfffffff0,%esp    # Stack alignment
0x08048520 <+6>:    call   0x80484a4 <v>       # Call v() function
0x08048525 <+11>:   leave  
0x08048526 <+12>:   ret    
```

### V Function (Main Logic):
```asm
0x080484a4 <+0>:    push   %ebp
0x080484a5 <+1>:    mov    %esp,%ebp
0x080484a7 <+3>:    sub    $0x218,%esp          # Allocate 536 bytes on stack
0x080484ad <+9>:    mov    0x8049860,%eax       # Load stdin
0x080484b2 <+14>:   mov    %eax,0x8(%esp)      
0x080484b6 <+18>:   movl   $0x200,0x4(%esp)    # Size = 512 bytes
0x080484be <+26>:   lea    -0x208(%ebp),%eax   # Buffer at EBP-520 (520 bytes)  
0x080484c4 <+32>:   mov    %eax,(%esp)
0x080484c7 <+35>:   call   0x80483a0 <fgets@plt>  # fgets(buffer, 512, stdin)

0x080484cc <+40>:   lea    -0x208(%ebp),%eax   # Load buffer address
0x080484d2 <+46>:   mov    %eax,(%esp)          
0x080484d5 <+49>:   call   0x8048390 <printf@plt>  # printf(buffer) - VULNERABILITY!

0x080484da <+54>:   mov    0x804988c,%eax       # Load global variable
0x080484df <+59>:   cmp    $0x40,%eax           # Compare with 64 (0x40)
0x080484e2 <+62>:   jne    0x8048518 <v+116>    # If not equal, exit

# If global variable == 64:
0x080484e4 <+64>:   mov    0x8049880,%eax       # Load another global
0x080484e9 <+69>:   mov    %eax,%edx
0x080484eb <+71>:   mov    $0x8048600,%eax      # Format string
0x080484f0 <+76>:   mov    %edx,0xc(%esp)
0x080484f4 <+80>:   movl   $0xc,0x8(%esp)       # Length = 12
0x080484fc <+88>:   movl   $0x1,0x4(%esp)       # Count = 1  
0x08048504 <+96>:   mov    %eax,(%esp)
0x08048507 <+99>:   call   0x80483b0 <fwrite@plt>  # fwrite()

0x0804850c <+104>:  movl   $0x804860d,(%esp)    # Command string
0x08048513 <+111>:  call   0x80483c0 <system@plt>  # system() call!
```

## Key Findings:
1. **Format String Vulnerability**: `printf(buffer)` without format specifier
2. **Global Variable Check**: Must modify variable at 0x804988c to equal 64 (0x40)  
3. **System Call**: If condition met, executes system() command
4. **Large Buffer**: 520 bytes, no buffer overflow risk with fgets() protection

## Exploitation Strategy:
- Use format string vulnerability to write value 64 to address 0x804988c
- This will trigger the system() call and likely spawn a shell