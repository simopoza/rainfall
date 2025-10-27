# Level7 Analysis - Advanced Heap Exploitation with Linked Lists

## Initial Observations

### Binary Information
- **File**: ELF 32-bit LSB executable, Intel 80386
- **Permissions**: -rwsr-s---+ 1 level8 users (SUID bit set for level8)
- **Size**: 5648 bytes
- **Key Functions**: malloc(), strcpy(), printf(), fgets(), time(), fopen(), puts(), main(), m()

### Behavioral Analysis
- **No arguments**: Segmentation fault (accessing NULL pointers)
- **One argument**: Segmentation fault (missing second argument)
- **Two arguments**: Prints "~~" and exits normally
- **Pattern**: Requires exactly 2 arguments to avoid crashes

## Assembly Analysis - Complex Heap Operations

### Main Function Analysis:

```asm
# Function main creates linked list structures
0x08048521 <+0>:    push   %ebp
0x08048522 <+1>:    mov    %esp,%ebp
0x08048524 <+3>:    and    $0xfffffff0,%esp
0x08048527 <+6>:    sub    $0x20,%esp

# First linked list node creation
0x0804852a <+9>:    movl   $0x8,(%esp)         # malloc(8)
0x08048531 <+16>:   call   0x80483f0 <malloc@plt>
0x08048536 <+21>:   mov    %eax,0x1c(%esp)     # Store node1 pointer
0x0804853a <+25>:   mov    0x1c(%esp),%eax     # Get node1 pointer  
0x0804853e <+29>:   movl   $0x1,(%eax)         # node1->value = 1

0x08048544 <+35>:   movl   $0x8,(%esp)         # malloc(8) for data
0x0804854b <+42>:   call   0x80483f0 <malloc@plt>
0x08048550 <+47>:   mov    %eax,%edx           # Get data pointer
0x08048552 <+49>:   mov    0x1c(%esp),%eax     # Get node1 pointer
0x08048556 <+53>:   mov    %edx,0x4(%eax)      # node1->data = data_ptr

# Second linked list node creation  
0x08048559 <+56>:   movl   $0x8,(%esp)         # malloc(8)
0x08048560 <+63>:   call   0x80483f0 <malloc@plt>
0x08048565 <+68>:   mov    %eax,0x18(%esp)     # Store node2 pointer
0x08048569 <+72>:   mov    0x18(%esp),%eax     # Get node2 pointer
0x0804856d <+76>:   movl   $0x2,(%eax)         # node2->value = 2

0x08048573 <+82>:   movl   $0x8,(%esp)         # malloc(8) for data
0x0804857a <+89>:   call   0x80483f0 <malloc@plt>
0x0804857f <+94>:   mov    %eax,%edx           # Get data pointer
0x08048581 <+96>:   mov    0x18(%esp),%eax     # Get node2 pointer
0x08048585 <+100>:  mov    %edx,0x4(%eax)      # node2->data = data_ptr

# FIRST STRCPY - argv[1] to node1->data
0x08048588 <+103>:  mov    0xc(%ebp),%eax      # Get argv
0x0804858b <+106>:  add    $0x4,%eax          # argv[1]
0x0804858e <+109>:  mov    (%eax),%eax        # Dereference argv[1]
0x08048590 <+111>:  mov    %eax,%edx          # Source: argv[1]
0x08048592 <+113>:  mov    0x1c(%esp),%eax    # Get node1 pointer
0x08048596 <+117>:  mov    0x4(%eax),%eax     # Get node1->data
0x08048599 <+120>:  mov    %edx,0x4(%esp)     # strcpy source
0x0804859d <+124>:  mov    %eax,(%esp)        # strcpy destination
0x080485a0 <+127>:  call   0x80483e0 <strcpy@plt>  # strcpy(node1->data, argv[1])

# SECOND STRCPY - argv[2] to node2->data  
0x080485a5 <+132>:  mov    0xc(%ebp),%eax      # Get argv
0x080485a8 <+135>:  add    $0x8,%eax          # argv[2]
0x080485ab <+138>:  mov    (%eax),%eax        # Dereference argv[2]
0x080485ad <+140>:  mov    %eax,%edx          # Source: argv[2]
0x080485af <+142>:  mov    0x18(%esp),%eax    # Get node2 pointer
0x080485b3 <+146>:  mov    0x4(%eax),%eax     # Get node2->data
0x080485b6 <+149>:  mov    %edx,0x4(%esp)     # strcpy source
0x080485ba <+153>:  mov    %eax,(%esp)        # strcpy destination
0x080485bd <+156>:  call   0x80483e0 <strcpy@plt>  # strcpy(node2->data, argv[2])

# File operations
0x080485c2 <+161>:  mov    $0x80486e9,%edx     # File mode "r"
0x080485c7 <+166>:  mov    $0x80486eb,%eax     # Filename
0x080485cc <+171>:  mov    %edx,0x4(%esp)      # fopen mode
0x080485d0 <+175>:  mov    %eax,(%esp)         # fopen filename  
0x080485d3 <+178>:  call   0x8048430 <fopen@plt>  # fopen(filename, "r")

0x080485d8 <+183>:  mov    %eax,0x8(%esp)      # File handle
0x080485dc <+187>:  movl   $0x44,0x4(%esp)     # Size: 68 bytes
0x080485e4 <+195>:  movl   $0x8049960,(%esp)   # Buffer address
0x080485eb <+202>:  call   0x80483c0 <fgets@plt>  # fgets(buffer, 68, file)

0x080485f0 <+207>:  movl   $0x8048703,(%esp)   # Load "~~" string
0x080485f7 <+214>:  call   0x8048400 <puts@plt>   # puts("~~")
```

### Function m() Analysis:
```asm
0x080484f4 <+0>:    push   %ebp
0x080484f5 <+1>:    mov    %esp,%ebp  
0x080484f7 <+3>:    sub    $0x18,%esp
0x080484fa <+6>:    movl   $0x0,(%esp)         # time(NULL)
0x08048501 <+13>:   call   0x80483d0 <time@plt>
0x08048506 <+18>:   mov    $0x80486e0,%edx     # Format string address
0x0804850b <+23>:   mov    %eax,0x8(%esp)      # time result
0x0804850f <+27>:   movl   $0x8049960,0x4(%esp) # Buffer address (same as fgets!)
0x08048517 <+35>:   mov    %edx,(%esp)         # Format string
0x0804851a <+38>:   call   0x80483b0 <printf@plt>  # printf(format, buffer, time)
```

## Initial Source Code Reconstruction
```c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

// Structure appears to be a simple linked list node
typedef struct {
    int value;      // 4 bytes
    char *data;     // 4 bytes pointer to allocated data
} node_t;

void m() {
    time_t current_time = time(NULL);
    // printf uses buffer at 0x8049960 - same buffer used by fgets!
    printf("%s - %lu\n", (char*)0x8049960, current_time);  // Format string at 0x80486e0
}

int main(int argc, char **argv) {
    node_t *node1, *node2;
    
    // Create first linked list node
    node1 = malloc(8);           // sizeof(node_t) = 8 bytes
    node1->value = 1;
    node1->data = malloc(8);     // 8 bytes for data storage
    
    // Create second linked list node  
    node2 = malloc(8);           // sizeof(node_t) = 8 bytes
    node2->value = 2;
    node2->data = malloc(8);     // 8 bytes for data storage
    
    // VULNERABLE: Copy user input without bounds checking
    strcpy(node1->data, argv[1]);  // Can overflow 8-byte allocation!
    strcpy(node2->data, argv[2]);  // Can overflow 8-byte allocation!
    
    // File operations - reads into global buffer
    FILE *file = fopen("/home/user/level8/.pass", "r");  // Filename at 0x80486eb
    fgets((char*)0x8049960, 68, file);  // Read flag into buffer
    
    puts("~~");
    return 0;
}
```

## Key Findings

### Vulnerability Analysis
- **Heap Buffer Overflows**: Both strcpy() calls copy into 8-byte allocations without bounds checking
- **Linked List Structure**: Four total allocations creating two nodes with data pointers
- **Global Buffer**: Address 0x8049960 used by both fgets() and function m()
- **Function m() exists**: Contains printf() that could display the global buffer

### Memory Layout
```
Heap Layout (4 allocations):
[node1: 8 bytes] [node1->data: 8 bytes] [node2: 8 bytes] [node2->data: 8 bytes]
       │                │                      │                │
       └─ value=1        └─ strcpy(argv[1])    └─ value=2       └─ strcpy(argv[2])
          data=ptr          VULNERABLE            data=ptr          VULNERABLE
```

### Attack Vectors
1. **Heap Overflow**: argv[1] or argv[2] longer than 8 bytes can corrupt adjacent memory
2. **Function Pointer Corruption**: If we can overwrite node2 structure, we might control execution
3. **Global Buffer Access**: Function m() can display the flag read by fgets()

## Strategic Insight
The program reads the level8 password into a global buffer but never calls function m() to display it. We need to find a way to redirect execution to function m() through heap corruption!