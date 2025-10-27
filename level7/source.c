// Level7 Source Code Reconstruction
// Based on GDB disassembly analysis

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

// Linked list node structure (8 bytes total)
typedef struct {
    int value;      // 4 bytes - node identifier
    char *data;     // 4 bytes - pointer to allocated data buffer  
} node_t;

// Function m() - TARGET FUNCTION (never called normally)
// Address: 0x080484f4
void m() {
    time_t current_time = time(NULL);
    
    // CRITICAL: Uses the same buffer where fgets() stored the flag!
    // Format string at 0x80486e0, buffer at 0x8049960, time value
    printf("%s - %lu\n", (char*)0x8049960, current_time);
}

int main(int argc, char **argv) {
    node_t *node1, *node2;
    FILE *file;
    
    // === HEAP ALLOCATION PHASE ===
    
    // Create first linked list node
    node1 = malloc(8);           // sizeof(node_t) = 8 bytes
    node1->value = 1;            // Set node identifier  
    node1->data = malloc(8);     // Allocate 8 bytes for string data
    
    // Create second linked list node
    node2 = malloc(8);           // sizeof(node_t) = 8 bytes  
    node2->value = 2;            // Set node identifier
    node2->data = malloc(8);     // Allocate 8 bytes for string data
    
    // === VULNERABILITY PHASE ===
    
    // VULNERABLE: strcpy without bounds checking!
    // Both copy into 8-byte allocations - can overflow into adjacent memory
    strcpy(node1->data, argv[1]);    // Can overflow node1->data buffer
    strcpy(node2->data, argv[2]);    // Can overflow node2->data buffer  
    
    // === FILE OPERATION PHASE ===
    
    // Open level8 password file (filename at 0x80486eb)
    file = fopen("/home/user/level8/.pass", "r");
    
    // Read flag into global buffer at 0x8049960 (68 bytes max)
    fgets((char*)0x8049960, 68, file);
    
    // Print status message and exit normally
    puts("~~");
    
    return 0;
}

/*
EXPLOITATION STRATEGY:
======================

The program reads the level8 password but never displays it! However, 
function m() exists and would print the buffer contents if called.

Key insight: We need to redirect execution to function m() through heap corruption.

Heap Memory Layout (4 consecutive allocations):
┌──────────────┬──────────────┬──────────────┬──────────────┐
│    node1     │ node1->data  │    node2     │ node2->data  │
│  (8 bytes)   │  (8 bytes)   │  (8 bytes)   │  (8 bytes)   │
│ value=1      │ strcpy dest  │ value=2      │ strcpy dest  │
│ data=ptr ────┼─────────────▶│ data=ptr ────┼─────────────▶│
└──────────────┴──────────────┴──────────────┴──────────────┘

Overflow Attack Vector:
- argv[1] longer than 8 bytes overflows node1->data into node2 structure
- We can overwrite node2->value and node2->data pointer
- If we can control node2->data to point to a function address...
- Need to find where/how execution can be redirected to m()

Possible attack methods:
1. Overwrite node2->data to point to function m() address
2. Look for indirect calls through data pointers  
3. Corrupt heap metadata to redirect malloc/free operations
4. Find format string vulnerabilities in function m()

Function m() address: 0x080484f4
Target: Somehow call m() to display the flag buffer at 0x8049960

Analysis needed:
- Exact heap layout and allocation order
- How node structures are used after strcpy operations
- Whether any indirect calls use the data pointers
- Heap metadata structure and corruption possibilities
*/