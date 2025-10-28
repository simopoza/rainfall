#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

// Global variables
char *auth = NULL;    // 0x8049aac
char *service = NULL; // 0x8049ab0

int main()
{
    char buffer[128];
    
    while (1) {
        // Print current pointer values
        printf("%p, %p \n", auth, service);

        // Read command from stdin
        if (fgets(buffer, 128, stdin) == NULL)
            break;
            
        // Parse "auth " command
        if (strncmp(buffer, "auth ", 5) == 0) {
            auth = malloc(4);        // Allocate only 4 bytes!
            *((int*)auth) = 0;       // Initialize to 0
            
            // Get username (starts at buffer[5])
            char *username = buffer + 5;
            
            // Check length <= 30 characters  
            if (strlen(username) <= 30) {
                strcpy(auth, username);  // VULNERABILITY: strcpy into 4-byte buffer!
            }
        }
        
        // Parse "reset" command
        else if (strncmp(buffer, "reset", 5) == 0) {
            free(auth);
            // BUG: auth pointer not set to NULL (use-after-free)
        }
        
        // Parse "service" command  
        else if (strncmp(buffer, "service", 7) == 0) {
            char *service_name = buffer + 7;
            service = strdup(service_name);  // Allocate and copy
        }
        
        // Parse "login" command
        else if (strncmp(buffer, "login", 5) == 0) {
            // CRITICAL CHECK: Look 32 bytes past auth pointer
            if (auth[32] != 0) {         // This is auth + 0x20 offset!
                system("/bin/sh");       // SUCCESS - spawn shell
            } else {
                fwrite("Password:\n", 1, 10, stdout);
            }
        }
    }
    
    return 0;
}

/*
VULNERABILITY ANALYSIS:

1. The auth buffer is only 4 bytes but strcpy has no bounds checking
2. The login check looks at auth[32] which is way past the allocated buffer
3. We need to manipulate heap layout so that auth[32] contains non-zero data

EXPLOITATION STRATEGIES:

1. Heap Layout Manipulation:
   - Use multiple service allocations to place data at auth + 32 offset
   - Current observation: services allocate 16 bytes apart
   - Need to find way to get allocation exactly at auth + 32

2. Use-After-Free:  
   - Use auth, then reset (free but don't nullify pointer)
   - Subsequent allocations might reuse memory and create right conditions

3. strcpy Overflow:
   - Though there's a 30-char limit, the buffer is only 4 bytes
   - Overflow could corrupt heap metadata and affect subsequent allocations
*/