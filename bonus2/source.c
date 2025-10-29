#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(int argc, char **argv)
{
    char buffer[76];
    char *env_lang;
    int lang = 0;

    if (argc != 3)
        return 1;

    memset(buffer, 0, 76);
    
    // Copy first 40 bytes of argv[1] to buffer
    strncpy(buffer, argv[1], 40);
    
    // Copy first 32 bytes of argv[2] to buffer[40]
    strncpy(&buffer[40], argv[2], 32);
    
    // Check LANG environment variable
    env_lang = getenv("LANG");
    if (env_lang != NULL)
    {
        if (memcmp(env_lang, "fi", 2) == 0)
            lang = 1;
        else if (memcmp(env_lang, "nl", 2) == 0)
            lang = 2;
    }
    
    // Call greetuser with combined buffer
    greetuser(buffer, lang);
    return 0;
}

void greetuser(char *user, int lang)
{
    char greeting[64];
    
    if (lang == 1)
        strcpy(greeting, "Hyvää päivää ");     // Finnish: 13 bytes
    else if (lang == 2)  
        strcpy(greeting, "Goedemiddag! ");     // Dutch: 13 bytes
    else
        strcpy(greeting, "Hello ");            // English: 6 bytes
    
    strcat(greeting, user);  // VULNERABLE: No bounds checking!
    puts(greeting);
}