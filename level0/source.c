/* pseudo-source for level0 */


#include <stdlib.h>
#include <unistd.h>
#include <string.h>


int main(int argc, char **argv) {
    /* Program expects a numeric argument */
    int n = atoi(argv[1]); /* crashes if argv[1] == NULL */


    /* If magic number (0x1A7 == 423) is provided, escalate to level1 */
    if (n == 0x1A7) {
        char *path = strdup("/bin/sh"); /* duplicated string used for execv */
        /* adopt UID/GID of binary owner (setuid binary owned by level1) */
        setresgid(getegid(), getegid(), getegid());
        setresuid(geteuid(), geteuid(), geteuid());
        /* exec a shell as level1 */
        execv(path, (char * const *)&path);
    } else {
        /* otherwise print "No !" and exit */
        fwrite("No !\n", 1, 4, stdout);
    }
    return 0;
}