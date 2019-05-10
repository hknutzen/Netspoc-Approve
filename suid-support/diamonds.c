/* Wrapper script for approve.pl
   This should be installed setuid and setgid
   to some dedicated user and group ID.
 */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

char program[] = "/usr/local/bin/approve.pl";

int main( int argc, char *argv[])
{
    return execv(program, argv);
}
