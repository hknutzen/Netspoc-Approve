/* Wrapper script for newpolicy.pl
   This should be installed setuid and setgid
   to some dedicated user and group ID.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

char program[] = "/home/MGMT/knutzehe-admin/Netspoc-Approve/bin/newpolicy.pl";

int main( int argc, char *argv[])
{
    char cvsroot[100] = "CVSROOT=";
    char lang[100] = "LANG=";
    char *ptr = getenv("CVSROOT");
    if (ptr) {
      strncat(cvsroot, ptr, sizeof(cvsroot)-sizeof("CVSROOT")-2);
    }
    ptr = getenv("LANG");
    if (ptr) {
      strncat(lang, ptr, sizeof(lang)-sizeof("LANG")-2);
    }

    char *empty[] = { NULL };
    char *env[] = { cvsroot, lang, NULL };

    /* Call with empty argument vector and new environment. */
    return execve(program, empty, env);
}
