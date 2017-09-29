#include <sys/ptrace.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
//#include <glob.h>
#include <fnmatch.h>

const int long_size = sizeof(long);

/* This API takes a child to read from, and the address of the string it's going to read.
 * Borrowed from here -> 
 * https://blog.nelhage.com/2010/08/write-yourself-an-strace-in-70-lines-of-code
 */
char* read_string_from_child_addr_space(pid_t child, unsigned long addr) {
    char *val = (char*) malloc(1024);  // buffer to copy the string into
    int allocated = 1024, read = 0; // counters of how much data we've copied and allocated
    unsigned long tmp; // temporary variable for reading memory

    // We grow the buffer if necessary. We read data one word at a time.    
    while (1) {
        if (read + sizeof tmp > allocated) {
            allocated *= 2;
            val = (char*) realloc(val, allocated);
        }

        /* PTRACE_PEEKDATA returns a work of data from the child at the specified offset. 
         * Because it uses its return for the value, we need to check errno to tell if it failed. 
         * If it did (perhaps because the child passed an invalid pointer), 
         * we just return the string we've got so far, making sure to add our own NULL at the end.
         */
		 
        /* Note: PTRACE_PEEKDATA is for reading the data/code section of the child process.
         * PTRACE_PEEKUSER is to read the contents of the child's USER area 
		 * which holds contents of registers and other info. 
		 * sys/user.h lists what is that Other info.
		 */
        tmp = ptrace(PTRACE_PEEKDATA, child, addr + read);
        if(errno != 0) {
            val[read] = 0;
            break;
        }

        /* Then it's a simple matter of appending the data we read, 
         * and breaking out if we found a terminating NULL, or else looping to read another word.
         */
        memcpy(val + read, &tmp, sizeof(tmp));
        if (memchr(&tmp, 0, sizeof(tmp)) != NULL)
            break;
        read += sizeof(tmp);

    }
    return val;
}

void put_string_into_child_addr_space(pid_t child, long addr,
             char *str, int len)
{   char *laddr;
    int i, j;
    union u {
            long val;
            char chars[long_size];
    }data;
    i = 0;
    j = len / long_size;
    laddr = str;
    while(i < j) {
        memcpy(data.chars, laddr, long_size);
        ptrace(PTRACE_POKEDATA, child,
               addr + i * 4, data.val);
        ++i;
        laddr += long_size;
    }
    j = len % long_size;
    if(j != 0) {
        memcpy(data.chars, laddr, j);
        ptrace(PTRACE_POKEDATA, child,
               addr + i * 4, data.val);
    }
}

/* Bad implementation, we are reading the config file for each open system call */
void get_file_permission (FILE *config, char*filename, char *perm) {
  char glob[1024], temp_perm[4];
  perm[0] = perm[1] = perm[2] = '1';
  perm[3] = '\0';

  while (fscanf(config, "%s %s", temp_perm, glob) == 2) {
            if (fnmatch(glob, filename, FNM_PATHNAME) == 0) {
               // In case of a match, store the permission and keep checking till the end of the file.
               // We need the last match.
               strcpy(perm, temp_perm);    
               //printf("match found %s %s %s\n", filename, glob, perm);
            }
    }
    rewind(config);
}
