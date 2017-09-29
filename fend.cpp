#include <sys/ptrace.h>
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <err.h>
#include <sys/user.h>
#include <asm/ptrace.h>
#include <sys/wait.h>
#include <asm/unistd.h>
#include <signal.h>
#include <string.h>
#include <errno.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/reg.h>  
#include <sys/syscall.h>   /* For SYS_open etc */
#include <sys/stat.h>
#include <fcntl.h>
#include <linux/limits.h>

FILE *config_file;
char* read_string_from_child_addr_space(pid_t child, unsigned long addr);
void put_string_into_child_addr_space(pid_t child, long addr, char *str, int len);
void get_file_permission (FILE *config, char*filename, char *perm);

/*Application framework borrowed from:
 *https://github.com/t00sh/p-sandbox/blob/master/p-sandbox.c
 */

struct sandbox {
		pid_t child;
		const char *progname;
};

void sandb_cleanup () {
		fclose(config_file);   
}

void sandb_kill (struct sandbox *sandb) {
		kill(sandb->child, SIGKILL);
		wait(NULL);
		sandb_cleanup();
		exit(EXIT_FAILURE);
}

void sandb_init (struct sandbox *sandb, int argc, char **argv) {
		pid_t pid;

		/* We are using the ptrace() system call to enables the parent/tracer process
		 * to control the execution of the child/tracee process.
		 * The traced process behaves normally until a signal is caught. 
		 * When that occurs the process enters stopped state and informs 
		 * the tracing process by a wait() call. 
		 * Then tracing process decides how the traced process should respond. 
		 * The only exception is SIGKILL which will kill the child process.
		 */
		pid = fork();

		/* A process can initiate a trace by calling fork() and having the
		 * resulting child do a PTRACE_TRACEME, followed (typically) by an
		 * execve(). Alternatively, one process may commence tracing another
		 * process using PTRACE_ATTACH or PTRACE_SEIZE.
		 */
		if (pid == -1) {
				sandb_cleanup();
				exit(EXIT_FAILURE);
		}
		if (pid == 0) {
				// child process executing
				if(ptrace(PTRACE_TRACEME, 0, NULL, NULL) < 0) {
						sandb_cleanup();
						exit(EXIT_FAILURE);
				}
				/* If the current program is being ptraced, 
				 * a SIGTRAP is sent to it after a successful execve(). 
				 */
				if(execv(argv[0], argv) < 0) {
						sandb_cleanup();
						exit(EXIT_FAILURE);
				}
		} else {
				// parent process executing
				sandb->child = pid;
				sandb->progname = argv[0];
		}
}

void sandb_handle_syscall (struct sandbox *sandb) {
		static int insyscall = 0, change_filename = 0;
		struct user_regs_struct regs;
		unsigned long flags, filename_addr = 0;
		char *filename, abspath[PATH_MAX], symbolic_link[PATH_MAX], perm[4];
		int is_path_relative_to_fd = 0;

		/* We will monitor all system calls 
		 * that accept a filepath as an argument
		 */
		bool check_read = 0, check_write = 0, check_exec = 0;

		/* This ptrace request involves reading the general purpose register 
		 * values for the child process. 
		 * Alternatively, we can use PTRACE_PEEKUSER request.
		 * Example: ptrace(PTRACE_PEEKUSER, sandb->child, 8 * ORIG_RAX, NULL) 
		 */   
		if(ptrace(( __ptrace_request)PTRACE_GETREGS, sandb->child, NULL, &regs) < 0) {
				sandb_cleanup();
				exit(EXIT_FAILURE);
		}

		/* regs.orig_rax contains the system call number.
		 * On some architectures, the syscall number lives in %eax.
		 * Ptrace needs to be able to read the register state before syscall and after it; 
		 * The return value from the syscall is written to %eax or %rax,
		 * and the original eax/rax, prior to the syscall is saved in orig_eax/orig_rax field.

		 * On x86_64 architecture, following registers are used to store the syscall arguments:
		 * regs.rdi - Stores the first argument
		 * regs.rsi - Stores the second argument
		 * regs.rdx - Stores the third argument
		 * regs.r10 - Stores the fourth argument
		 * regs.r8 - Stores the fifth argument
		 * regs.r9 - Stores the sixth argument   
		 */

		switch(regs.orig_rax) {
				case SYS_open:
				case SYS_creat:
				case SYS_mkdir:
						filename_addr = regs.rdi;
						flags = regs.rsi;
						check_read = 1;      
						if (flags & O_WRONLY) {
								check_write = 1;  
								check_read = 0;
						} else if (flags & O_RDWR)
								check_write = 1;
						//printf("open or mkdir\n");
						break;
				case SYS_openat:
				case SYS_mkdirat:
						is_path_relative_to_fd = 1;
						flags = regs.rdx; 
						filename_addr = regs.rsi;
						check_read = 1;
						if (flags & O_WRONLY) {
								check_write = 1;
								check_read = 0;
						} else if (flags & O_RDWR)
								check_write = 1;
						//printf("openat or mkdirat. FD is %llu\n", regs.rdi);
						break;
				case SYS_unlink:
				case SYS_rmdir:
						filename_addr = regs.rdi;
						check_write = 1;
						//printf("unlink or rmdir\n");
						break;
				case SYS_unlinkat:
						is_path_relative_to_fd = 1;
						filename_addr = regs.rsi;
						check_write = 1;
						//printf("unlinkat \n");
						break;
				case SYS_chmod:
				case SYS_chown:
				case SYS_lchown:
						filename_addr = regs.rdi;
						check_write = 1;
						//printf("chmod or chown\n");
						break;
				case SYS_fchmodat:
				case SYS_fchownat:
						is_path_relative_to_fd = 1;
						filename_addr = regs.rsi;
						check_write = 1;
						//printf("fchmodat or fchownat\n");
						break;
				case SYS_chdir:
						filename_addr = regs.rdi;
						check_exec = 1;
						//printf("chdir\n");
						break;
				case SYS_access:
						filename_addr = regs.rdi;
						flags = regs.rsi;
						if (flags & R_OK)
								check_read = 1;
						else if (flags & W_OK)
								check_write = 1;
						else if (flags & X_OK)
								check_exec = 1;
						//printf("access\n");
						break;
				case SYS_faccessat:
						is_path_relative_to_fd = 1;
						filename_addr = regs.rsi;
						flags = regs.rdx;
						if (flags & R_OK) 
								check_read = 1;
						else if (flags & W_OK)
								check_write = 1;
						else if (flags & X_OK)
								check_exec = 1;
						//printf("faccessat\n");
						break;
				case SYS_execve:
						filename_addr = regs.rdi;
						check_exec = 1;
						//printf("execve\n");
						break;
				case SYS_rename:
						filename_addr = regs.rdi;
						check_write = 1;
						//printf("rename\n");
						break;
				case SYS_renameat:
				case SYS_renameat2:
						is_path_relative_to_fd = 1;
						filename_addr = regs.rsi;
						check_write = 1;
						//printf("renameat\n");
						break;
				case SYS_link:
				case SYS_stat:
						filename_addr = regs.rdi;
						/* This is not how stat works in the OS.
						 * To be able to stat a file, you need search permission on all
						 * the parent directories, no permissions needed for the file.
						 * To be able to stat a directory, you need search permission on all
						 * the parent directories, as well as this directory.
						 */
						check_read = 1;
						//printf("stat\n");
						break;
		}

		if (filename_addr != 0) {
				if (insyscall == 0) {
						/* Syscall entry */
						insyscall = 1;
						filename = read_string_from_child_addr_space(sandb->child, filename_addr);
						memset(abspath, 0, PATH_MAX);
						// If the filepath is relative, then expand it into an absolute path
						if (is_path_relative_to_fd == 0 || (is_path_relative_to_fd == 1 && regs.rdi == AT_FDCWD)) {
								if (filename[0] != '/') {
										strcat(abspath,getenv("PWD"));
										strcat(abspath, "/");
								}
						} else {
								sprintf(symbolic_link,"/proc/%u/fd/%llu",sandb->child,regs.rdi);
								readlink(symbolic_link, abspath, PATH_MAX);  //this gives the filepath for a particular fd
								strcat(abspath, "/");
						}
						strcat(abspath,filename);
						//printf("syscall entry orig file %s abs path %s\n", filename, abspath);
						get_file_permission(config_file, abspath, perm);
						if (check_read && perm[0] == '0')
								change_filename = 1;
						if (check_write && perm[1] == '0')
								change_filename = 1;                  
						if (check_exec && perm[2] == '0')
								change_filename = 1;
						if (change_filename == 1) {
								/* Change the filepath so that the system will throw a permission denied error.
								   This is how we are emulating EACCES error code.*/
								put_string_into_child_addr_space(sandb->child, filename_addr, "/root/N", 7);
						}
				} else {
						/* syscall exit */
						//printf("syscall exit \n");
						insyscall = 0;
						if (change_filename == 1) {
								change_filename = 0;
								//printf("permission denied\n");
								/* change back the filepath so that stderr is printed correctly */
								put_string_into_child_addr_space(sandb->child, filename_addr, filename, 8);
						}
				}
		}
}

void sandb_run (struct sandbox *sandb) {
		int status;

		wait(&status);

		if(WIFEXITED(status)) {
				sandb_cleanup();
				exit(EXIT_SUCCESS);
		}

		if(WIFSTOPPED(status)) {
				sandb_handle_syscall(sandb);
		}

		/* PTRACE_SYSCALL restarts the child process and arranges for it to stop 
		 * at the next entry to or exit from a system call
		 */
		if (ptrace(PTRACE_SYSCALL, sandb->child, NULL, NULL) < 0) {
				if (errno == ESRCH) {
						waitpid(sandb->child, &status, __WALL | WNOHANG);
						sandb_kill(sandb);
				} else {
						sandb_cleanup();
						exit(EXIT_FAILURE);
				}
		}
}

int main(int argc, char **argv) {
		struct sandbox sandb;
		unsigned short cmd_index = 1;
		char *in_home_dir; 
		char ch;

		if (argc < 2) {
				return EXIT_FAILURE;
		}

		if (strcmp(argv[1], "-c") == 0) {
				config_file = fopen(argv[2], "r");
				cmd_index = 3;
		} else {
				// search current directory for config file
				config_file = fopen("./.fendrc", "r");
				if (config_file == NULL) {
						// search user directory for config file
						in_home_dir = strcat(getenv("HOME"), "/.fendrc");
						config_file = fopen(in_home_dir, "r");
				}
		}

		if (config_file == NULL) {
				printf("Must provide a config file.\n");
				return EXIT_FAILURE;
		}

		sandb_init(&sandb, argc-cmd_index, argv+cmd_index);

		for(;;) {
				sandb_run(&sandb);
		}

		return EXIT_SUCCESS;
}
