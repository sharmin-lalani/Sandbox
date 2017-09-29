# Sandbox
A simple sandbox using the ptrace system call.

File accesses made by an executable are permitted/denied as per permissions specified in a config file.
If an access is disallowed the offending system call will return the EACESS error code.

Invocation:
fend [‐c config] <command [args ...]>

Where config is an optional configuration file and command is the program the is being sandboxed. 
If the config file option is not given, the program will look for a file named .fendrc,
first in the current working directory and second in the user's home directory. 
If none are found, it will exit with the message "Must provide a config file."

Configuration file:
The configuration file contains one specification per line. 
Each specification contains a permission and one glob pattern. 
The fields are separated by a space. 
The permission is a 3‐bit binary digit, representing in order read, write, and execute permissions.  

Therefore,  
111 foo.txt is full permission and  
000 foo.txt is complete denial.  

It is possible that more than one specification matches a given file name. In such a case, the last match is the one that holds. For example, suppose the following two‐line configuration file.  
000 /usr/foo/*  
110 /usr/foo/bar  
The file "/usr/foo/bar" matches both lines. Therefore, the last line (110) holds. 
This is useful for denying access to all files in directory except for an enumerated few.
File names presented to the guarded system calls are generally absolute paths. 
Therefore, globs based on relative paths names (such as "foo" or "../bar") will not work as you may think. 

If no specification matches the file name, then fend will not restrict the access.
