# Cybersecurity Exam - Demo: Buffer Overflows

## Introduction
In the following demo I will execute a remote code injection attack based on the [_Lab 1 of MIT 6.566: Computer Systems Security_](https://css.csail.mit.edu/6.5660/2026/labs/lab1.html) course. The complete lab is made of 4 parts, we will solve the first 2 in this demo.

The objective of this demo is to exploit a real buffer overflow on a x64 linux machine running a vulnerable http server written in C.

For the setup I relied on the instructions provided by the Lab1 guide, I ran the _6.566-standalone-v26_ virtual machine on UTM on MacOS virtualizing the x64 aarch needed for the lab. Inside the virtual machine I then cloned the official repository from https://github.com/mit-pdos/6.566-lab-2026 which contains:

* the zookd vulnerable server, composed of `http.c` and `zookd.c`
* some files to help the exploitation of the web-server like `exploit-template.py` and `shellcode.S`.
* some scripts to help running the programs with the same addresses and to check if exploitations have been successful.

---

In this threat model, the attacker/adversary:
* has the server code available for inspection 
* is aware of the buffer overflow vulnerabilities
* has the capabilities for writing an exploit
* can interact with a vulnerable instance of the software

## Part 0 - Vulnerability discovery
The first step of the lab is to analyze the codebase and find some vulnerable buffers. I started from the `zookd.c - main()` function following the code and the first vulnerable buffer have been found in 
```c
static void process_client(int fd) {
    ...
    char reqpath[4096];
    ...
}
```
which is a buffer placed on the stack. The vulnerability becomes clear once one follows the code into the `http_request_line()` and `url_decode()` functions. 

An attacker can see that the server accepts request lines of up to 8192 bytes (`http.c` line 66), and `url_decode` blindly copies the path part of that netowrk input onto the reqpath buffer without any boundary checks. This allows an adversary to carefully construct constructed an input that exceeds 4096 bytes, resulting in a stack buffer overflow."

## Part 1 - Program Crash

## Part 2 - Write the shellcode and delete a file

## Sources

- MIT 6.566, _Lab 1_ - [css.csail.mit.edu](https://css.csail.mit.edu/6.5660/2026/labs/lab1.html)
- Smashing the stack in the 21st century - [thesquareplanet.com](https://thesquareplanet.com/blog/smashing-the-stack-21st-century/)
- Smashing the stack for fun and profit - [phrack.org](https://phrack.org/issues/49/14#article)
- Stack frame layout on x86-x64 - [eli.thegreenplace.net](https://eli.thegreenplace.net/2011/09/06/stack-frame-layout-on-x86-64)
- Syscall x86-64 codes - [chromium.googlesource.com](https://chromium.googlesource.com/chromiumos/docs/+/master/constants/syscalls.md#x86_64-64_bit)