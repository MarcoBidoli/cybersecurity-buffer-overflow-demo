# Cybersecurity Exam Demo: Buffer Overflow Exploitation

This repository contains the materials for a buffer overflow exploitation demo, prepared as part of the examination for the **Cybersecurity Course** at the **University of Trieste**.

## Demo Video
The full demonstration of the exploits can be found here:
[Watch the Demo Video on YouTube](https://www.youtube.com/watch?v=P8VKzfWPnlI)

## Project Overview
The project is based on [Lab 1 of the MIT 6.566: Computer Systems Security course](https://css.csail.mit.edu/6.5660/2026/labs/lab1.html). It focuses on identifying and exploiting a stack buffer overflow vulnerability in a vulnerable web server called `zookws`, running on an x86-64 Linux system.

### Key Objectives:
1.  **Vulnerability Discovery**: Identifying an unchecked buffer in the `process_client` function of the web server.
2.  **Denial of Service (Part 1)**: Overwriting the return address to cause a server crash.
3.  **Code Injection (Part 2)**: Injecting custom x86-64 shellcode to perform arbitrary actions (deleting a specific file on the server).

## Repository Content
- `code/`: Contains the technical implementation:
    - `exploit-2.py`: Python script to trigger a server crash.
    - `exploit-4.py`: Python script for shellcode injection and arbitrary code execution.
    - `shellcode.S`: The assembly source for the injected payload.
- `Report.md`: A comprehensive technical report detailing the vulnerability analysis, the exploitation methodology, and the setup environment.
