# CRAXplusplus (CRAX++)

Modular **Automatic Exploit Generator (AEG)** using selective symbolic execution.

version: 0.1.1

CRAX++ is maintained by:

* Marco Wang \<aesophor.cs09g@nctu.edu.tw\> 
* Tim Yang \<tl455047.gcs09g@nctu.edu.tw\>

## Core Features

* Leverages [S2E 2.0](https://github.com/S2E/s2e) to **concolically execute x86_64 linux binaries** and **generate exploit scripts**
* Currently only supports CTF binaries
* Robust against modern exploit mitigations (e.g., ASLR, NX, PIE, Canary)
* Custom modules (plugins) support
* Custom exploitation techniques (ROP formulae) support
* ...

## Quick Start \[WIP]

Introduction

* [Building CRAX++](Documentation/Build.md)
* Usage
* Reproducing experiments from the `examples` directory
* What is a Module?
* What is a Technique?

Extending CRAX++

* [Register API](Documentation/API.md#register)
* [Memory API](Documentation/API.md#memory)
* [Virtual Memory Map API](Documentation/API.md#virtual-memory-map)
* [Disassembler API](Documentation/API.md#disassembler)
* [Logging API](Documentation/API.md#logging)
* Instruction hooks
* Syscall hooks
* [How to add a Module](Documentation/Module.md)
* How to add a Technique

## Quick Example

* ASLR + NX + PIE + Canary + Full RELRO
* Exploit script: [examples/aslr-nx-pie-canary-fullrelro/exploit_11.py](examples/aslr-nx-pie-canary-fullrelro/exploit_11.py)

```c
#include <stdio.h>
#include <unistd.h>

int main() {
    char buf[0x18];

    printf("what's your name: ");
    fflush(stdout);
    read(0, buf, 0x80);

    printf("Hello, %s. Your comment: ", buf);
    fflush(stdout);
    read(0, buf, 0x80);

    printf("Thanks! We've received it: %s\n", buf);
    fflush(stdout);
    read(0, buf, 0x30);
}
```

## Trophies

Experimental Setup:

* Binaries are compiled with gcc 9.3.0 (Ubuntu 9.3.0-17ubuntu1~20.04)
* Binaries are concolically executed in S2E guest (Debian 9.2.1 x86_64, 4.9.3-s2e)
* All generate exploit scripts are executed in host (Ubuntu 20.04.1 x86_64, 5.11.0-46-generic)

We avoid using libc-sensitive exploitation techniques, i.e., the exploit scripts work across different versions of libc.

| Binary | ASLR | NX | PIE | Canary | Full RELRO | Source | Exploit |
| --- | --- | --- | --- | --- | --- | --- | --- |
| [aslr-nx-pie-canary-fullrelro](examples/aslr-nx-pie-canary-fullrelro) | ✓ | ✓ | ✓ | ✓ | ✓ | [main.c](examples/aslr-nx-pie-canary-fullrelro/main.c) | [script](examples/aslr-nx-pie-canary-fullrelro/exploit_11.py) |
| [aslr-nx-pie-canary](examples/aslr-nx-pie-canary) | ✓ | ✓ | ✓ | ✓ | | [main.c](examples/aslr-nx-pie-canary/main.c) | [script](examples/aslr-nx-pie-canary/exploit_9.py) |
| [aslr-nx-pie](examples/aslr-nx-pie) | ✓ | ✓ | ✓ | | | [main.c](examples/aslr-nx-pie/main.c) | [script](examples/aslr-nx-pie/exploit_2.py) |
| [aslr-nx-canary](examples/aslr-nx-canary) | ✓ | ✓ | | ✓ | | [main.c](examples/aslr-nx-canary/main.c) | [script](examples/aslr-nx-canary/exploit_2.py) |
| [aslr-nx](examples/aslr-nx) | ✓ | ✓ | | |  | [main.c](examples/aslr-nx/main.c) | [script](examples/aslr-nx/exploit_0.py) |
| [NTU Computer Security 2017 Fall: readme (150 pts)](examples/readme) | ✓ | ✓ | | |  | [main.c](examples/readme/main.c) | [script](examples/readme/exploit_0.py) |
| [readme-alt1](examples/readme-alt1) | ✓ | ✓ | | |  | [main.c](examples/readme-alt1/main.c) | [script](examples/readme-alt1/exploit_0.py) |
| [readme-alt2](examples/readme-alt2) | ✓ | ✓ | | |  | [main.c](examples/readme-alt2/main.c) | [script](examples/readme-alt2/exploit_0.py) |
| [pwnable.tw: unexploitable (500 pts)](https://pwnable.tw/challenge/#20) | ✓ | ✓ | | | | [main.c](examples/unexploitable/main.c) | [script](examples/unexploitable/exploit_0.py) |

## Motivation

#### CRAX (2012), Software CRash analysis for Automatic eXploit generation

[[Paper](https://ir.nctu.edu.tw/bitstream/11536/24012/1/000332520700022.pdf)] [[Repo](https://github.com/SQLab/CRAX/tree/workable)] [[Article](https://skhuang.web.nctu.edu.tw/research/)]

> This research was started back in ~1992. When I was serving as a Ph.D TA at the 3F server room of National Chiao Tung University, the Internet was rapidly evolving, during which black hat hackers started to emerge. As the administrators of the servers, we had to engage in combat against malicious hackers from the wild in order to protect our digital properties from attacks. Over time, we started to be aware that all these problems stemmed from software bugs.
> 
> Back then, we lacked the ability and tools to analyze bugs, but things had started to change since 2005. We started to make good progress with bug analysis as well as the development of software testing tools, and until 2012, we've successfully developed CRAX (an automatic exploit generator built upon S2E 1.0) which was capable of automatically generating exploits for unix media player (mplayer, ~500,000 loc), web browsers (e.g., firefox and Internet Explorer) and Microsoft Word using selective symbolic execution.
> 
> -- Prof. Shih-Kun Huang ([@skhuang](https://github.com/skhuang)), National Yang Ming Chiao Tung University

#### LAEG (2021), Bypassing ASLR with Dynamic Binary Analysis for Automated Exploit Generation

[[Paper](https://www.airitilibrary.com/Publication/alDetailedMesh1?DocID=U0001-0508202117214500)]

> ASLR is a binary protection technique to prevent exploitation by randomizing the loaded section base address in every execution, which is enabled by default in modern operating systems. With ASLR enabled, exploitation will become more complicated as attacker has to leak additional information to bypass ASLR. However, we notice that most of the state-of-the-art Automated Exploit Generation solutions assume that ASLR is disabled to generate a working exploit. Thus, we proposed a prototype called LAEG that utilizes Dynamic Taint Analysis to analyse the given proof-of-crash input and record the input and output state information that can be used to determine potential information leak. Then, LAEG leverages this information to recover sections’ base address and generate an exploit to bypass ASLR. Our result shows that LAEG can bypass various binary protections, including not only ASLR, but also PIE, and stack canary. In addition, LAEG shows better performance than an opensource AEG solution Zeratool and has about 6.46x to 45.15x speedup in exploit generation compared to human experts.
>
> -- [@how2hack](https://github.com/how2hack), Balsn CTF Team from Network Security Lab of National Taiwan University

## Special Thanks (Listed Lexicographically)

This project is impossible without:

* [Balsn CTF Team](https://github.com/balsn) and Network Security Lab, NTU
* S2E: [Vitaly Chipounov](https://github.com/vitalych/) and all the S2E authors/contributors
* Software Quality Lab, NYCU

## License

Licensed under MIT. Copyright 2021-2022 Software Quality Laboratory, NYCU.
