# CRAXplusplus (CRAX++)

Modular **Automatic Exploit Generator (AEG)** using selective symbolic execution.

version: 0.1.0

CRAX++ is maintained by:

* Marco Wang \<aesophor.cs09g@nctu.edu.tw\> 
* Tim Yang \<tl455047.gcs09g@nctu.edu.tw\>

## Core Features

* Leverages [S2E 2.0](https://github.com/S2E/s2e) to **concolically execute x86_64 linux binaries** and **generate exploit scripts**
* Robust against modern exploit mitigations (e.g., ASLR, NX, PIE, Canary)
* Custom modules (plugins) support
* Custom exploitation techniques (ROP formulae) support
* ...

## Quick Start

This section is currently WIP, but we're working very hard to get this section done. Please come back later.

Introduction

* [Installation](Documentation/BUILD.md) - outdated
* [Usage]()
* [What is a Module?]()
* [What is a Technique?]()

Extending CRAX++

* signals in S2E (libfsigc++)
* (before/after) Instruction hooks
* (before/after) Syscall hooks
* Register API
* Memory API
* Disassembler API (capstone)
* Virtual Memory Map API
* [How to add a Module]()
* [How to add a Technique]()

## Quick Example

* ASLR + NX + PIE + Canary
* Exploit: [examples/aslr-nx-pie-canary/exploit_9.py](examples/aslr-nx-pie-canary/exploit_9.py)

```c
#include <stdio.h>
#include <unistd.h>

int main() {
    setvbuf(stdin, NULL, _IONBF, 0);
    setvbuf(stdout, NULL, _IONBF, 0);

    char buf[0x18];
    printf("what's your name: ");
    read(0, buf, 0x80);

    printf("Hello, %s. Your comment: ", buf);
    read(0, buf, 0x80);

    printf("Thanks! We've received it: %s\n", buf);
    read(0, buf, 0x30);
}
```

## Motivation

#### CRAX (2012), Software CRash analysis for Automatic eXploit generation

[[Paper](https://ir.nctu.edu.tw/bitstream/11536/24012/1/000332520700022.pdf)] [[Repo](https://github.com/SQLab/CRAX/tree/workable)] | [[Article](https://skhuang.web.nctu.edu.tw/research/)]

> This research was started back in ~1992. When I was serving as a Ph.D TA at the 3F server room of National Chiao Tung University, the Internet was rapidly evolving, during which black hat hackers started to emerge. As the administrators of the servers, we had to engage in combat against malicious hackers from the wild in order to protect our digital properties from attacks. Over time, we started to be aware that all these problems stemmed from software bugs.
> 
> Back then, we lacked the ability and tools to analyze bugs, but things had started to change since 2005. We started to make good progress with bug analysis as well as the development of software testing tools, and until 2012, we've successfully developed CRAX (an automatic exploit generator built upon S2E 1.0) which was capable of automatically generating exploits for unix media player (mplayer, ~500,000 loc), web browsers (e.g., firefox and Internet Explorer) and Microsoft Word using selective symbolic execution.
> 
> -- Prof. Shih-Kun Huang ([@skhuang](https://github.com/skhuang)), National Yang Ming Chiao Tung University

## Trophies

All binaries are evaluted on Ubuntu 20.04.1 (5.11.0-46-generic). See the `example` directory for details.

| Binary | ASLR | NX | PIE | Canary | Full RELRO | Exploit Script |
| --- | --- | --- | --- | --- | --- | --- |
| survey | ✓ | ✓ | ✓ | ✓ | ✓ | WIP |
| [aslr-nx-pie-canary](examples/aslr-nx-pie-canary) | ✓ | ✓ | ✓ | ✓ | | [Exploit](examples/aslr-nx-pie-canary/exploit_9.py) |
| [aslr-nx-pie](examples/aslr-nx-pie) | ✓ | ✓ | ✓ | | | [Exploit](examples/aslr-nx-pie/exploit_2.py) |
| [aslr-nx-canary](examples/aslr-nx-canary) | ✓ | ✓ | | ✓ | | [Exploit](examples/aslr-nx-canary/exploit_2.py) |
| [aslr-nx](examples/aslr-nx) | ✓ | ✓ | | | | [Exploit](examples/aslr-nx/exploit_0.py) |
| [NTU Computer Security 2017 Fall: readme (150 pts)](examples/readme) | ✓ | ✓ | | | | [Exploit](examples/readme/exploit_0.py) |
| [pwnable.tw: unexploitable (500 pts)](https://pwnable.tw/challenge/#20) | ✓ | ✓ | | | | [Exploit](examples/unexploitable/exploit_0.py) |

## Special Thanks (Listed Lexicographically)

This work is impossible without:

* [Balsn CTF Team](https://github.com/balsn) and Network Security Lab, NTU
* Software Quality Lab, NYCU

## License

Licensed under MIT. Copyright 2021-2022 Software Quality Laboratory, NYCU.
