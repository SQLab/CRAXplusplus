# CRAXplusplus (CRAX++)

<a href="Documentation/thesis.png"><img src="Documentation/thesis.png" width="25%" align="right"></a>

**current version: 0.2.1**

CRAXplusplus is an **exploit generator** based on S2E. Given a binary program and a PoC input, our system leverages concolic execution to collect the path constraints determined by the PoC input, add exploit constraints to the crashing states, and query the constraint solver for exploit script generation. Our system supports custom exploitation techniques and modules with the aim of maximizing its extensibility. We implement several binary exploitation techniques in our system, and design two ROP payload chaining algorithms to build ROP payload from multiple techniques. In addition, we implement two modules: IOStates and DynamicRop. The former adapts the methodology of [LAEG](#laeg-2021-bypassing-aslr-with-dynamic-binary-analysis-for-automated-exploit-generation) to the multi-path execution environment in S2E, and the latter enables our system to dynamically perform ROP inside S2E as it adds exploit constraints. Our results show that provided the target binary contains an adequate amount of input and output states to perform information leak, CRAXplusplus can still generate a working exploit script even when all the exploit mitigations are enabled at the same time, and even in the presence of basic input transformations.

## Core Features

* Leverages [S2E 2.0](https://github.com/S2E/s2e) to **concolically execute x86_64 linux binaries** and **generate exploit scripts**
* Currently only supports CTF binaries
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

## Trophies

Experimental Setup:

* Binaries are compiled with gcc 9.3.0 (Ubuntu 9.3.0-17ubuntu1~20.04)
* Binaries are concolically executed in S2E guest (Debian 9.2.1 x86_64, 4.9.3-s2e) using libc/ld 2.24
* All generated exploit scripts are verified in host (Ubuntu 20.04.1 x86_64, 5.11.0-46-generic) using libc/ld 2.24

![](Documentation/evaluation.png)

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
