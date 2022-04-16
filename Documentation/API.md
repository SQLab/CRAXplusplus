## API

This file documents the application programming interfaces (API) of CRAX++.

* Author: [@aesophor](https://github.com/aesophor)
* Last updated: Feb 20, 2022

## Table of Contents

* [Register](#register)
* [Memory](#memory)
* [Virtual Memory Map](#virtual-memory-map)
* [Disassembler](#disassembler)
* [Logging](#logging)

## Before We Begin

In S2E:

* to access EIP's value within X86CPUState: `CPU_OFFSET(eip)`
* to access RAX's value within X86CPUState: `CPU_OFFSET(regs[R_EAX])`
* to access RSP's value within X86CPUState: `CPU_OFFSET(regs[R_ESP])`
* to access R12's value within X86CPUState: `CPU_OFFSET(regs[12])`

As you can see, S2E's interfaces are not intuitive to use. Therefore, I wrote wrappers for S2E's CPU and Memory interfaces.

## Register

All x86_64 registers are defined in `src/API/Register.h`, whose values match the values from `libcpu/include/cpu/i386/defs.h`.

You'll notice that `RIP` is defined after `LAST`, this is because libcpu treats EIP/RIP differently than general purpose registers.

```
// src/API/Register.h
class Register {
public:
    // ...
    enum X64 {
        RAX,  // 0
        RCX,  // 1
        RDX,  // 2
        RBX,  // 3
        RSP,  // 4
        RBP,  // 5
        RSI,  // 6
        RDI,  // 7
        R8,   // 8
        R9,   // 9
        R10,  // 10
        R11,  // 11
        R12,  // 12
        R13,  // 13
        R14,  // 14
        R15,  // 15
        LAST,
        RIP
    };
    // ...
};
```

#### Read concrete data from a register

```cpp
S2EExecutionState *state = ...;

uint64_t rax = reg(state).readConcrete(Register::X64::RAX);
uint64_t r12 = reg(state).readConcrete(Register::X64::R12);
uint64_t rip = reg(state).readConcrete(Register::X64::RIP);
```

#### Read symbolic data from a register

```cpp
S2EExecutionState *state = ...;

ref<Expr> rax = reg(state).readSymbolic(Register::X64::RAX);
ref<Expr> r12 = reg(state).readSymbolic(Register::X64::R12);
ref<Expr> rip = reg(state).readSymbolic(Register::X64::RIP);
```

#### Write concrete data to a register

```cpp
S2EExecutionState *state = ...;
uint64_t value = 0x1337;

ref<Expr> rax = reg(state).writeSymbolic(Register::X64::RAX, value);
ref<Expr> r12 = reg(state).writeSymbolic(Register::X64::R12, value);
ref<Expr> rip = reg(state).writeSymbolic(Register::X64::RIP, value);
```

#### Write symbolic data to a register

```cpp
S2EExecutionState *state = ...;
ref<Expr> value = ConstantExpr::create(0x1337, Expr::Int64);

ref<Expr> rax = reg(state).readSymbolic(Register::X64::RAX, value);
ref<Expr> r12 = reg(state).readSymbolic(Register::X64::R12, value);
ref<Expr> rip = reg(state).readSymbolic(Register::X64::RIP, value);
```

#### Check if a register is symbolic

```cpp
S2EExecutionState *state = ...;

bool isRaxSymbolic = reg(state).isSymbolic(Register::RAX);
```

#### Get register name

```cpp
S2EExecutionState *state = ...;

std::string regName = reg(state).getName(Register::X64::RAX);
// regName is "RAX"
```

## Memory

#### Read concrete bytes from a guest memory region

> Warning: If \[addr,addr+size) contains symbolic bytes, they will be concretized by S2E.

```cpp
S2EExecutionState *state = ...;

uint64_t addr = 0x402000;
uint64_t size = 0x30;

std::vector<uint8_t> bytes = mem(state).readConcrete(addr, size);
// bytes.size() == 0x30
```

#### Non-concretizing read from a guest memory region

```cpp
S2EExecutionState *state = ...;

uint64_t addr = 0x402000;
uint64_t size = 0x30;

std::vector<uint8_t> bytes = mem(state).readConcrete(addr, size, /*concretize=*/false);
// bytes.size() == 0x30
```

#### Read symbolic bytes from a guest memory region

```cpp
S2EExecutionState *state = ...;

uint64_t addr = 0x402000;
Expr::Width size = Expr::Int64;  // 64 bits == 8 bytes

std::vector<uint8_t> bytes = mem(state).readSymbolic(addr, size);
// bytes.size() == 8
```

#### Write concrete bytes to a guest memory region

```cpp
S2EExecutionState *state = ...;

uint64_t addr = 0x402000;
std::string s = "/bin/sh";
std::vector<uint8_t> bytes(s.begin(), s.end());

bool ok = mem(state).writeConcrete(addr, bytes);
```

#### Write symbolic bytes to a guest memory region

```cpp
S2EExecutionState *state = ...;

uint64_t addr = 0x402000;
ref<Expr> value = ConstantExpr::create(0x1337, Expr::Int64);

bool ok = mem(state).writeSymbolic(addr, value);
```

#### Check if a guest memory region contains at least one symbolic byte

```cpp
S2EExecutionState *state = ...;

uint64_t addr = 0x402000;
uint64_t size = 0x30;

bool isSymbolic = mem(state).isSymbolic(addr, size);
```

#### Check if a guest virtual address is mapped

```cpp
S2EExecutionState *state = ...;

bool isMapped = mem(state).isMapped(0x402000);
```

#### Search certain bytes (using KMP) from the guest virtual address space

```cpp
S2EExecutionState *state = ...;

std::string needleStr = "/bin/sh";
std::vector<uint8_t> needle(needleStr.begin(), needleStr.end());

// Searches all instances of "/bin/sh" from the guest va_space.
// The search result is returned as a vector containing their guest virtual addresses.
std::vector<uint64_t> addresses = mem(state).search(needle);
```

## Virtual Memory Map

The virtual memory map in CRAX++ is analogous to the `vmmap` from [pwndbg](https://github.com/pwndbg/pwndbg).

It is implemented as an [llvm::IntervalMap](https://llvm.org/doxygen/classllvm_1_1IntervalMap.html) in CRAX++, and is built by merging the following maps on-the-fly:

* MemoryMap
* ModuleMap

> Warning: This vmmap implementation can be inaccurate because it is not built from /proc/$pid/maps, as I haven't figured out a way to read a guest file.
> The dynamic loader `ld-linux-x86-64.so.2`, once loaded by linux kernel's `load_elf_binary()`, will relocate itself to somewhere else and then load `libc.so.6`.
> Since `libc.so.6` is loaded by the dynamic loader instead of by the kernel, we won't be able to know where libc actually resides in the guest virtual address space.
> What we currently do is similar to what we do during pwning: we "leak" the runtime address of `__libc_start_main` from the Global Offset Table (GOT),
> subtract it from its offset within libc, and we get the libc base within S2E.

```
Start           End             Perm    Module
0x561104593000  0x561104594000  r--     target
0x561104594000  0x561104595000  r-x     target
0x561104595000  0x561104597000  r--     target
0x561104597000  0x561104598000  rw-     target
0x7f32d7e2a000  0x7f32d7fbf000  r-x     libc.so.6
0x7f32d7fbf000  0x7f32d81bf000  ---     libc.so.6
0x7f32d81bf000  0x7f32d81c3000  r--     libc.so.6
0x7f32d81c3000  0x7f32d81c9000  rw-     libc.so.6
0x7f32d81c9000  0x7f32d81ec000  r-x     ld-linux-x86-64.so.2
0x7f32d83e2000  0x7f32d83e4000  rw-     ld-linux-x86-64.so.2
0x7f32d83ec000  0x7f32d83ed000  r--     ld-linux-x86-64.so.2
0x7f32d83ed000  0x7f32d83ee000  rw-     ld-linux-x86-64.so.2
0x7ffd67eb7000  0x7ffd67ebb000  rw-     [stack]
```

#### Iterating over the vmmap

```cpp
S2EExecutionState *state = ...;
const auto &vmmap = mem(state).vmmap();

foreach2 (it, vmmap.begin(), vmmap.end()) {
    RegionDescriptorPtr region = *it;
    bool r = region->r;
    bool w = region->w;
    bool x = region->x;
    std::string name = region->moduleName;  // e.g., libc.so.6
}
```

#### Get the associated module's base address of an address

```cpp
S2EExecutionState *state = ...;

uint64_t moduleBase = mem(state).vmmap().getModuleBaseAddress(0x7f32d81bf004);
// moduleBase == 0x7f32d7e2a000, i.e. libc base
```

#### Get the associated module's end address of an address

```cpp
S2EExecutionState *state = ...;

uint64_t moduleEnd = mem(state).vmmap().getModuleEndAddress(0x7f32d81bf004);
// moduleEnd == 0x7f32d81c9000, i.e. libc end
```

## Disassembler

The disassembler API is a wrapper around [capstone](https://github.com/capstone-engine/capstone), and each disassembled instruction is returned as an `Instruction`.

```cpp
// Defined in src/API/Disassembler.h
struct Instruction {
    uint64_t address;
    uint64_t size;
    std::string mnemonic;
    std::string opStr;
};
```

#### Disassemble one instruction at an address

```cpp
S2EExecutionState *state = ...;

std::optional<Instruction> insn = disas(state).disasm(0x401000);

if (insn) {
    // Success.
} else {
    // Failed.
}
```

#### Disassemble all instructions within a function (symbol)

```cpp
S2EExecutionState *state = ...;

std::vector<Instruction> insns = disas(state).disasm("__libc_csu_init");

if (insns.size()) {
    // Success.
} else {
    // Failed.
}
```

#### Disassemble all instructions from a vector of concrete bytes

```cpp
S2EExecutionState *state = ...;

std::vector<uint8_t> bytes = mem(state).readConcrete(0x401000, 0x100);
std::vector<Instruction> insns = disas(state).disasm(bytes, 0x401000);

if (insns.size()) {
    // Success.
} else {
    // Failed.
}
```

## Logging

#### Log levels

* INFO
* DEBUG
* WARN

#### Examples

Beware! Avoid using the logging APIs within the constructor of CRAX (and the constructors of CRAX's data members)!

Make sure `g_crax` has been initialized.

```cpp
S2EExecutionState *state = ...;

log<WARN>(state) << "hello\n";  // hello
log<WARN>(state) << 0x1337 << '\n';  // 4919
log<WARN>(state) << klee::hexval(0x1337) << '\n';  // 0x1337
```
