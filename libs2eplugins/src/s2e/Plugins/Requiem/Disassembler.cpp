// Copyright (C) 2021-2022, Marco Wang
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

#include <s2e/Plugins/Requiem/Requiem.h>
#include <capstone/capstone.h>

#include "Disassembler.h"

#define X86_64_INSN_MAX_NR_BYTES 15

namespace s2e::plugins::requiem {

Instruction Disassembler::disasm(uint64_t pc) {
    csh handle;
    cs_insn *insn;
    size_t count;
    Instruction ret;

    std::vector<uint8_t> code
        = m_ctx.mem().readConcrete(pc, X86_64_INSN_MAX_NR_BYTES);

    if (code.empty()) {
        return ret;
    }

    if (cs_open(CS_ARCH_X86, CS_MODE_64, &handle) != CS_ERR_OK) {
        return ret;
    }

    count = cs_disasm(handle, code.data(), code.size(), pc, 0, &insn);

    if (count) {
        ret = {pc, std::move(insn[0].mnemonic), std::move(insn[0].op_str)};
        cs_free(insn, count);
    } else {
        m_ctx.log<WARN>()
            << "disassemble failed: " << hexval(pc) << "\n";
    }

    cs_close(&handle);
    return ret;
}

std::vector<Instruction> Disassembler::disasm(const std::vector<uint8_t> &code,
                                              const uint64_t virtAddr) {
    csh handle;
    cs_insn *insn;
    size_t count;
    std::vector<Instruction> ret;

    if (code.empty()) {
        return ret;
    }

    if (cs_open(CS_ARCH_X86, CS_MODE_64, &handle) != CS_ERR_OK) {
        return ret;
    }

    count = cs_disasm(handle, code.data(), code.size(), virtAddr, 0, &insn);

    if (count) {
        ret.resize(count);
        for (size_t i = 0; i < count; i++) {
            ret[i] = {insn[i].address, insn[i].mnemonic, insn[i].op_str};
        }
        cs_free(insn, count);
    } else {
        auto &os = m_ctx.log<WARN>();
        os << "disassemble failed: ";

        for (size_t i = 0; i < code.size(); i++) {
            os << hexval(code[i]);
            if (i != code.size() - 1) {
                os << " ";
            }
        }
        os << "\n";
    }

    cs_close(&handle);
    return ret;
}

std::vector<Instruction> Disassembler::disasm(const std::string &symbol) {
    csh handle;
    cs_insn *insn;
    size_t count;
    std::vector<Instruction> ret;

    auto f = m_ctx.getExploit().getElf().functions()[symbol];

    std::vector<uint8_t> code
        = m_ctx.mem().readConcrete(f.address, f.size);

    if (code.empty()) {
        return ret;
    }

    if (cs_open(CS_ARCH_X86, CS_MODE_64, &handle) != CS_ERR_OK) {
        return ret;
    }

    count = cs_disasm(handle, code.data(), code.size(), f.address, 0, &insn);

    if (count) {
        ret.resize(count);
        for (size_t i = 0; i < count; i++) {
            ret[i] = {insn[i].address, insn[i].mnemonic, insn[i].op_str};
        }
        cs_free(insn, count);
    } else {
        m_ctx.log<WARN>()
            << "disassemble failed: "
            << f.name << " ("
            << hexval(f.address) << ", "
            << hexval(f.size) << ")\n";
    }

    cs_close(&handle);
    return ret;
}

}  // namespace s2e::plugins::requiem
