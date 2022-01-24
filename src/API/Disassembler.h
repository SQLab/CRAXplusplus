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

#ifndef S2E_PLUGINS_CRAX_DISASSEMBLER_H
#define S2E_PLUGINS_CRAX_DISASSEMBLER_H

#include <s2e/S2E.h>
#include <s2e/S2EExecutionState.h>

#include <optional>
#include <string>
#include <vector>

namespace s2e::plugins::crax {

struct Instruction {
    uint64_t address;
    uint64_t size;
    std::string mnemonic;
    std::string opStr;
};

struct SyscallCtx {
    uint64_t ret;
    uint64_t nr;
    uint64_t arg1;
    uint64_t arg2;
    uint64_t arg3;
    uint64_t arg4;
    uint64_t arg5;
    uint64_t arg6;
};


class Disassembler {
    friend class CRAX;

public:
    Disassembler() : m_state() {}

    // Disassemble one instruction at the specificed address.
    std::optional<Instruction> disasm(uint64_t pc) const;

    // Disassemble a function by its symbol.
    std::vector<Instruction> disasm(const std::string &symbol) const;

    // Disassemble all instructions in the given `code` vector,
    // where the `code` is assumed to be loaded at `virtAddr`.
    std::vector<Instruction> disasm(const std::vector<uint8_t> &code,
                                    uint64_t virtAddr,
                                    bool warnOnError = true) const;

private:
    S2EExecutionState *m_state;
};


Disassembler &disas(S2EExecutionState *state = nullptr);

}  // namespace s2e::plugins::crax

#endif  // S2E_PLUGINS_CRAX_DISASSEMBLER_H
