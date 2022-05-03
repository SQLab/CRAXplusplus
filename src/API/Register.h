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

#ifndef S2E_PLUGINS_CRAX_REGISTER_H
#define S2E_PLUGINS_CRAX_REGISTER_H

#include <s2e/cpu.h>
#include <s2e/S2EExecutionState.h>

#include <array>

namespace s2e::plugins::crax {

class Register {
    friend class CRAX;

public:
    // libcpu/include/cpu/i386/defs.h
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


    Register() : m_state(), m_isRipSymbolic(), m_ripExpr() {}

    void initialize() {}

    // Determine if the given register contains symbolic data.
    [[nodiscard]]
    bool isSymbolic(Register::X64 reg);

    // Read symbolic data from the register file.
    klee::ref<klee::Expr> readSymbolic(Register::X64 reg,
                                       klee::Expr::Width width = klee::Expr::Int64,
                                       bool verbose = true);

    // Read concrete data from the register file.
    uint64_t readConcrete(Register::X64 reg,
                          bool verbose = true);

    // Write symbolic data to the register file.
    bool writeSymbolic(Register::X64 reg,
                       const klee::ref<klee::Expr> &value,
                       bool verbose = true);

    // Write concrete data to the register file.
    bool writeConcrete(Register::X64 reg,
                       uint64_t value,
                       bool verbose = true);

    // Register files are declared as the data members of `struct CPUX86State`.
    // This method returns the offset of the specified register file.
    // See libcpu/include/cpu/i386/cpu.h
    [[nodiscard, gnu::always_inline]] inline
    unsigned getOffset(Register::X64 reg) const {
        return (reg == Register::X64::RIP) ? CPU_OFFSET(eip) : CPU_OFFSET(regs[reg]);
    }

    // Get the name of the specified register file.
    [[nodiscard, gnu::always_inline]] inline
    std::string getName(Register::X64 reg) const {
        return (reg == Register::X64::RIP) ? "RIP" : s_regs64[reg];
    }

    // Dump all register values.
    void showRegInfo();

    void setRipSymbolic(const klee::ref<klee::Expr> &ripExpr);

private:
    static const std::array<std::string, 10> s_regs32;
    static const std::array<std::string, 18> s_regs64;

    S2EExecutionState *m_state;

    // libcpu mandates that RIP should never become symbolic,
    // hence we'll maintain an extra flag.
    bool m_isRipSymbolic;
    klee::ref<klee::Expr> m_ripExpr;
};


Register &reg(S2EExecutionState *state = nullptr);

}  // namespace s2e::plugins::crax

#endif  // S2E_PLUGINS_CRAX_REGISTER_H
