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

#include <s2e/S2E.h>
#include <s2e/S2EExecutionStateRegisters.h>
#include <s2e/Plugins/CRAX/CRAX.h>

#include "Register.h"

using namespace klee;

namespace s2e::plugins::crax {

const std::array<std::string, 10> Register::s_regs32 = {{
    "EAX", "ECX", "EDX", "EBX", "ESP", "EBP", "ESI", "EDI"
}};

const std::array<std::string, 18> Register::s_regs64 = {{
    "RAX", "RCX", "RDX", "RBX", "RSP", "RBP", "RSI", "RDI",
    "R8", "R9",  "R10", "R11", "R12", "R13", "R14", "R15"
}};


bool Register::isSymbolic(Register::X64 reg) {
    return !isa<ConstantExpr>(readSymbolic(reg, Expr::Int64, /*verbose=*/false));
}

ref<Expr> Register::readSymbolic(Register::X64 reg, Expr::Width width, bool verbose) {
    ref<Expr> ret = nullptr;

    if (reg == Register::X64::RIP && m_isRipSymbolic) {
        ret = m_ripExpr;
        if (width != Expr::Int64) {
            ret = ExtractExpr::create(ret, 0, width);
        }
    } else {
        ret = m_state->regs()->read(getOffset(reg), width);
    }

    if (isa<ConstantExpr>(ret) && verbose) {
        log<WARN>() << "readSymbolic(" << getName(reg) << "), but register isn't symbolic.\n";
    }
    return ret;
}

uint64_t Register::readConcrete(Register::X64 reg, bool verbose) {
    uint64_t ret = 0;
    bool success
        = m_state->regs()->read(getOffset(reg), &ret, sizeof(ret), /*concretize=*/false);
    if (!success && verbose) {
        log<WARN>() << "Cannot read concrete data from register: " << getName(reg) << "\n";
    }
    return ret;
}

bool Register::writeSymbolic(Register::X64 reg, const ref<Expr> &value, bool verbose) {
    bool success = m_state->regs()->write(getOffset(reg), value);
    if (!success && verbose) {
        log<WARN>() << "Cannot write symbolic data to register: " << getName(reg) << "\n";
    }
    return success;
}

bool Register::writeConcrete(Register::X64 reg, uint64_t value, bool verbose) {
    bool success = m_state->regs()->write(getOffset(reg), &value, sizeof(value));
    if (!success && verbose) {
        log<WARN>() << "Cannot write concrete data to register: " << getName(reg) << "\n";
    }
    return success;
}

void Register::showRegInfo() {
    auto &os = log<WARN>();

    os << "Dumping CPU registers...\n"
        << "---------- [REGISTERS] ----------\n";

    for (int i = 0; i < Register::X64::LAST; i++) {
        auto reg = static_cast<Register::X64>(i);
        os << getName(reg) << "\t";

        if (isSymbolic(reg)) {
            os << "(symbolic)";
        } else {
            os << hexval(readConcrete(reg));
        }
        os << "\n";
    }

    os << "RIP\t";
    if (m_isRipSymbolic) {
        os << "(symbolic)";
    } else {
        os << hexval(m_state->regs()->getPc());
    }
    os << "\n";
}

void Register::setRipSymbolic(const ref<Expr> &ripExpr) {
    m_isRipSymbolic = static_cast<bool>(ripExpr);
    m_ripExpr = ripExpr;
}


Register& reg(S2EExecutionState *state) {
    return g_crax->reg(state);
}

}  // namespace s2e::plugins::crax
