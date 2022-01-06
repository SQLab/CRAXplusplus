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

#include <klee/Expr.h>
#include <s2e/Plugins/CRAX/CRAX.h>
#include <s2e/Plugins/CRAX/Expr/BinaryExprEvaluator.h>
#include <s2e/Plugins/CRAX/Techniques/Technique.h>
#include <s2e/Plugins/CRAX/Techniques/StackPivot.h>
#include <s2e/Plugins/CRAX/Pwnlib/Util.h>
#include <s2e/Plugins/CRAX/Utils/StringUtil.h>

#include "RopChainBuilder.h"

using namespace klee;
using VarValuePair = std::pair<std::string, std::vector<uint8_t>>;
using ConcreteInputs = std::vector<VarValuePair>;

namespace s2e::plugins::crax {

using SymbolicRopPayload = Technique::SymbolicRopPayload;
using ConcreteRopPayload = Technique::ConcreteRopPayload;


bool RopChainBuilder::build(Exploit &exploit,
                            const std::vector<std::unique_ptr<Technique>> &techniques) {
    // [Optional] generate code to leak canary.
    if (exploit.getElf().getChecksec().hasCanary) {
        exploit.appendRopPayload(format("b'A' * %d", exploit.getCanaryLeakOffset()));
        exploit.flushRopPayload();

        exploit.writelines({
            format("    proc.recvuntil(b'A' * %d)", exploit.getCanaryLeakOffset()),
            "    canary = b'\\x00' + proc.recv(7)",
            "    log.info('leaked canary: {}'.format(hex(u64(canary))))",
            ""
        });
    }

    // [Optional] generate code to leak ELF base.
    if (exploit.getElf().getChecksec().hasPIE) {

    }

    // [Required] generate ROP chain.
    for (const auto &t : techniques) {
        std::vector<SymbolicRopPayload> symbolicRopPayloadList = t->getSymbolicRopPayloadList();

        if (symbolicRopPayloadList.empty()) {
            continue;
        }

        // Direct payload generation mode
        if (!m_symbolicMode) {
            for (const auto &payload : symbolicRopPayloadList) {
                for (const ref<Expr> &e : payload) {
                    exploit.appendRopPayload(BinaryExprEvaluator<std::string>().evaluate(e));
                }
                exploit.flushRopPayload();
            }
            continue;
        }

        // Symbolic payload generation mode
        log<WARN>() << "Building exploit constraints...\n";
        for (size_t i = 0; i < symbolicRopPayloadList[0].size(); i++) {
            const ref<Expr> &e = symbolicRopPayloadList[0][i];
            bool ok = false;

            if (i == 0) {
                ok = addRegisterConstraint(Register::X64::RBP, e);
            } else if (i == 1) {
                ok = addRegisterConstraint(Register::X64::RIP, e);
            } else {
                uint64_t addr = m_ctx.reg().readConcrete(Register::X64::RSP) + m_symbolicModeRspOffset;
                ok = addMemoryConstraint(addr, e);
                m_symbolicModeRspOffset += 8;
            }

            if (!ok) {
                return false;
            }
        }

        if (shouldSwitchToDirectMode(t.get())) {
            log<WARN>() << "Switching from symbolic mode to direct mode...\n";
            m_symbolicMode = false;

            ConcreteInputs newInput;
            if (!m_ctx.getCurrentState()->getSymbolicSolution(newInput)) {
                log<WARN>() << "Could not get symbolic solutions\n";
                return false;
            }

            std::string symbolicPayload = "b'";
            const VarValuePair &vp = newInput[0];
            for (const auto __byte : vp.second) {
                symbolicPayload += format("\\x%02x", __byte);
            }
            symbolicPayload += "'";

            // XXX: You mad bro?
            if (exploit.getElf().getChecksec().hasCanary) {
                assert(exploit.getElf().getCanary() != 0 && "Corrupted canary?");

                std::string canaryBytes;  // in "\xff\xff..." form
                for (auto __byte : p64(exploit.getElf().getCanary())) {
                    canaryBytes += format("\\x%02x", __byte);
                }
                log<WARN>() << "canary: " << klee::hexval(exploit.getElf().getCanary()) << '\n';
                log<WARN>() << "replacing: " << canaryBytes << '\n';
                symbolicPayload = replace(symbolicPayload, canaryBytes, "' + canary + b'");
            }

            exploit.appendRopPayload(symbolicPayload);
            exploit.flushRopPayload();

            for (size_t i = 1; i < symbolicRopPayloadList.size(); i++) {
                for (const ref<Expr> &e : symbolicRopPayloadList[i]) {
                    exploit.appendRopPayload(BinaryExprEvaluator<std::string>().evaluate(e));
                }
                exploit.flushRopPayload();
            }
        }
    }

    return true;
}


bool RopChainBuilder::shouldSwitchToDirectMode(const Technique *t) const {
    // Currently we assume that we can find a decent
    // write primitive such as read(0, bss, 0x400)
    // to write the 2nd stage rop payload to bss, so
    // after stack pivoting our rop chain can be built
    // without solving exploit constraints.
    return dynamic_cast<const StackPivot *>(t);
}

bool RopChainBuilder::addRegisterConstraint(Register::X64 reg, const ref<Expr> &e) {
    uint64_t value = BinaryExprEvaluator<uint64_t>().evaluate(e);
    auto regExpr = m_ctx.reg().readSymbolic(reg);
    auto constraint = EqExpr::create(regExpr, ConstantExpr::create(value, Expr::Int64));

    log<INFO>()
        << m_ctx.reg().getName(reg) << " = "
        << BinaryExprEvaluator<std::string>().evaluate(e)
        << " (concretized=" << klee::hexval(value) << ")\n";

    return m_ctx.getCurrentState()->addConstraint(constraint, true);
}

bool RopChainBuilder::addMemoryConstraint(uint64_t addr, const ref<Expr> &e) {
    uint64_t value = BinaryExprEvaluator<uint64_t>().evaluate(e);
    auto memExpr = m_ctx.mem().readSymbolic(addr, klee::Expr::Int64);
    auto constraint = EqExpr::create(memExpr, ConstantExpr::create(value, Expr::Int64));

    log<INFO>()
        << "[RSP + " << m_symbolicModeRspOffset << "] = "
        << BinaryExprEvaluator<std::string>().evaluate(e)
        << " (concretized=" << klee::hexval(value) << ")\n";

    return m_ctx.getCurrentState()->addConstraint(constraint, true);
}

}  // namespace s2e::plugins::crax