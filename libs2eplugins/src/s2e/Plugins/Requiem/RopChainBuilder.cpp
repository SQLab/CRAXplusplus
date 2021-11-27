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
#include <s2e/Plugins/Requiem/Core/RegisterManager.h>
#include <s2e/Plugins/Requiem/Expr/BinaryExprEvaluator.h>
#include <s2e/Plugins/Requiem/Techniques/Technique.h>
#include <s2e/Plugins/Requiem/Techniques/StackPivot.h>

#include <klee/Expr.h>

#include <string>

#include "RopChainBuilder.h"

using namespace klee;
using VarValuePair = std::pair<std::string, std::vector<uint8_t>>;
using ConcreteInputs = std::vector<VarValuePair>;

namespace s2e::plugins::requiem {

using SymbolicRopPayload = Technique::SymbolicRopPayload;
using ConcreteRopPayload = Technique::ConcreteRopPayload;


bool RopChainBuilder::build(Exploit &exploit,
                            const std::vector<Technique *> &techniques) {
    for (auto t : techniques) {
        std::vector<SymbolicRopPayload> symbolicRopPayloadList = t->getSymbolicRopPayloadList();

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
        m_ctx.log<WARN>() << "Allocating concrete rop payload list...\n";
        std::vector<ConcreteRopPayload> concreteRopPayloadList;

        m_ctx.log<WARN>() << "Concretizing rop payload list...\n";
        for (size_t i = 0; i < symbolicRopPayloadList.size(); i++) {
            concreteRopPayloadList.push_back({});

            for (size_t j = 0; j < symbolicRopPayloadList[i].size(); j++) {
                const ref<Expr> &e = symbolicRopPayloadList[i][j];
                uint64_t value = BinaryExprEvaluator<uint64_t>().evaluate(e);
                concreteRopPayloadList.back().push_back(value);
            }
        }

        m_ctx.log<WARN>() << "Building exploit constraints...\n";
        for (size_t i = 0; i < concreteRopPayloadList[0].size(); i++) {
            const ref<Expr> &e = symbolicRopPayloadList[0][i];
            uint64_t value = concreteRopPayloadList[0][i];
            m_ctx.log<INFO>() << BinaryExprEvaluator<std::string>().evaluate(e) << " (concretized=" << klee::hexval(value) << ")\n";

            if (i == 0) {
                if (!addRegisterConstraint(Register::RBP, value)) {
                    return false;
                }
            } else if (i == 1) {
                if (!addRegisterConstraint(Register::RIP, value)) {
                    return false;
                }
            } else {
                uint64_t addr = m_ctx.reg().readConcrete(Register::RSP) +
                                m_symbolicModeRspOffset;
                if (!addMemoryConstraint(addr, value)) {
                    return false;
                }
                m_symbolicModeRspOffset += 8;
            }
        }

        if (shouldSwitchToDirectMode(t)) {
            m_ctx.log<WARN>() << "Switching from symbolic mode to direct mode...\n";
            m_symbolicMode = false;

            ConcreteInputs newInput;
            if (!m_ctx.getCurrentState()->getSymbolicSolution(newInput)) {
                m_ctx.log<WARN>() << "Could not get symbolic solutions\n";
                return false;
            }

            std::string symbolicPayload = "b'";
            const VarValuePair &vp = newInput[0];
            for (const auto __byte : vp.second) {
                symbolicPayload += format("\\x%02x", __byte);
            }
            symbolicPayload += "'";
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


// XXX: jesus...
bool RopChainBuilder::shouldSwitchToDirectMode(const Technique *t) const {
    return dynamic_cast<const BasicStackPivot *>(t) ||
           dynamic_cast<const AdvancedStackPivot *>(t);
}

bool RopChainBuilder::addRegisterConstraint(Register reg, uint64_t value) {
    auto regExpr = m_ctx.reg().readSymbolic(reg);
    auto constraint = EqExpr::create(regExpr, ConstantExpr::create(value, Expr::Int64));
    return m_ctx.getCurrentState()->addConstraint(constraint, true);
}

bool RopChainBuilder::addMemoryConstraint(uint64_t virtAddr, uint64_t value) {
    auto memExpr = m_ctx.mem().readSymbolic(virtAddr, klee::Expr::Int64);
    auto constraint = EqExpr::create(memExpr, ConstantExpr::create(value, Expr::Int64));
    return m_ctx.getCurrentState()->addConstraint(constraint, true);
}

}  // namespace s2e::plugins::requiem
