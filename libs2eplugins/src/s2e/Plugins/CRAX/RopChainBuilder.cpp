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
#include <s2e/Plugins/CRAX/Expr/BinaryExprEvaluator.h>
#include <s2e/Plugins/CRAX/Techniques/Technique.h>
#include <s2e/Plugins/CRAX/Techniques/StackPivot.h>

#include <cassert>

#include "RopChainBuilder.h"

using namespace klee;

namespace s2e::plugins::crax {

using RopSubchain = Technique::RopSubchain;

RopChainBuilder::RopChainBuilder(CRAX &ctx)
    : m_ctx(ctx),
      m_isSymbolicMode(true),
      m_shouldSkipSavedRbp(),
      m_rspOffset(),
      m_ropChain() {}


void RopChainBuilder::reset() {
    m_isSymbolicMode = true;
    m_shouldSkipSavedRbp = false;
    m_rspOffset = 0;
    m_ropChain.clear();
}

bool RopChainBuilder::chain(const Technique &technique) {
    // Not all exploitation techniques have a ROP formula,
    // so we'll return true here.
    if (technique.getRopSubchains().empty()) {
        return true;
    }

    return m_isSymbolicMode ? doChainSymbolic(technique)
                            : doChainDirect(technique);
}

const std::vector<RopSubchain> &RopChainBuilder::build() const {
    return m_ropChain;
}


bool RopChainBuilder::doChainSymbolic(const Technique &technique) {
    bool ok;
    uint64_t rsp = m_ctx.reg().readConcrete(Register::X64::RSP);
    std::vector<RopSubchain> ropSubchains = technique.getRopSubchains();

    // Treat S-Expr trees in ropoSubchains[0] as ROP constraints
    // and add them to the exploitable S2EExecutionState.
    log<INFO>() << "Building ROP constraints...\n";
    for (size_t i = 0; i < ropSubchains[0].size(); i++) {
        if (i == 0) {
            ok = addRegisterConstraint(Register::X64::RBP, ropSubchains[0][i]);
        } else if (i == 1) {
            ok = addRegisterConstraint(Register::X64::RIP, ropSubchains[0][i]);
        } else {
            ok = addMemoryConstraint(rsp + m_rspOffset, ropSubchains[0][i]);
            m_rspOffset += 8;
        }

        if (!ok) {
            return false;
        }
    }

    if (!shouldSwitchToDirectMode(&technique)) {
        return true;
    }

    log<INFO>() << "Switching to direct mode...\n";
    m_isSymbolicMode = false;

    ConcreteInput payload = getFirstConcreteInput();
    if (payload.size()) {
        m_ropChain.push_back({ ByteVectorExpr::create(payload) });
        m_ropChain.push_back({});
    } else {
        log<WARN>() << "Sorry, the ROP constraints are unsatisfiable :(\n";
        return false;
    }

    if (ropSubchains.size() > 1) {
        m_ropChain.push_back({});
    }

    for (size_t i = 1; i < ropSubchains.size(); i++) {
        for (const ref<Expr> &e : ropSubchains[i]) {
            m_ropChain.back().push_back(e);
        }
        if (i != ropSubchains.size() - 1) {
            m_ropChain.push_back({});
        }
    }

    return true;
}

bool RopChainBuilder::doChainDirect(const Technique &technique) {
    std::vector<RopSubchain> ropSubchains = technique.getRopSubchains();

    // The first expr in ropSubchains[0] is saved RBP.
    // It should only be used for constructing the very first ROP subchain.
    size_t j = 1;
    if (!m_shouldSkipSavedRbp) {
        m_shouldSkipSavedRbp = true;
        j = 0;
    }

    if (m_ropChain.empty()) {
        m_ropChain.push_back({});
    }

    for (size_t i = 0; i < ropSubchains.size(); i++, j = 0) {
        for (; j < ropSubchains[i].size(); j++) {
            m_ropChain.back().push_back(ropSubchains[i][j]);
        }
        if (i != ropSubchains.size() - 1) {
            m_ropChain.push_back({});
        }
    }

    if (technique.getExtraRopSubchain().size()) {
        m_ropChain.push_back({});
    }

    for (const ref<Expr> &e : technique.getExtraRopSubchain()) {
        log<INFO>() << evaluate<std::string>(e) << '\n';
        m_ropChain.back().push_back(e);
    }

    return true;
}

bool RopChainBuilder::shouldSwitchToDirectMode(const Technique *t) const {
    // Currently we assume that we can find a decent write primitive
    // such as read@plt to write the 2nd stage rop payload to bss,
    // so after stack pivoting our rop chain can be built without
    // solving ROP constraints.
    return dynamic_cast<const StackPivot *>(t);
}


bool RopChainBuilder::addRegisterConstraint(Register::X64 reg,
                                            const ref<Expr> &e) {
    uint64_t value = evaluate<uint64_t>(e);
    auto regExpr = m_ctx.reg().readSymbolic(reg);
    auto constraint = EqExpr::create(regExpr,
                                     ConstantExpr::create(value, Expr::Int64));

    log<INFO>()
        << m_ctx.reg().getName(reg) << " = "
        << evaluate<std::string>(e)
        << " (concretized=" << klee::hexval(value) << ")\n";

    return m_ctx.getCurrentState()->addConstraint(constraint, true);
}

bool RopChainBuilder::addMemoryConstraint(uint64_t addr,
                                          const ref<Expr> &e) {
    uint64_t value = evaluate<uint64_t>(e);
    auto memExpr = m_ctx.mem().readSymbolic(addr, klee::Expr::Int64);
    auto constraint = EqExpr::create(memExpr,
                                     ConstantExpr::create(value, Expr::Int64));

    log<INFO>()
        << "[RSP + " << m_rspOffset << "] = "
        << evaluate<std::string>(e)
        << " (concretized=" << klee::hexval(value) << ")\n";

    return m_ctx.getCurrentState()->addConstraint(constraint, true);
}

RopChainBuilder::ConcreteInputs RopChainBuilder::getConcreteInputs() {
    ConcreteInputs ret;
    m_ctx.getCurrentState()->getSymbolicSolution(ret);
    return ret;
}

RopChainBuilder::ConcreteInput RopChainBuilder::getFirstConcreteInput() {
    ConcreteInputs inputs = getConcreteInputs();
    return inputs.size() ? inputs[0].second : ConcreteInput {};
}

}  // namespace s2e::plugins::crax
