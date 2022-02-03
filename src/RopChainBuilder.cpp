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

RopChainBuilder::RopChainBuilder()
    : m_isSymbolicMode(true),
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

    return m_isSymbolicMode ? chainSymbolic(technique)
                            : chainDirect(technique);
}

const std::vector<RopSubchain> &RopChainBuilder::build() {
    if (m_isSymbolicMode) {
        buildStage1Payload();
    }

    return m_ropChain;
}

bool RopChainBuilder::chainSymbolic(const Technique &technique) {
    S2EExecutionState *state = g_crax->getCurrentState();

    std::vector<RopSubchain> ropSubchains = technique.getRopSubchains();
    RopSubchain extraRopSubchain = technique.getExtraRopSubchain();

    bool ok;
    uint64_t rsp = reg().readConcrete(Register::X64::RSP);

    // Treat S-Expr trees in ropoSubchains[0] as ROP constraints
    // and add them to the exploitable S2EExecutionState.
    log<INFO>() << "Adding ROP constraints...\n";
    for (size_t i = 0; i < ropSubchains[0].size(); i++) {
        if (i == 0) {
            ok = addRegisterConstraint(*state, Register::X64::RBP, ropSubchains[0][i]);
        } else if (i == 1) {
            ok = addRegisterConstraint(*state, Register::X64::RIP, ropSubchains[0][i]);
        } else {
            ok = addMemoryConstraint(*state, rsp + m_rspOffset, ropSubchains[0][i]);
            m_rspOffset += 8;
        }

        if (!ok) {
            return false;
        }
    }

    if (ropSubchains[0].empty()) {
        m_ropChain.push_back({});
    } else if (!buildStage1Payload()) {
        return false;
    }

    if (!shouldSwitchToDirectMode(&technique)) {
        return true;
    }

    log<INFO>() << "Switching to direct mode...\n";
    m_isSymbolicMode = false;

    // Chain the rest (i.e. ropSubchains[1..last]).
    if (ropSubchains.size() > 1) {
        m_ropChain.push_back({});
        doChainDirect(ropSubchains, extraRopSubchain, 1);
    }

    return true;
}

bool RopChainBuilder::chainDirect(const Technique &technique) {
    doChainDirect(technique.getRopSubchains(), technique.getExtraRopSubchain());
    return true;
}

void RopChainBuilder::doChainDirect(const std::vector<RopSubchain> &ropSubchains,
                                    const RopSubchain &extraRopSubchain,
                                    size_t ropSubchainsBegin) {
    size_t i = ropSubchainsBegin;
    size_t j = m_shouldSkipSavedRbp;

    // The first expr in ropSubchains[0] is saved RBP.
    // It should only be used for constructing the very first ROP subchain.
    if (!m_shouldSkipSavedRbp) {
        m_shouldSkipSavedRbp = true;
    }

    if (m_ropChain.empty()) {
        m_ropChain.push_back({});
    }

    for (; i < ropSubchains.size(); i++, j = 0) {
        if (ropSubchains[i].empty()) {
            continue;
        }

        for (; j < ropSubchains[i].size(); j++) {
            m_ropChain.back().push_back(ropSubchains[i][j]);
        }

        if (i != ropSubchains.size() - 1) {
            m_ropChain.push_back({});
        }
    }

    if (extraRopSubchain.size()) {
        m_ropChain.push_back({});
    }

    for (const ref<Expr> &e : extraRopSubchain) {
        m_ropChain.back().push_back(e);
    }
}

bool RopChainBuilder::shouldSwitchToDirectMode(const Technique *t) const {
    // Currently we assume that we can find a decent write primitive
    // such as read@plt to write the 2nd stage rop payload to bss,
    // so after stack pivoting our rop chain can be built without
    // solving ROP constraints.
    return dynamic_cast<const StackPivot *>(t);
}

bool RopChainBuilder::buildStage1Payload() {
    S2EExecutionState *state = g_crax->getCurrentState();
    ConcreteInput payload = getOneConcreteInput(*state);

    if (payload.empty()) {
        log<WARN>() << "Sorry, the ROP constraints are unsatisfiable :(\n";
        return false;
    }

    m_ropChain.push_back({ ByteVectorExpr::create(payload) });
    m_ropChain.push_back({});
    return true;
}


bool RopChainBuilder::addRegisterConstraint(S2EExecutionState &state,
                                            Register::X64 r,
                                            const ref<Expr> &e) {
    assert(e);

    // Concretize the given expression.
    uint64_t value = evaluate<uint64_t>(e);
    ref<ConstantExpr> ce = ConstantExpr::create(value, Expr::Int64);

    // Build the constraint.
    auto constraint = EqExpr::create(reg(&state).readSymbolic(r), ce);

    log<INFO>()
        << "Constraining " << reg(&state).getName(r)
        << " to " << evaluate<std::string>(e)
        << " (concretized=" << hexval(value) << ")\n";

    return state.addConstraint(constraint, true);
}

bool RopChainBuilder::addMemoryConstraint(S2EExecutionState &state,
                                          uint64_t addr,
                                          const ref<Expr> &e) {
    assert(e);

    // Concretize the given expression.
    uint64_t value = evaluate<uint64_t>(e);
    ref<ConstantExpr> ce = ConstantExpr::create(value, Expr::Int64);

    // Build the constraint.
    auto constraint = EqExpr::create(mem(&state).readSymbolic(addr, Expr::Int64), ce);

    log<INFO>()
        << "Constraining " << hexval(addr)
        << " to " << evaluate<std::string>(e)
        << " (concretized=" << hexval(value) << ")\n";

    return state.addConstraint(constraint, true);
}

RopChainBuilder::ConcreteInputs
RopChainBuilder::getConcreteInputs(S2EExecutionState &state) {
    ConcreteInputs ret;
    state.getSymbolicSolution(ret);
    return ret;
}

RopChainBuilder::ConcreteInput
RopChainBuilder::getOneConcreteInput(S2EExecutionState &state) {
    ConcreteInputs inputs = getConcreteInputs(state);
    return inputs.size() ? inputs[0].second : ConcreteInput {};
}

}  // namespace s2e::plugins::crax
