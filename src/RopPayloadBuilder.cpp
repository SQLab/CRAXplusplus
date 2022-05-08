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
#include <s2e/Plugins/CRAX/Expr/BinaryExprEval.h>
#include <s2e/Plugins/CRAX/Techniques/Technique.h>
#include <s2e/Plugins/CRAX/Techniques/StackPivoting.h>

#include <cassert>

#include "RopPayloadBuilder.h"

using namespace klee;

namespace s2e::plugins::crax {

RopPayloadBuilder::RopPayloadBuilder()
    : m_hasAddedConstraints(),
      m_isSymbolicMode(true),
      m_shouldSkipSavedRbp(),
      m_rspOffset(),
      m_ropPayload() {}


void RopPayloadBuilder::reset() {
    m_hasAddedConstraints = false;
    m_isSymbolicMode = true;
    m_shouldSkipSavedRbp = false;
    m_rspOffset = 0;
    m_ropPayload.clear();
}

bool RopPayloadBuilder::chain(const Technique &technique) {
    std::vector<RopPayload> ropPayloadList = technique.getRopPayloadList();

    // Not all exploitation techniques have a ROP formula,
    // so we'll return true here.
    if (ropPayloadList.empty()) {
        return true;
    }

    RopPayload extraRopPayload = technique.getExtraRopPayload();
    bool shouldSwitch = shouldSwitchToDirectMode(&technique, ropPayloadList);

    return m_isSymbolicMode ? chainSymbolic(ropPayloadList, extraRopPayload, shouldSwitch)
                            : chainDirect(ropPayloadList, extraRopPayload);
}

const std::vector<RopPayload> &RopPayloadBuilder::build() {
    if (m_isSymbolicMode) {
        buildStage1Payload();
    }

    while (m_ropPayload.size() && m_ropPayload.back().empty()) {
        m_ropPayload.pop_back();
    }

    return m_ropPayload;
}

bool RopPayloadBuilder::chainSymbolic(const std::vector<RopPayload> &ropPayloadList,
                                      const RopPayload &extraRopPayload,
                                      bool shouldSwitchMode) {
    bool ok;
    S2EExecutionState *state = g_crax->getCurrentState();
    uint64_t rsp = reg(state).readConcrete(Register::X64::RSP);

    // Treat S-Expr trees in ropPayloadList[0] as ROP constraints
    // and add them to the exploitable S2EExecutionState.
    log<INFO>() << "Adding exploit constraints...\n";
    for (size_t i = 0; i < ropPayloadList[0].size(); i++) {
        if (i == 0) {
            ok = addRegisterConstraint(*state, Register::X64::RBP, ropPayloadList[0][i]);
        } else if (i == 1) {
            ok = addRegisterConstraint(*state, Register::X64::RIP, ropPayloadList[0][i]);
        } else {
            ok = addMemoryConstraint(*state, rsp + m_rspOffset, ropPayloadList[0][i]);
            m_rspOffset += sizeof(uint64_t);
        }

        if (!ok) {
            return false;
        }
    }

    m_hasAddedConstraints = true;

    if (!shouldSwitchMode) {
        return true;
    }

    log<INFO>() << "Switching to direct mode...\n";
    if (!buildStage1Payload()) {
        return false;
    }
    m_ropPayload.push_back({});
    m_isSymbolicMode = false;
    m_rspOffset = 0;

    // Chain the rest (i.e. ropPayloadList[1..last]).
    if (ropPayloadList.size() > 1) {
        doChainDirect(ropPayloadList, extraRopPayload, 1);
    }

    return true;
}

bool RopPayloadBuilder::chainDirect(const std::vector<RopPayload> &ropPayloadList,
                                    const RopPayload &extraRopPayload) {
    doChainDirect(ropPayloadList, extraRopPayload);
    return true;
}

void RopPayloadBuilder::doChainDirect(const std::vector<RopPayload> &ropPayloadList,
                                      const RopPayload &extraRopPayload,
                                      size_t ropPayloadListBegin) {
    size_t i = ropPayloadListBegin;
    size_t j = m_shouldSkipSavedRbp;
    uint64_t newRspOffset = m_rspOffset;

    // The first expr in ropPayloadList[0] is saved RBP.
    // It should only be used for constructing the very first ROP payload.
    if (!m_shouldSkipSavedRbp) {
        m_shouldSkipSavedRbp = true;
    }

    for (; i < ropPayloadList.size(); i++, j = 0) {
        if (ropPayloadList[i].empty()) {
            continue;
        }

        m_ropPayload.back().reserve(ropPayloadList[i].size());

        for (; j < ropPayloadList[i].size(); j++) {
            ref<Expr> e = ropPayloadList[i][j];

            // If `e` is a PlaceholderExpr, turn it into a ConstantExpr.
            // Sometimes an offset in the ROP payload cannot be hardcoded,
            // because the user may chain different techniques in different
            // orders, resulting in a non-fixed offset.
            maybeConcretizePlaceholderExpr(e);

            m_ropPayload.back().push_back(e);
            newRspOffset += e->getWidth() / 8;
        }

        if (i != ropPayloadList.size() - 1) {
            m_ropPayload.push_back({});
        }
    }

    if (extraRopPayload.size()) {
        m_ropPayload.push_back(extraRopPayload);
    }

    m_ropPayload.push_back({});
    m_rspOffset = newRspOffset;
}

void RopPayloadBuilder::maybeConcretizePlaceholderExpr(ref<Expr> &e) const {
    using BaseType = BaseOffsetExpr::BaseType;

    auto phe = dyn_cast<PlaceholderExpr<uint64_t>>(e);

    if (!phe) {
        return;
    }

    const Exploit &exploit = g_crax->getExploit();
    const ELF &elf = exploit.getElf();
    uint64_t offset = phe->getUserData();

    e = AddExpr::alloc(
            BaseOffsetExpr::create<BaseType::VAR>(elf, "pivot_dest"),
            ConstantExpr::create(sizeof(uint64_t) + m_rspOffset + offset, Expr::Int64));
}

bool RopPayloadBuilder::shouldSwitchToDirectMode(const Technique *t,
                                                 const std::vector<RopPayload> &ropPayloadList) const {
    // Currently we assume that we can find a decent write primitive
    // such as read@plt to write the 2nd stage ROP payload to bss,
    // so after stack pivoting our ROP payload can be built without
    // solving ROP constraints.
    return dynamic_cast<const StackPivoting *>(t) ||
           ropPayloadList.size() > 1;
}

bool RopPayloadBuilder::buildStage1Payload() {
    // No constraints have been added, so there's no need to proceed.
    if (!m_hasAddedConstraints) {
        return false;
    }

    S2EExecutionState *state = g_crax->getCurrentState();
    ConcreteInput payload = getOneConcreteInput(*state);

    if (payload.empty()) {
        log<WARN>() << "Sorry, the exploit constraints are unsatisfiable.\n";
        return false;
    }

    m_ropPayload.push_back({ ByteVectorExpr::create(payload) });
    return true;
}


bool RopPayloadBuilder::addRegisterConstraint(S2EExecutionState &state,
                                              Register::X64 r,
                                              const ref<Expr> &e) {
    if (!e) {
        log<INFO>() << "Leaving " << reg(&state).getName(r) << " unconstrained\n";
        return true;
    }

    // Build the constraint.
    ref<Expr> target = reg(&state).readSymbolic(r, e->getWidth());
    ref<ConstantExpr> value = concretizeExpr(e);
    auto constraint = EqExpr::create(target, value);

    log<INFO>()
        << "Constraining " << reg(&state).getName(r)
        << " to " << evaluate<std::string>(e)
        << " (concretized=" << hexval(value->getZExtValue()) << ")\n";

    return state.addConstraint(constraint, true);
}

bool RopPayloadBuilder::addMemoryConstraint(S2EExecutionState &state,
                                            uint64_t addr,
                                            const ref<Expr> &e) {
    if (!e) {
        log<INFO>() << "Leaving " << hexval(addr) << " unconstrained\n";
        return true;
    }

    // Build the constraint.
    ref<Expr> target = mem(&state).readSymbolic(addr, e->getWidth());
    ref<ConstantExpr> value = concretizeExpr(e);
    auto constraint = EqExpr::create(target, value);

    log<INFO>()
        << "Constraining " << hexval(addr)
        << " to " << evaluate<std::string>(e)
        << " (concretized=" << hexval(value->getZExtValue()) << ")\n";

    return state.addConstraint(constraint, true);
}

ref<ConstantExpr> RopPayloadBuilder::concretizeExpr(const ref<Expr> &e) {
    if (auto ce = dyn_cast<ConstantExpr>(e)) {
        return ce;
    } else {
        return ConstantExpr::create(evaluate<uint64_t>(e), Expr::Int64);
    }
}

RopPayloadBuilder::ConcreteInputs
RopPayloadBuilder::getConcreteInputs(S2EExecutionState &state) {
    // FIXME: To integrate tl455047's adaptive symbolic input selection with this,
    // replace the use of `getSymbolicSolution()` with TestCaseGenerator.
    // See: testcase_generator_register_concrete_file().
    ConcreteInputs ret;
    state.getSymbolicSolution(ret);
    return ret;
}

RopPayloadBuilder::ConcreteInput
RopPayloadBuilder::getOneConcreteInput(S2EExecutionState &state) {
    ConcreteInputs inputs = getConcreteInputs(state);
    return inputs.size() ? inputs[0].second : ConcreteInput {};
}

const RopPayloadBuilder::ConcreteInput &
RopPayloadBuilder::getStage1Payload(const std::vector<RopPayload> &ropPayload) {
    auto bve = dyn_cast<ByteVectorExpr>(ropPayload[0][0]);
    assert(bve);
    return bve->getBytes();
}

}  // namespace s2e::plugins::crax
