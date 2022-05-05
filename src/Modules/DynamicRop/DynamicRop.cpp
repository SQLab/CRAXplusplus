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
#include <s2e/Plugins/CRAX/Modules/IOStates/IOStates.h>

#include "DynamicRop.h"

using namespace klee;

namespace s2e::plugins::crax {

DynamicRop::DynamicRop()
    : Module(),
      m_currentConstraintGroup() {
    auto iostates = CRAX::getModule<IOStates>();

    if (!iostates) {
        log<WARN>() << "Please load IOStates before DynamicRop\n";
        exit(1);
    }

    g_crax->beforeExploitGeneration.connect(
            sigc::mem_fun(*this, &DynamicRop::beforeExploitGeneration));
}


DynamicRop &DynamicRop::addConstraint(DynamicRop::ConstraintPtr c) {
    m_currentConstraintGroup.push_back(std::move(c));
    return *this;
}

void DynamicRop::commitConstraints() {
    auto modState = g_crax->getModuleState(g_crax->getCurrentState(), this);
    assert(modState);

    modState->constraintsQueue.push(std::move(m_currentConstraintGroup));
}


void DynamicRop::applyNextConstraintGroup(S2EExecutionState &state) {
    auto iostates = CRAX::getModule<IOStates>();
    assert(iostates);

    auto modState = g_crax->getModuleState(&state, this);
    assert(modState);

    if (modState->constraintsQueue.empty()) {
        log<WARN>() << "No more dynamic ROP constraints to apply.\n";
        return;
    }

    log<WARN>() << "Adding dynamic ROP constraints...\n";
    for (const auto &c : modState->constraintsQueue.front()) {
        bool ok = false;
        auto ce = dyn_cast<ConstantExpr>(c->expr);

        uint64_t userElfBase = iostates->getUserSpecifiedElfBase();
        uint64_t rebasedAddr = maybeRebaseAddr(state, ce->getZExtValue(), userElfBase);

        ref<Expr> guestExpr = ce;
        ref<Expr> rebasedExpr = ConstantExpr::create(rebasedAddr, Expr::Int64);

        if (auto mc = std::dynamic_pointer_cast<MemoryConstraint>(c)) {
            ok = RopPayloadBuilder::addMemoryConstraint(state, mc->addr, rebasedExpr);
            mem().writeSymbolic(mc->addr, c->expr);
        } else if (auto rc = std::dynamic_pointer_cast<RegisterConstraint>(c)) {
            ok = RopPayloadBuilder::addRegisterConstraint(state, rc->reg, rebasedExpr);
            reg().writeSymbolic(rc->reg, c->expr);
        }

        if (!ok) {
            g_s2e->getExecutor()->terminateState(state, "Dynamic ROP failed");
        }
    }

    modState->constraintsQueue.pop();

    // To make the target program restart at the address we've specified,
    // we need to throw a CpuExitException to invalidate the current translation block.
    throw CpuExitException();
}

void DynamicRop::beforeExploitGeneration(S2EExecutionState *state) {
    assert(state);
    applyNextConstraintGroup(*state);
}


uint64_t DynamicRop::maybeRebaseAddr(S2EExecutionState &state,
                                     uint64_t guestVirtualAddress,
                                     uint64_t userSpecifiedElfBase) const {
    const ELF &elf = g_crax->getExploit().getElf();
    const auto &vmmap = mem(&state).vmmap();
    auto it = vmmap.find(guestVirtualAddress);
    uint64_t ret = guestVirtualAddress;

    // XXX: Currently it only checks whether `guestVirtualAddress` is
    // an ELF address. If we want to rebase libc addresses as well,
    // we should also add support for user-specified libc base.
    bool isElfAddress = it != vmmap.end() &&
                        (*it)->moduleName == VirtualMemoryMap::s_elfLabel;

    if (userSpecifiedElfBase && isElfAddress) {
        ret = elf.rebaseAddress(guestVirtualAddress, userSpecifiedElfBase);
    }

    return ret;
}

}  // namespace s2e::plugins::crax
