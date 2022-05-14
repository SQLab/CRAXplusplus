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

#ifndef S2E_PLUGINS_CRAX_SYMBOLIC_ADDRESS_MAP_H
#define S2E_PLUGINS_CRAX_SYMBOLIC_ADDRESS_MAP_H

#include <klee/Expr.h>
#include <s2e/S2EExecutionState.h>
#include <s2e/Plugins/CRAX/Modules/Module.h>

#include <vector>

namespace s2e::plugins::crax {

// This is an implementation of "Symbolic Address Map" from the original CRAX.
//
// Vanilla S2E cannot deal with symbolic pointers, so symbolic bytes that
// propagate through a symbolic pointer or a symbolic array index will be cut off.
//
// Whenever a branch condition with symbolic pointer or symbolic array index involved
// is executed, klee::Executor will try to "guess" the possible address which
// satisfies the branch constraint. However, in most cases, the executor will
// just keep forking states until the # of state forks has reached the maximum limit.
// Accordingly, we have to maintain a special "Symbolic Address Map" and
// perform constraint handling ourselves.
//
// Reference:
// [1] Meng-Wei Lin, Shih-Kung Huang. Exploiting Symbolic Locations for Abnormal
//     Execution Paths (2011)

class SymbolicAddressMap : public Module {
public:
    struct Entry {
        uint64_t tmpAddress;  // related address

        klee::ref<klee::Expr> tmpExpr;  // substituted expression
        const klee::Array *tmpArray;  // used to store major variable name of `tmpExpr`

        klee::ref<klee::Expr> targetExpr;  // original expression
        const klee::Array *targetArray;  // used to store major variable name of `targetExpr`

        uint64_t targetAddress;  // target address
        klee::ref<klee::Expr> targetValueExpr;  // the content of `targetAddress` in actual memory
    };


    class State : public ModuleState {
    public:
        State() : ModuleState() {}
        virtual ~State() override = default;

        static ModuleState *factory(Module *, CRAXState *) {
            return new State();
        }

        virtual ModuleState *clone() const override {
            return new State(*this);
        }
    };


    SymbolicAddressMap();
    virtual ~SymbolicAddressMap() override = default;

    virtual std::string toString() const override {
        return "SymbolicAddressMap";
    }

private:
    void onSymbolicAddress(S2EExecutionState *state,
                           klee::ref<klee::Expr> virtualAddress,
                           uint64_t concreteAddress,
                           bool &concretize,
                           CorePlugin::symbolicAddressReason reason);

    // XXX: Rename the following methods later.
    void adjust(S2EExecutionState *state);


    int m_nrSymbolicAddresses;
    std::vector<Entry> m_entries;
};

}  // namespace s2e::plugins::crax

#endif  // S2E_PLUGINS_CRAX_SYMBOLIC_ADDRESS_MAP_H
