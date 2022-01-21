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

#ifndef S2E_PLUGINS_CRAX_DYNAMIC_ROP_H
#define S2E_PLUGINS_CRAX_DYNAMIC_ROP_H

#include <s2e/Plugins/CRAX/API/Memory.h>
#include <s2e/Plugins/CRAX/API/Register.h>
#include <s2e/Plugins/CRAX/Modules/Module.h>

#include <memory>
#include <queue>
#include <vector>
#include <variant>

namespace s2e::plugins::crax {

// Allows a module to explore deeper execution paths by performing ROP
// within the guest. It is called "dynamic" because we are performing
// dynamic analysis and ROP at once, where ROP is used as a means of
// path exploration.
class DynamicRop : public Module {
public:
    struct RegisterConstraint {
        Register::X64 reg;
        klee::ref<klee::Expr> e;
    };

    struct MemoryConstraint {
        uint64_t addr;
        klee::ref<klee::Expr> e;
    };

    using Constraint = std::variant<RegisterConstraint, MemoryConstraint>;


    class State : public ModuleState {
    public:
        State() : constraintsQueue() {}
        virtual ~State() = default;

        static ModuleState *factory(Module *, CRAXState *) {
            return new State();
        }

        virtual ModuleState *clone() const override {
            return new State(*this);
        }

        std::queue<std::vector<Constraint>> constraintsQueue;
    };


    DynamicRop();
    virtual ~DynamicRop() = default;

    virtual std::string toString() const override { return "DynamicRop"; }

    // Constraint builder API
    DynamicRop &addConstraint(const Constraint &c);
    void scheduleConstraints();

private:
    void beforeExploitGeneration(S2EExecutionState *state);

    std::vector<Constraint> m_constraints;
};

}  // namespace s2e::plugins::crax

#endif  // S2E_PLUGINS_CRAX_DYNAMIC_ROP_H
