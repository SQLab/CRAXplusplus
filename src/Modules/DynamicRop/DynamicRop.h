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

#include <llvm/ADT/SmallVector.h>
#include <s2e/Plugins/CRAX/API/Memory.h>
#include <s2e/Plugins/CRAX/API/Register.h>
#include <s2e/Plugins/CRAX/Modules/Module.h>

#include <memory>
#include <queue>
#include <vector>

namespace s2e::plugins::crax {

// Allows a module to explore deeper execution paths by performing ROP
// within the guest. It is called "dynamic" because we are performing
// dynamic analysis and ROP at once, where ROP is used as a means of
// path exploration.
class DynamicRop : public Module {
public:
    struct Constraint {
        virtual ~Constraint() = default;
        klee::ref<klee::Expr> expr;

    protected:
        Constraint(klee::ref<klee::Expr> expr) : expr(expr) {}
    };

    struct RegisterConstraint : public Constraint {
        RegisterConstraint(Register::X64 reg, klee::ref<klee::Expr> expr)
            : Constraint(expr),
              reg(reg) {}

        virtual ~RegisterConstraint() override = default;
        Register::X64 reg;
    };

    struct MemoryConstraint : public Constraint {
        MemoryConstraint(uint64_t addr, klee::ref<klee::Expr> expr)
            : Constraint(expr),
              addr(addr) {}

        virtual ~MemoryConstraint() override = default;
        uint64_t addr;
    };

    using ConstraintPtr = std::shared_ptr<Constraint>;
    using ConstraintGroup = llvm::SmallVector<ConstraintPtr, 8>;


    class State : public ModuleState {
    public:
        State()
            : ModuleState(),
              initialized(),
              constraintsQueue() {}

        virtual ~State() override = default;

        static ModuleState *factory(Module *, CRAXState *) {
            return new State();
        }

        virtual ModuleState *clone() const override {
            return new State(*this);
        }

        bool initialized;
        std::queue<ConstraintGroup> constraintsQueue;
    };


    DynamicRop();
    virtual ~DynamicRop() override = default;

    virtual std::string toString() const override { return "DynamicRop"; }

    // Add one constraint to `m_constraintGroup`.
    DynamicRop &addConstraint(ConstraintPtr c);

    // Commit all the constraints in `m_constraintGroup`,
    // appending them to `modState->constraintsQueue`.
    void commitConstraints();

    // Fetch the first element in `modState->constraintsQueue`,
    // and add all the constraints to `state`.
    void applyNextConstraintGroup(S2EExecutionState &state);

private:
    void beforeExploitGeneration(S2EExecutionState *state);

    uint64_t maybeRebaseAddr(S2EExecutionState &state,
                             uint64_t guestVirtualAddress,
                             uint64_t userSpecifiedElfBase) const;

    ConstraintGroup m_currentConstraintGroup;
};

}  // namespace s2e::plugins::crax

#endif  // S2E_PLUGINS_CRAX_DYNAMIC_ROP_H
