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

#ifndef S2E_PLUGINS_CRAX_CODE_SELECTION_H
#define S2E_PLUGINS_CRAX_CODE_SELECTION_H

#include <s2e/S2EExecutionState.h>
#include <s2e/Plugins/CRAX/Modules/Module.h>
#include <s2e/Plugins/ExecutionMonitors/FunctionMonitor.h>

#include <stack>
#include <string>
#include <vector>
#include <utility>

namespace s2e::plugins::crax {

// In order to reduce the overhead of SMT solvers and speed up the process,
// code selection is used to temporarily concretize arguments of uninteresting
// functions. After the function returns, its arguments are symbolized again.
//
// Reference:
// [1] Po-Yen Huang, Shih-Kung Huang. Automated Exploit Generation for
//     Control-Flow Hijacking Attacks (2011)

class CodeSelection : public Module {
public:
    struct FuncCtx {
        std::string symbol;
        uint64_t rdi;
        klee::ConstraintManager constraints;
        klee::ref<klee::Expr> expr;
    };

    class State : public ModuleState {
        friend class CodeSelection;

    public:
        State() : ModuleState(), m_callStack() {}
        virtual ~State() override = default;

        static ModuleState *factory(Module *, CRAXState *) {
            return new State();
        }

        virtual ModuleState *clone() const override {
            return new State(*this);
        }

        void onFunctionCall(FuncCtx funcCtx) {
            m_callStack.push(std::move(funcCtx));
        }

        FuncCtx onFunctionRet() {
            FuncCtx ret = std::move(m_callStack.top());
            m_callStack.pop();
            return ret;
        }

    private:
        // Stores function symbols.
        std::stack<FuncCtx> m_callStack;
    };


    CodeSelection();
    virtual ~CodeSelection() override = default;

    virtual std::string toString() const override {
        return "CodeSelection";
    }

private:
    void onFunctionCall(S2EExecutionState *state,
                        const ModuleDescriptorConstPtr &callerModule,
                        const ModuleDescriptorConstPtr &calleeModule,
                        uint64_t callerPc,
                        uint64_t calleePc,
                        const FunctionMonitor::ReturnSignalPtr &onRet);

    void onFunctionReturn(S2EExecutionState *state,
                          const ModuleDescriptorConstPtr &retSiteModule,
                          const ModuleDescriptorConstPtr &retTargetModule,
                          uint64_t retSite);

    uint64_t guestStrlen(S2EExecutionState *state, uint64_t ptr);

    // The functions to intercept.
    std::vector<std::string> m_functions;
};

}  // namespace s2e::plugins::crax

#endif  // S2E_PLUGINS_CRAX_CODE_SELECTION_H
