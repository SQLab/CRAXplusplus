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

#include <llvm/ADT/SmallVector.h>
#include <s2e/S2EExecutionState.h>
#include <s2e/Plugins/CRAX/API/Register.h>
#include <s2e/Plugins/CRAX/Modules/Module.h>
#include <s2e/Plugins/ExecutionMonitors/FunctionMonitor.h>

#include <map>
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
    struct ConcretizedRegionDescriptor {
        llvm::SmallVector<std::pair<uint64_t, klee::ref<klee::Expr>>, 6> exprs;

        // The path constraints before concretization.
        klee::ConstraintManager constraints;
    };

public:
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

        void onFunctionCall(ConcretizedRegionDescriptor crd) {
            m_callStack.push(std::move(crd));
        }

        ConcretizedRegionDescriptor onFunctionRet() {
            auto ret = std::move(m_callStack.top());
            m_callStack.pop();
            return ret;
        }

    private:
        std::stack<ConcretizedRegionDescriptor> m_callStack;
    };


    CodeSelection();
    virtual ~CodeSelection() override = default;

    virtual bool checkRequirements() const override;
    virtual std::string toString() const override { return "CodeSelection"; }

private:
    // When calling a glibc function, the arguments may be pointers to
    // symbolic memory regions.
    //
    // Key: function name
    // Value: which registers (arguments) may point to symbolic regions.
    using Argv = llvm::SmallVector<Register::X64, 1>;
    using SymMemRegMap = std::map<std::string, Argv>;
    SymMemRegMap initSymMemRegMap();

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

    bool isCallingRegisteredLibraryFunction(uint64_t calleePc,
                                            std::string &symbolOut) const;

    Argv decideArgv(const std::string &symbol) const;

    uint64_t getSymBlockLen(S2EExecutionState *state, uint64_t ptr) const;


    std::vector<std::string> m_functions;
    SymMemRegMap m_symMemRegMap;
};

}  // namespace s2e::plugins::crax

#endif  // S2E_PLUGINS_CRAX_CODE_SELECTION_H
