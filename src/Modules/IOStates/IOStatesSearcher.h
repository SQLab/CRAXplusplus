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

#ifndef S2E_PLUGINS_CRAX_IO_STATES_SEARCHER_H
#define S2E_PLUGINS_CRAX_IO_STATES_SEARCHER_H

#include <klee/Searcher.h>
#include <s2e/S2EExecutionState.h>

#include <queue>

namespace s2e::plugins::crax {

// IOStates scheduler
class IOStatesSearcher : public klee::Searcher {
public:
    IOStatesSearcher();
    virtual ~IOStatesSearcher() override = default;

    virtual klee::ExecutionState &selectState() override;

    virtual void update(klee::ExecutionState *current,
                        const klee::StateSet &addedStates,
                        const klee::StateSet &removedStates) override;

    virtual bool empty() override { return m_outputStates.empty(); }

    virtual void printName(llvm::raw_ostream &os) override {
        os << "IOStates searcher\n";
    }

private:
    std::queue<S2EExecutionState *> m_stateQueue;
};

}  // namespace s2e::plugins::crax

#endif  // S2E_PLUGINS_CRAX_IO_STATES_SEARCHER_H
