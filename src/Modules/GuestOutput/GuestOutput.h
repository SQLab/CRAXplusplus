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

#ifndef S2E_PLUGINS_CRAX_GUEST_OUTPUT_H
#define S2E_PLUGINS_CRAX_GUEST_OUTPUT_H

#include <s2e/S2EExecutionState.h>
#include <s2e/Plugins/CRAX/Modules/Module.h>

#include <unistd.h>

namespace s2e::plugins::crax {

// When a concolic execution proxy is used, ~/s2e/projects/*/serial.txt
// will only contain the output of the proxy itself, not the output of
// the target binary. This module hooks the write() and writev() syscalls
// and prints the target binary's output to host's stdout/stderr.

class GuestOutput : public Module {
public:
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


    GuestOutput();
    virtual ~GuestOutput() override = default;

    virtual std::string toString() const override {
        return "GuestOutput";
    }

private:
    void onWrite(S2EExecutionState *state,
                 const SyscallCtx &syscall);

    void onWritev(S2EExecutionState *state,
                  const SyscallCtx &syscall);

    inline bool isValidFd(int fd) {
        return fd == STDOUT_FILENO || fd == STDERR_FILENO;
    }
};

}  // namespace s2e::plugins::crax

#endif  // S2E_PLUGINS_CRAX_GUEST_OUTPUT_H
