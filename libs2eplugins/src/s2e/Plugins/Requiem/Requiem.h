// Copyright (C) 2021-2022, Marco Wang
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

#ifndef S2E_PLUGINS_REQUIEM_H
#define S2E_PLUGINS_REQUIEM_H

#include <string>

#include <pybind11/embed.h>

#include <s2e/Plugin.h>
#include <s2e/Plugins/Core/BaseInstructions.h>
#include <s2e/Plugins/OSMonitors/Linux/LinuxMonitor.h>
#include <s2e/Plugins/Requiem/Disassembler.h>
#include <s2e/Plugins/Requiem/Exploit.h>

namespace s2e::plugins::requiem {

enum S2E_REQUIEM_COMMANDS {
    // TODO: customize list of commands here
    COMMAND_1
};

struct S2E_REQUIEM_COMMAND {
    S2E_REQUIEM_COMMANDS Command;
    union {
        // Command parameters go here
        uint64_t param;
    };
};


class Requiem : public Plugin, IPluginInvoker {
    S2E_PLUGIN

public:
    Requiem(S2E *s2e);
    void initialize();

private:
    void onProcessLoad(S2EExecutionState *state,
                       uint64_t cr3,
                       uint64_t pid,
                       const std::string &imageFileName);

    void onMemoryMap(S2EExecutionState *state,
                     uint64_t pid,
                     uint64_t start,
                     uint64_t size,
                     uint64_t prot);

    void onRipCorrupt(S2EExecutionState *state,
                      klee::ref<klee::Expr> virtualAddress,
                      uint64_t concreteAddress,
                      bool &concretize,
                      CorePlugin::symbolicAddressReason reason);


    void onTranslateInstructionEnd(ExecutionSignal *onInstructionExecute,
                                   S2EExecutionState *state,
                                   TranslationBlock *tb,
                                   uint64_t pc);

    void instructionHook(S2EExecutionState *state,
                         uint64_t pc);

    void syscallHook(S2EExecutionState *state,
                     uint64_t pc);

    // Allow the guest to communicate with this plugin using s2e_invoke_plugin
    virtual void handleOpcodeInvocation(S2EExecutionState *state,
                                        uint64_t guestDataPtr,
                                        uint64_t guestDataSize);


    pybind11::scoped_interpreter m_pybind11;
    pybind11::module m_pwnlib;

    LinuxMonitor* m_monitor;
    Disassembler m_disassembler;
    Exploit m_exploit;

    uint64_t m_target_process_pid;
};

}  // namespace s2e::plugins::requiem

#endif  // S2E_PLUGINS_REQUIEM_H
