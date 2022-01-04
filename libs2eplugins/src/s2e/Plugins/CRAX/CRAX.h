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

#ifndef S2E_PLUGINS_CRAX_H
#define S2E_PLUGINS_CRAX_H

#include <s2e/Plugin.h>
#include <s2e/Plugins/Core/BaseInstructions.h>
#include <s2e/Plugins/OSMonitors/ModuleDescriptor.h>
#include <s2e/Plugins/OSMonitors/Linux/LinuxMonitor.h>
#include <s2e/Plugins/ExecutionMonitors/StackMonitor.h>
#include <s2e/Plugins/CRAX/API/Register.h>
#include <s2e/Plugins/CRAX/API/Memory.h>
#include <s2e/Plugins/CRAX/API/Disassembler.h>
#include <s2e/Plugins/CRAX/API/Logging.h>
#include <s2e/Plugins/CRAX/Modules/Behaviors.h>
#include <s2e/Plugins/CRAX/Modules/IOStates.h>
#include <s2e/Plugins/CRAX/Techniques/Technique.h>
#include <s2e/Plugins/CRAX/Exploit.h>
#include <s2e/Plugins/CRAX/RopChainBuilder.h>

#include <pybind11/embed.h>

#include <memory>
#include <string>

namespace s2e::plugins::crax {

class CRAX : public Plugin, IPluginInvoker {
    S2E_PLUGIN

public:
    CRAX(S2E *s2e);
    void initialize();


    [[nodiscard]]
    S2EExecutionState *getCurrentState() { return m_currentState; }

    void setCurrentState(S2EExecutionState *state) { m_currentState = state; }

    [[nodiscard]]
    Register &reg() { return m_register; }

    [[nodiscard]]
    Memory &mem() { return m_memory; }

    [[nodiscard]]
    Disassembler &getDisassembler() { return m_disassembler; }

    [[nodiscard]]
    Exploit &getExploit() { return m_exploit; }

    [[nodiscard]]
    uint64_t getTargetProcessPid() const { return m_targetProcessPid; }

    [[nodiscard]]
    const std::vector<uint64_t> &getReadPrimitives() const { return m_readPrimitives; }

    [[nodiscard]]
    const std::vector<uint64_t> &getWritePrimitives() const { return m_writePrimitives; }


    // clang-format off
    sigc::signal<void,
                 S2EExecutionState*,
                 const Instruction&>
        beforeInstructionHooks;

    sigc::signal<void,
                 S2EExecutionState*,
                 const Instruction&>
        afterInstructionHooks;

    sigc::signal<void,
                 S2EExecutionState*,
                 uint64_t /* rax */,
                 uint64_t /* rdi */,
                 uint64_t /* rsi */,
                 uint64_t /* rdx */,
                 uint64_t /* r10 */,
                 uint64_t /* r8 */,
                 uint64_t /* r9 */>
        beforeSyscallHooks;

    sigc::signal<void,
                 S2EExecutionState*,
                 uint64_t /* rax */,
                 uint64_t /* rdi */,
                 uint64_t /* rsi */,
                 uint64_t /* rdx */,
                 uint64_t /* r10 */,
                 uint64_t /* r8 */,
                 uint64_t /* r9 */>
        afterSyscallHooks;
    // clang-format on

    // Embedded Python interpreter from pybind11 library.
    static pybind11::scoped_interpreter s_pybind11;
    static pybind11::module s_pwnlib;

private:
    // Allow the guest to communicate with this plugin using s2e_invoke_plugin
    virtual void handleOpcodeInvocation(S2EExecutionState *state,
                                        uint64_t guestDataPtr,
                                        uint64_t guestDataSize) {}

    void onProcessLoad(S2EExecutionState *state,
                       uint64_t cr3,
                       uint64_t pid,
                       const std::string &imageFileName);

    void onModuleLoad(S2EExecutionState *state,
                      const ModuleDescriptor &md);

    void onSymbolicRip(S2EExecutionState *state,
                       klee::ref<klee::Expr> symbolicRip,
                       uint64_t concreteRip,
                       bool &concretize,
                       CorePlugin::symbolicAddressReason reason);

    void onTranslateInstructionStart(ExecutionSignal *onInstructionExecute,
                                     S2EExecutionState *state,
                                     TranslationBlock *tb,
                                     uint64_t pc);

    void onTranslateInstructionEnd(ExecutionSignal *onInstructionExecute,
                                   S2EExecutionState *state,
                                   TranslationBlock *tb,
                                   uint64_t pc);

    void onExecuteInstructionStart(S2EExecutionState *state,
                                   uint64_t pc);

    void onExecuteInstructionEnd(S2EExecutionState *state,
                                 uint64_t pc);

    void onExecuteSyscallStart(S2EExecutionState *state);

    void onExecuteSyscallEnd(S2EExecutionState *state);

    [[nodiscard]]
    bool generateExploit();


    // S2E
    S2EExecutionState *m_currentState;
    LinuxMonitor *m_linuxMonitor;

    // CRAX's attributes.
    Register m_register;
    Memory m_memory;
    Disassembler m_disassembler;
    Exploit m_exploit;
    RopChainBuilder m_ropChainBuilder;
    IOStates m_ioStates;
    uint64_t m_targetProcessPid;

    // Exploitation-specific attributes.
    std::vector<std::shared_ptr<Technique>> m_techniques;
    std::vector<std::unique_ptr<Behavior>> m_ioBehaviors;
    std::vector<uint64_t> m_readPrimitives;
    std::vector<uint64_t> m_writePrimitives;
};

}  // namespace s2e::plugins::crax

#endif  // S2E_PLUGINS_CRAX_H
