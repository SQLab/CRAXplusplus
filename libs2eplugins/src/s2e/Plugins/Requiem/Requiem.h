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

#include <s2e/Plugin.h>
#include <s2e/Plugins/Core/BaseInstructions.h>
#include <s2e/Plugins/OSMonitors/Linux/LinuxMonitor.h>
#include <s2e/Plugins/ExecutionMonitors/StackMonitor.h>
#include <s2e/Plugins/Requiem/Core/RegisterManager.h>
#include <s2e/Plugins/Requiem/Core/MemoryManager.h>
#include <s2e/Plugins/Requiem/Strategies/Strategy.h>
#include <s2e/Plugins/Requiem/Behaviors.h>
#include <s2e/Plugins/Requiem/Disassembler.h>
#include <s2e/Plugins/Requiem/Exploit.h>
#include <s2e/Plugins/Requiem/RopChainBuilder.h>

#include <pybind11/embed.h>

#include <memory>
#include <string>

namespace s2e::plugins::requiem {

// Logging
enum LogLevel {
    INFO,
    DEBUG,
    WARN,
};

class Requiem : public Plugin, IPluginInvoker {
    S2E_PLUGIN

public:
    Requiem(S2E *s2e);
    void initialize();

    template <enum LogLevel T>
    llvm::raw_ostream &log(S2EExecutionState *state = nullptr) const;

    template <>
    llvm::raw_ostream &log<LogLevel::INFO>(S2EExecutionState *state) const {
        return state ? getInfoStream(state) : getInfoStream(m_currentState);
    }

    template <>
    llvm::raw_ostream &log<LogLevel::DEBUG>(S2EExecutionState *state) const {
        return state ? getDebugStream(state) : getDebugStream(m_currentState);
    }

    template <>
    llvm::raw_ostream &log<LogLevel::WARN>(S2EExecutionState *state) const {
        return state ? getWarningsStream(state) : getWarningsStream(m_currentState);
    }


    [[nodiscard]]
    S2EExecutionState *getCurrentState() { return m_currentState; }

    void setCurrentState(S2EExecutionState *state) { m_currentState = state; }

    [[nodiscard]]
    pybind11::module &pwnlib() { return m_pwnlib; }

    [[nodiscard]]
    RegisterManager &reg() { return m_registerManager; }

    [[nodiscard]]
    MemoryManager &mem() { return m_memoryManager; }

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
        instructionHooks;

    sigc::signal<void,
                 S2EExecutionState*,
                 uint64_t /* rax */,
                 uint64_t /* rdi */,
                 uint64_t /* rsi */,
                 uint64_t /* rdx */,
                 uint64_t /* r10 */,
                 uint64_t /* r8 */,
                 uint64_t /* r9 */>
        syscallHooks;
    // clang-format on

private:
    // Allow the guest to communicate with this plugin using s2e_invoke_plugin
    virtual void handleOpcodeInvocation(S2EExecutionState *state,
                                        uint64_t guestDataPtr,
                                        uint64_t guestDataSize) {}

    void onProcessLoad(S2EExecutionState *state,
                       uint64_t cr3,
                       uint64_t pid,
                       const std::string &imageFileName);

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

    void onExecuteInstructionEnd(S2EExecutionState *state,
                                 uint64_t pc);

    void onExecuteSyscallEnd(S2EExecutionState *state,
                             uint64_t pc);

    [[nodiscard]]
    bool generateExploit();

 
    // S2E
    S2EExecutionState *m_currentState;

    // S2E built-in plugins.
    LinuxMonitor *m_linuxMonitor;

    // Embedded Python interpreter from pybind11 library.
    pybind11::scoped_interpreter m_pybind11;
    pybind11::module m_pwnlib;

    // Requiem's attributes.
    RegisterManager m_registerManager;
    MemoryManager m_memoryManager;
    Exploit m_exploit;
    Disassembler m_disassembler;
    RopChainBuilder m_ropChainBuilder;
    uint64_t m_targetProcessPid;

    // Exploitation-specific attributes.
    std::unique_ptr<Strategy> m_strategy;
    std::vector<std::unique_ptr<Behavior>> m_ioBehaviors;
    std::vector<uint64_t> m_readPrimitives;
    std::vector<uint64_t> m_writePrimitives;
};

}  // namespace s2e::plugins::requiem

#endif  // S2E_PLUGINS_REQUIEM_H
