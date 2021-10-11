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
#include <s2e/Plugins/Requiem/Disassembler.h>
#include <s2e/Plugins/Requiem/Exploit.h>

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
    llvm::raw_ostream &log() const;

    template <>
    llvm::raw_ostream &log<LogLevel::INFO>() const { return g_s2e->getInfoStream(m_state); }

    template <>
    llvm::raw_ostream &log<LogLevel::DEBUG>() const { return g_s2e->getDebugStream(m_state); }

    template <>
    llvm::raw_ostream &log<LogLevel::WARN>() const { return g_s2e->getWarningsStream(m_state); }


    S2EExecutionState *state() { return m_state; }
    pybind11::module &pwnlib() { return m_pwnlib; }
    RegisterManager &reg() { return m_registerManager; }
    MemoryManager &mem() { return m_memoryManager; }

    Disassembler &getDisassembler() { return m_disassembler; }
    Exploit &getExploit() { return m_exploit; }

    uint64_t getTargetProcessPid() const { return m_targetProcessPid; }
    const std::vector<uint64_t> &getReadPrimitives() const { return m_readPrimitives; }
    const std::vector<uint64_t> &getWritePrimitives() const { return m_writePrimitives; }

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


    void onTranslateInstructionEnd(ExecutionSignal *onInstructionExecute,
                                   S2EExecutionState *state,
                                   TranslationBlock *tb,
                                   uint64_t pc);

    void instructionHook(S2EExecutionState *state, uint64_t pc);
    void syscallHook(S2EExecutionState *state, uint64_t pc);

    void generateExploit();


    // S2E
    S2EExecutionState *m_state;

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
    uint64_t m_targetProcessPid;

    std::unique_ptr<Strategy> m_strategy;
    std::vector<uint64_t> m_readPrimitives;
    std::vector<uint64_t> m_writePrimitives;

public:
    uint64_t m_padding;
    uint64_t m_sysReadBuf;
    uint64_t m_sysReadSize;
};

}  // namespace s2e::plugins::requiem

#endif  // S2E_PLUGINS_REQUIEM_H
