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

#ifndef S2E_PLUGINS_CRAX_IO_STATES_H
#define S2E_PLUGINS_CRAX_IO_STATES_H

#include <s2e/S2EExecutionState.h>
#include <s2e/Plugins/CRAX/Modules/Module.h>

#include <array>
#include <string>
#include <vector>
#include <variant>

namespace s2e::plugins::crax {

// This is an implementation of "IOState" from balsn's LAEG, but adapted
// to S2E's multi-path execution environment. We renamed it to IOState"s"
// because an execution path con contain more than just one I/O state.
//
// The sequence of I/O states of each execution path is stored in the
// vector `IOStates::State::stateInfoList`, i.e., each path has its
// own list of I/O states.
//
// Reference:
// [1] Mow Wei Loon. Bypassing ASLR with Dynamic Binary Analysis for
//     Automated Exploit Generation (2021)

class IOStates : public Module {
public:
    enum LeakType {
        UNKNOWN,
        CODE,
        LIBC,
        HEAP,
        STACK,
        CANARY,
        LAST
    };

    struct InputStateInfo {
        uint64_t offset;
    };

    struct OutputStateInfo {
        bool isInteresting;
        uint64_t bufIndex;
        uint64_t baseOffset;
        LeakType leakType;
    };

    struct SleepStateInfo {
        __kernel_time64_t sec;
    };

    using StateInfo = std::variant<InputStateInfo, OutputStateInfo, SleepStateInfo>;


    class State : public ModuleState {
    public:
        State()
            : ModuleState(),
              leakableOffset(),
              lastInputStateInfoIdx(),
              lastInputStateInfoIdxBeforeFirstSymbolicRip(-1),
              currentLeakTargetIdx(),
              stateInfoList() {}

        virtual ~State() override = default;

        static ModuleState *factory(Module *, CRAXState *) {
            return new State();
        }

        virtual ModuleState *clone() const override {
            return new State(*this);
        }

        void dump() const;

        std::string toString() const;

        // XXX: maybe make these data members private?
        uint64_t leakableOffset;
        uint32_t lastInputStateInfoIdx;
        uint32_t lastInputStateInfoIdxBeforeFirstSymbolicRip;
        uint32_t currentLeakTargetIdx;
        std::vector<StateInfo> stateInfoList;
    };


    IOStates();
    virtual ~IOStates() override = default;

    virtual bool checkRequirements() const override;
    virtual std::unique_ptr<CoreGenerator> makeCoreGenerator() const override;
    virtual std::string toString() const override { return "IOStates"; }

    uint64_t getCanary() const { return m_canary; }
    uint64_t getUserSpecifiedCanary() const { return m_userSpecifiedCanary; }
    uint64_t getUserSpecifiedElfBase() const { return m_userSpecifiedElfBase; }

    const std::vector<LeakType> &getLeakTargets() const {
        return m_leakTargets;
    }

    static std::string toString(LeakType leakType) {
        return s_leakTypes[leakType];
    }

    static const std::array<std::string, LeakType::LAST> s_leakTypes;

private:
    std::vector<StateInfo> initUserSpecifiedStateInfoList();

    void inputStateHookTopHalf(S2EExecutionState *inputState,
                               SyscallCtx &syscall);

    void inputStateHookBottomHalf(S2EExecutionState *inputState,
                                  const SyscallCtx &syscall);

    void outputStateHook(S2EExecutionState *outputState,
                         const SyscallCtx &syscall);

    void sleepStateHook(S2EExecutionState *sleepState,
                        const SyscallCtx &syscall);

    void maybeInterceptStackCanary(S2EExecutionState *state,
                                   const Instruction &i);

    void onStackChkFailed(S2EExecutionState *state,
                          const Instruction &i);

    void onStateForkModuleDecide(S2EExecutionState *state,
                                 const klee::ref<klee::Expr> &__condition,
                                 bool &allowForking);

    void beforeExploitGeneration(S2EExecutionState *state);


    // Called at input states.
    std::array<std::vector<uint64_t>, IOStates::LeakType::LAST>
    analyzeLeak(S2EExecutionState *inputState, uint64_t buf, uint64_t len);

    // Called at output states.
    std::vector<IOStates::OutputStateInfo>
    detectLeak(S2EExecutionState *outputState, uint64_t buf, uint64_t len);

    bool hasLeakedAllRequiredInfo(S2EExecutionState *state) const;

    LeakType getLeakType(const std::string &image) const;


    // The targets that must be leaked according to checksec.
    std::vector<LeakType> m_leakTargets;

    // Intercepted canary (guest).
    uint64_t m_canary;

    // User-specified canary and ELF base (host).
    uint64_t m_userSpecifiedCanary;
    uint64_t m_userSpecifiedElfBase;

    // User-specified stateInfoList.
    // If the user has defined this in s2e-config.lua, then the
    // "IOStates" module will not fork at input states. Instead,
    // it will follow the input offsets specified by the user.
    std::vector<StateInfo> m_userSpecifiedStateInfoList;
};

}  // namespace s2e::plugins::crax

#endif  // S2E_PLUGINS_CRAX_IO_STATES_H
