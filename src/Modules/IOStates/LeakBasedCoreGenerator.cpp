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

#include <s2e/Plugins/CRAX/CRAX.h>
#include <s2e/Plugins/CRAX/Expr/BinaryExprEval.h>
#include <s2e/Plugins/CRAX/Modules/IOStates/IOStates.h>
#include <s2e/Plugins/CRAX/Modules/IOStates/PseudoInputStream.h>
#include <s2e/Plugins/CRAX/Utils/StringUtil.h>

#include "LeakBasedCoreGenerator.h"

#include <variant>
#include <utility>

namespace s2e::plugins::crax {

using InputStateInfo = IOStates::InputStateInfo;
using OutputStateInfo = IOStates::OutputStateInfo;
using SleepStateInfo = IOStates::SleepStateInfo;


// Since InputStateInfo, OutputStateInfo and SleepStateInfo hold
// completely unrelated data, they are declared as std::variant
// instead of sharing a common base type. As a result we'll use
// std::visit() to visit and handle them separately.

struct IOStateInfoVisitor {
    // StateInfo handlers
    void operator()(const InputStateInfo &stateInfo);
    void operator()(const OutputStateInfo &stateInfo);
    void operator()(const SleepStateInfo &stateInfo);

    bool shouldSkipInputState() const;
    void handleStage1(const InputStateInfo &stateInfo);

    // Extra parameters
    LeakBasedCoreGenerator &coreGenerator;
    Exploit &exploit;
    const ELF &elf;
    const std::vector<RopPayload> &ropPayload;
    PseudoInputStream &inputStream;
    const IOStates::State &modState;
    const size_t i;  // the index of `stateInfo` in `modState.stateInfoList`
};


void IOStateInfoVisitor::operator()(const InputStateInfo &stateInfo) {
    // This bridges compatibility between IOStates and DynamicRop modules.
    // DynamicRop starts after the target program's RIP becomes symbolic
    // for the first time, and then the DynamicRop module adds constraints
    // to that execution state, making the target program perform ROP in S2E.
    // 
    // During dynamic ROP, the target program may trigger extra I/O states
    // that shouldn't occur during normal program execution. A good example is
    // that we make make it return to somewhere in main() again after RIP
    // has become symbolic for the first time.
    //
    // If all required information have already been leaked, then we should
    // just skip these extra I/O states (especially the input states).
    if (shouldSkipInputState()) {
        exploit.writeline(format("# input state (offset = %d), skipped", stateInfo.offset));
        inputStream.skip(stateInfo.offset);
        return;
    }

    exploit.writeline(format("# input state (offset = %d)", stateInfo.offset));

    if (i != modState.lastInputStateInfoIdx) {
        llvm::ArrayRef<uint8_t> bytes = inputStream.read(stateInfo.offset);
        std::string byteString = toByteString(bytes.begin(), bytes.end());

        exploit.writeline(format("proc.send(b'%s')", byteString.c_str()));
        return;
    }

    exploit.writeline("# input state (ROP payload begins)");
    handleStage1(stateInfo);
    exploit.writeline("proc.recvrepeat(0)\n");
    coreGenerator.handleStage2(ropPayload);
}

bool IOStateInfoVisitor::shouldSkipInputState() const {
    // If there are no input states at all, then the onSymbolicRip()
    // shouldn't have been triggered in the first place. In theory,
    // this won't happen, but I'll just leave this assertion here
    // for extra safety.
    assert(-1 != modState.lastInputStateInfoIdxBeforeFirstSymbolicRip);

    return i != modState.lastInputStateInfoIdx &&
           i >= modState.lastInputStateInfoIdxBeforeFirstSymbolicRip;
}

void IOStateInfoVisitor::handleStage1(const InputStateInfo &stateInfo) {
    uint64_t nrBytesRead = inputStream.getNrBytesRead();
    uint64_t nrBytesSkipped = inputStream.getNrBytesSkipped();

    std::string s;

    // Let's deal with the simplest case first (no canary and no PIE).
    if (!elf.checksec.hasCanary && !elf.checksec.hasPIE) {
        llvm::ArrayRef<uint8_t> bytes = inputStream.read(nrBytesSkipped + stateInfo.offset);
        s += evaluate<std::string>(ByteVectorExpr::create(bytes));
    } else {
        // If either canary or PIE is enabled, stage1 needs to be solved
        // on the fly at exploitation time.
        s += format("solve_stage1(canary, %s_base, '%s')", elf.getVarPrefix().c_str(),
                                                           modState.toString().c_str());
    }

    if (nrBytesRead || nrBytesSkipped) {
        s += '[';
        s += nrBytesRead ? std::to_string(nrBytesRead) : "";
        s += ':';
        s += nrBytesSkipped ? std::to_string(nrBytesRead + nrBytesSkipped) : "";
        s += ']';
    }

    exploit.appendRopPayload(s);
    exploit.flushRopPayload();
}

void IOStateInfoVisitor::operator()(const OutputStateInfo &stateInfo) {
    exploit.writeline("# output state");

    // This output state cannot leak anything.
    if (!stateInfo.isInteresting) {
        exploit.writeline("proc.recvrepeat(0.1)");
        return;
    }

    exploit.writeline("# leaking: " + IOStates::toString(stateInfo.leakType));
    exploit.writeline(format("proc.recv(%d)", stateInfo.bufIndex));

    // XXX: Add support for leaking libc via IOStates
    if (stateInfo.leakType == IOStates::LeakType::CANARY) {
        exploit.writeLeakCanary();
    } else {
        exploit.writeLeakElfBase(stateInfo.baseOffset);
    }

    // We still need to receive whatever that comes after
    // the canary or the address.
    exploit.writeline("proc.recvrepeat(0.1)");
}

void IOStateInfoVisitor::operator()(const SleepStateInfo &stateInfo) {
    exploit.writeline("# sleep state");
    exploit.writeline(format("sleep(%d)", stateInfo.sec));
}


void LeakBasedCoreGenerator::generateMainFunction(S2EExecutionState *state,
                                                  const std::vector<RopPayload> &ropPayload) {
    Exploit &exploit = g_crax->getExploit();
    Process &process = exploit.getProcess();

    auto iostates = CRAX::getModule<IOStates>();
    assert(iostates);

    auto modState = g_crax->getModuleState(state, iostates);
    assert(modState);

    PseudoInputStream inputStream(RopPayloadBuilder::getStage1Payload(ropPayload));
    exploit.writeline(process.toDeclStmt());

    for (size_t i = 0; i < modState->stateInfoList.size(); i++) {
        exploit.writeline();

        auto v = IOStateInfoVisitor{
            *this, exploit, exploit.getElf(), ropPayload, inputStream, *modState, i
        };

        std::visit(v, modState->stateInfoList[i]);
    }
}

}  // namespace s2e::plugins::crax
