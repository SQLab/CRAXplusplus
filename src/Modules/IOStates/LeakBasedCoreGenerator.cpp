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

#include "LeakBasedCoreGenerator.h"

using namespace klee;

namespace s2e::plugins::crax {

void LeakBasedCoreGenerator::generateMainFunction(S2EExecutionState *state,
                                                  std::vector<RopSubchain> ropChain,
                                                  std::vector<uint8_t> stage1) {
    Exploit &exploit = g_crax->getExploit();
    const auto &checksec = exploit.getElf().getChecksec();

    auto iostates = dynamic_cast<IOStates *>(CRAX::getModule("IOStates"));
    assert(iostates);

    auto modState = g_crax->getPluginModuleState(state, iostates);
    assert(modState);

    // The number of bytes already removed from the input stream.
    // XXX: encapsulate this...
    uint64_t nrConsumedBytes = 0;
    uint64_t nrTotalBytes = 0;

    for (size_t i = 0; i < modState->stateInfoList.size(); i++) {
        using InputStateInfo = IOStates::InputStateInfo;
        using OutputStateInfo = IOStates::OutputStateInfo;
        exploit.writeline();

        const auto &info = modState->stateInfoList[i];

        if (const auto stateInfo = std::get_if<InputStateInfo>(&info)) {
            if (i != modState->lastInputStateInfoIdx &&
                modState->lastInputStateInfoIdxBeforeFirstSymbolicRip != -1 &&
                i >= modState->lastInputStateInfoIdxBeforeFirstSymbolicRip) {
                exploit.writeline(format("# input state (offset = %d), skipping", stateInfo->offset));
                nrTotalBytes += stateInfo->offset;
                continue;
            }

            exploit.writeline(format("# input state (offset = %d)", stateInfo->offset));

            // XXX: remove inputstateinfo->buf
            std::string byteString = toByteString(stage1.begin() + nrConsumedBytes,
                                                  stage1.begin() + nrConsumedBytes + stateInfo->offset);

            if (i != modState->lastInputStateInfoIdx) {
                exploit.writeline(format("proc.send(%s)", byteString.c_str()));
                nrConsumedBytes += stateInfo->offset;
                nrTotalBytes += stateInfo->offset;
                continue;
            }

            exploit.writeline("# rop chain");
            for (size_t j = 0; j < ropChain.size(); j++) {
                if (j == 0) {
                    if (checksec.hasCanary || checksec.hasPIE) {
                        std::string fuck;
                        if (nrConsumedBytes == nrTotalBytes) {
                            fuck = format("payload  = solve_stage1(canary, elf_base, '%s')[%d:]",
                                          modState->toString().c_str(), nrConsumedBytes);
                        } else {
                            fuck = format("payload  = solve_stage1(canary, elf_base, '%s')[%d:%d]",
                                          modState->toString().c_str(), nrConsumedBytes, nrTotalBytes);
                        }
                        exploit.writeline(fuck);
                        exploit.flushRopPayload();

                    } else if (ropChain[0].size()) {
                        assert(ropChain[0].size() == 1);

                        auto bve = dyn_cast<ByteVectorExpr>(ropChain[0][0]);
                        stage1 = bve->getBytes();
                        stage1 = std::vector<uint8_t>(stage1.begin() + nrConsumedBytes, stage1.end());

                        std::string s = evaluate<std::string>(ByteVectorExpr::create(stage1));
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
