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
#include <s2e/Plugins/CRAX/Utils/StringUtil.h>

#include "CoreGenerator.h"

using namespace klee;

namespace s2e::plugins::crax {

void CoreGenerator::generateMainFunction(S2EExecutionState *state,
                                         const std::vector<RopPayload> &ropPayload) {
    handleStage1(ropPayload);
    g_crax->getExploit().writeline("proc.recvrepeat(0)\n");
    handleStage2(ropPayload);
}

void CoreGenerator::handleStage1(const std::vector<RopPayload> &ropPayload) {
    Exploit &exploit = g_crax->getExploit();
    Process &process = exploit.getProcess();

    assert(ropPayload[0].size() == 1);
    std::string stage1 = evaluate<std::string>(ropPayload[0][0]);

    exploit.writelines({
        format("payload  = %s", stage1.c_str()),
        process.toDeclStmt(),
    });

    // If the proxy in use is SYM_STDIN, then we have to explicitly
    // send our payload to the stdin of the target process.
    if (g_crax->getProxy() == CRAX::Proxy::SYM_STDIN) {
        exploit.writelines({
            "proc.send(payload)",
            "time.sleep(0.2)"
        });
    }
}

void CoreGenerator::handleStage2(const std::vector<RopPayload> &ropPayload) {
    Exploit &exploit = g_crax->getExploit();

    for (size_t i = 1; i < ropPayload.size(); i++) {
        if (auto le = dyn_cast<LambdaExpr>(ropPayload[i][0])) {
            assert(ropPayload[i].size() == 1);
            std::invoke(*le);
        } else {
            for (const ref<Expr> &e : ropPayload[i]) {
                exploit.appendRopPayload(evaluate<std::string>(e));
            }
            exploit.flushRopPayload();
        }
    }
}

}  // namespace s2e::plugins::crax
