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
#include <s2e/Plugins/CRAX/Utils/StringUtil.h>
#include <s2e/Plugins/CRAX/Utils/Subprocess.h>

#include "RopGadgetResolver.h"

using namespace klee;

namespace s2e::plugins::crax {

uint64_t RopGadgetResolver::resolveGadget(const ELF &elf, const std::string &gadgetAsm) const {
    if (auto cachedAddr = m_ropGadgetCache.lookup(&elf, gadgetAsm)) {
        return cachedAddr;
    }

    // Get the output of `ROPgadget --binary <m_elfFilename> | grep <keyword>`
    // and store it in `output`.
    subprocess::popen ropGadget("ROPgadget", {"--binary", elf.getFilename()});
    ropGadget.close();

    // Example entry:
    // 0x000000000040117d : pop rbp ; ret
    const std::string keyword = " : " + gadgetAsm;
    subprocess::popen grep("grep", { keyword });
    grep.stdin() << ropGadget.stdout().rdbuf();
    grep.close();

    std::string output = streamToString(grep.stdout());

    for (const auto &line : split(output, '\n')) {
        size_t firstSpaceIdx = line.find_first_of(" ");
        size_t asmBeginIdx = firstSpaceIdx + 3;  // skips " : "

        std::string addrStr = line.substr(0, firstSpaceIdx);
        std::string asmStr = line.substr(asmBeginIdx);

        // Look for an exact match.
        if (asmStr == gadgetAsm) {
            uint64_t addr = std::stoull(addrStr, nullptr, 0);
            m_ropGadgetCache.insert(&elf, gadgetAsm, addr);
            log<INFO>() << format("Resolved gadget: [0x%x] %s\n", addr, asmStr.c_str());
            return addr;
        }
    }

    log<WARN>() << "Cannot resolve gadget: " << gadgetAsm << "\n";
    return 0;
}

}  // namespace s2e::plugins::crax
