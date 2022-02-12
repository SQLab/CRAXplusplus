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
#include <s2e/Plugins/CRAX/Exploit.h>
#include <s2e/Plugins/CRAX/Techniques/Ret2csu.h>
#include <s2e/Plugins/CRAX/Techniques/StackPivot.h>
#include <s2e/Plugins/CRAX/Techniques/GotPartialOverwrite.h>
#include <s2e/Plugins/CRAX/Techniques/GotLeakLibc.h>
#include <s2e/Plugins/CRAX/Techniques/OneGadget.h>

#include <cassert>
#include <algorithm>

#include "Technique.h"

namespace s2e::plugins::crax {

std::map<std::type_index, Technique*> Technique::s_mapper;

bool Technique::checkRequirements() const {
    const Exploit &exploit = g_crax->getExploit();

    return std::all_of(m_requiredGadgets.begin(),
                       m_requiredGadgets.end(),
                       [&exploit](const auto &entry) {
                           return exploit.resolveGadget(*entry.first, entry.second);
                       });
}

void Technique::resolveRequiredGadgets() {
    Exploit &exploit = g_crax->getExploit();

    for (const auto &entry : m_requiredGadgets) {
        const ELF &elf = *entry.first;
        const std::string &gadget = entry.second;

        std::string varName = Exploit::toVarName(entry.second);
        exploit.registerSymbol(varName, exploit.resolveGadget(elf, gadget));
    }
}

std::unique_ptr<Technique> Technique::create(const std::string &name) {
    std::unique_ptr<Technique> ret;

    if (name == "Ret2csu") {
        ret = std::make_unique<Ret2csu>();
    } else if (name == "BasicStackPivot") {
        ret = std::make_unique<BasicStackPivot>();
    } else if (name == "AdvancedStackPivot") {
        ret = std::make_unique<AdvancedStackPivot>();
    } else if (name == "GotPartialOverwrite") {
        ret = std::make_unique<GotPartialOverwrite>();
    } else if (name == "GotLeakLibc") {
        ret = std::make_unique<GotLeakLibc>();
    } else if (name == "OneGadget") {
        ret = std::make_unique<OneGadget>();
    }

    assert(ret && "Technique::create() failed, incorrect technique name given in config?");

    auto &technique = *ret;
    Technique::s_mapper.insert({typeid(technique), &technique});
    return ret;
}

}  // namespace s2e::plugins::crax
