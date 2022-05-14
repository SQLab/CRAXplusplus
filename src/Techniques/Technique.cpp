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
#include <s2e/Plugins/CRAX/Techniques/GotLeakLibc.h>
#include <s2e/Plugins/CRAX/Techniques/OneGadget.h>
#include <s2e/Plugins/CRAX/Techniques/Ret2csu.h>
#include <s2e/Plugins/CRAX/Techniques/Ret2stack.h>
#include <s2e/Plugins/CRAX/Techniques/Ret2syscall.h>
#include <s2e/Plugins/CRAX/Techniques/StackPivoting.h>

#include <cassert>
#include <algorithm>

#include "Technique.h"

namespace s2e::plugins::crax {

std::map<std::type_index, Technique*> Technique::s_mapper;

void Technique::initialize() {
    blockUntilRequiredGadgetsPopulated();

    resolveRequiredGadgets();
}

bool Technique::checkRequirements() const {
    const Exploit &exploit = g_crax->getExploit();

    blockUntilRequiredGadgetsPopulated();

    return std::all_of(m_requiredGadgets.begin(),
                       m_requiredGadgets.end(),
                       [&exploit](const auto &entry) {
                           return exploit.resolveGadget(*entry.first, entry.second);
                       });
}

void Technique::resolveRequiredGadgets() {
    Exploit &exploit = g_crax->getExploit();

    for (const auto &[elfPtr, gadgetAsm] : m_requiredGadgets) {
        const ELF &elf = *elfPtr;

        std::string varName = Exploit::toVarName(elf, gadgetAsm);
        uint64_t offset = exploit.resolveGadget(elf, gadgetAsm);

        exploit.registerSymbol(varName, offset);
    }
}

std::string Technique::getConfigKey() const {
    return g_crax->getConfigKey() + ".techniquesConfig." + toString();
}

std::unique_ptr<Technique> Technique::create(const std::string &name) {
    std::unique_ptr<Technique> ret;

    if (name == "GotLeakLibc") {
        ret = std::make_unique<GotLeakLibc>();
    } else if (name == "OneGadget") {
        ret = std::make_unique<OneGadget>();
    } else if (name == "AdvancedStackPivoting") {
        ret = std::make_unique<AdvancedStackPivoting>();
    } else if (name == "BasicStackPivoting") {
        ret = std::make_unique<BasicStackPivoting>();
    } else if (name == "Ret2csu") {
        ret = std::make_unique<Ret2csu>();
    } else if (name == "Ret2syscall") {
        ret = std::make_unique<Ret2syscall>();
    } else if (name == "Ret2stack") {
        ret = std::make_unique<Ret2stack>();
    }

    assert(ret && "Technique::create() failed, incorrect technique name given in config?");

    auto &technique = *ret;
    Technique::s_mapper.insert({typeid(technique), &technique});
    return ret;
}

}  // namespace s2e::plugins::crax
