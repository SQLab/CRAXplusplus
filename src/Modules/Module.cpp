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
#include <s2e/Plugins/CRAX/Modules/CodeSelection/CodeSelection.h>
#include <s2e/Plugins/CRAX/Modules/DynamicRop/DynamicRop.h>
#include <s2e/Plugins/CRAX/Modules/IOStates/IOStates.h>
#include <s2e/Plugins/CRAX/Modules/GuestOutput/GuestOutput.h>
#include <s2e/Plugins/CRAX/Modules/SymbolicAddressMap/SymbolicAddressMap.h>

#include <cassert>
#include <type_traits>

#include "Module.h"

namespace s2e::plugins::crax {

std::map<std::type_index, Module *> Module::s_mapper;


ModuleState *Module::getModuleState(CRAXState *s, ModuleStateFactory f) const {
    return s->getModuleState(const_cast<Module *>(this), f);
}

std::string Module::getConfigKey() const {
    return g_crax->getConfigKey() + ".modulesConfig." + toString();
}


std::unique_ptr<Module> Module::create(const std::string &name) {
    std::unique_ptr<Module> ret;

    if (name == "CodeSelection") {
        ret = std::make_unique<CodeSelection>();
    } else if (name == "DynamicRop") {
        ret = std::make_unique<DynamicRop>();
    } else if (name == "IOStates") {
        ret = std::make_unique<IOStates>();
    } else if (name == "GuestOutput") {
        ret = std::make_unique<GuestOutput>();
    } else if (name == "SymbolicAddressMap") {
        ret = std::make_unique<SymbolicAddressMap>();
    }

    assert(ret && "Module::create() failed, incorrect module name given in config?");

    // It seems that we cannot write `typeid(*ret)` directly due to
    // [-Werror,-Wpotentially-evaluated-expression], so we have to add
    // a layer of indirection here...
    auto &mod = *ret;
    Module::s_mapper.insert({typeid(mod), &mod});
    return ret;
}

}  // namespace s2e::plugins::crax
