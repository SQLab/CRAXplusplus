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
#include <s2e/Plugins/CRAX/Modules/IOStates.h>

#include <cassert>

#include "Module.h"

namespace s2e::plugins::crax {

std::map<std::string, Module *> Module::s_mapper;


ModuleState *Module::getModuleState(CRAXState *s, ModuleStateFactory f) const {
    return s->getModuleState(const_cast<Module *>(this), f);
}

std::string Module::getConfigKey() const {
    return g_crax->getConfigKey() + ".modulesConfig." + toString();
}


std::unique_ptr<Module> Module::create(const std::string &name) {
    std::unique_ptr<Module> ret;

    if (name == "IOStates") {
        ret = std::make_unique<IOStates>();
    }

    assert(ret && "Module::create() failed, possibly due to incorrect module name!");

    Module::s_mapper[name] = ret.get();
    return ret;
}

}  // namespace s2e::plugins::crax
