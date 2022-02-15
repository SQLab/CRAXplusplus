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

#include <s2e/CorePlugin.h>
#include <s2e/Plugins/CRAX/CRAX.h>

#include <string>

#include "SymbolicAddressMap.h"

using namespace klee;

namespace s2e::plugins::crax {

SymbolicAddressMap::SymbolicAddressMap()
    : Module(),
      m_nrSymbolicAddresses(),
      m_entries() {
    // Install symbolic address handler.
    //g_s2e->getCorePlugin()->onSymbolicAddress.connect(
    //        sigc::mem_fun(*this, &SymbolicAddressMap::onSymbolicAddress));
}

void SymbolicAddressMap::onSymbolicAddress(S2EExecutionState *state,
                                           klee::ref<klee::Expr> virtualAddress,
                                           uint64_t concreteAddress,
                                           bool &concretize,
                                           CorePlugin::symbolicAddressReason reason) {
    if (reason != CorePlugin::symbolicAddressReason::MEMORY) {
        return;
    }

    log<WARN>()
        << "Detected symbolic pointer: " << hexval(concreteAddress)
        //<< ", expr: " << virtualAddress
        << '\n';

    auto &os = log<WARN>();
    os << "Dumping state->symbolics\n"
        << "Name\taddress\tsize\n";

    for (ArrayPtr array : state->symbolics) {
        os << array->getName() << '\t'
            //<< hexval(array->address) << '\t'
            << hexval(array->getSize()) << '\n';
    }

    os << "Dumping state->addressSpace.objects\n"
        << "Name\taddress\tsize\n";

    const auto &objects = state->addressSpace.objects;

    //for (auto it = objects.begin(); it != objects.end(); it++) {
    for (const auto &entry : objects) {
        //ObjectStateConstPtr o = *it;

        const auto &objState = entry.second;

        if (objState->getName().size()) {
            os << objState->getName() << '\t'
                << hexval(objState->getAddress()) << '\t'
                << objState->getSize() << '\n';
        }
    }

    if (m_nrSymbolicAddresses++ == 1) {
        g_s2e->getExecutor()->terminateState(*state, "Symbolic Pointer WIP QQ");
    }

    //m_counter++;

    /*
    // Hijack branch condition recursively until there are no more symbolic addresses.
    std::string name = "SA" + std::to_string(m_counter);
    state->createSymbolicArray(A, 8, name);
    Entry entry;
    entry.tmpAddress = A;
    entry.targetArray = findSymbolicObjects(state)->second;
    entry.targetExpr = E;
    entry.tmpArray = findSymbolicObjects(name)->second;
    entry.tmpExpr = Expr::createTempRead(*entry.tmpArray, Expr::Int64);
    m_entries.push_back(std::move(entry));
    */
}

}  // namespace s2e::plugins::crax
