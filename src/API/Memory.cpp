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

#include <boost/algorithm/searching/knuth_morris_pratt.hpp>

#include "Memory.h"

using namespace klee;

namespace s2e::plugins::crax {

bool Memory::isSymbolic(uint64_t virtAddr, uint64_t size) const {
    return m_state->mem()->symbolic(virtAddr, size);
}

ref<Expr> Memory::readSymbolic(uint64_t virtAddr, Expr::Width size) const {
    return m_state->mem()->read(virtAddr, size);
}

std::vector<uint8_t> Memory::readConcrete(uint64_t virtAddr,
                                          uint64_t size,
                                          bool concretize) const {
    std::vector<uint8_t> ret(size);

    if (concretize) {
        if (!m_state->mem()->read(virtAddr, ret.data(), size)) {
            log<WARN>() << "Cannot read concrete data from memory: " << hexval(virtAddr) << '\n';
            ret.clear();
        }
    } else {
        // XXX: The performance seems fast enough even though I bruteforce it byte by byte,
        // but maybe we can optimize it directly in libs2ecore at some point.
        bool ok = false;
        for (uint64_t i = 0; i < size; i++) {
            if (isSymbolic(virtAddr + i, 1)) {
                // Read the underlying concrete bytes, but don't concretize them.
                ok = m_state->mem()->read(virtAddr + i, &ret[i], VirtualAddress, false);
            } else {
                ok = m_state->mem()->read(virtAddr + i, &ret[i], 1);
            }

            if (!ok) {
                ret[i] = 0;
            }
        }
    }

    return ret;
}

bool Memory::writeSymbolic(uint64_t virtAddr, const ref<Expr> &value) {
    bool success = m_state->mem()->write(virtAddr, value);
    if (!success) {
        log<WARN>() << "Cannot write symbolic data to memory: " << hexval(virtAddr) << '\n';
    }
    return success;
}

bool Memory::writeConcrete(uint64_t virtAddr, const std::vector<uint8_t> &bytes) {
    bool success = m_state->mem()->write(virtAddr, bytes.data(), bytes.size());
    if (!success) {
        log<WARN>() << "Cannot write concrete data to memory: " << hexval(virtAddr) << '\n';
    }
    return success;
}

bool Memory::isMapped(uint64_t virtAddr) const {
    return m_state->mem()->getHostAddress(virtAddr) != -1;
}

std::vector<uint64_t> Memory::search(const std::vector<uint8_t> &needle) const {
    const auto &_vmmap = vmmap();
    std::vector<uint64_t> ret;

    // Iterate over all the mapped memory regions.
    foreach2 (it, _vmmap.begin(), _vmmap.end()) {
        // XXX: Some regions might be unaccessible even though it's mapped,
        // which I believe this is a bug in S2E. Just in case this happens,
        // we'll use `Memory::isMapped()` to scan through every address
        // within this region until an accessible address is found.
        uint64_t start = it.start();
        uint64_t end = it.stop();

        while (!isMapped(start) && start < end) {
            ++start;
        }

        // If the entire region is not accessible, then
        // we don't have to do anything with this region.
        if (start >= end) {
            continue;
        }

        // Read the region concretely into `haystack`,
        // and use kmp algorithm to search all the occurences of `needle`.
        std::vector<uint8_t> haystack = readConcrete(start, end - start, /*concretize=*/false);

        auto its = boost::algorithm::knuth_morris_pratt_search(haystack.begin(),
                                                               haystack.end(),
                                                               needle.begin(),
                                                               needle.end());

        if (its.first == haystack.end() && its.second == haystack.end()) {
            continue;
        }

        ret.push_back((its.first - haystack.begin()) + start);
    }

    return ret;
}

std::map<uint64_t, uint64_t> Memory::getSymbolicMemory() const {
    // first:  The base address of a consecutive symbolic data.
    // second: The size of the symbolic data.
    std::map<uint64_t, uint64_t> ret;

    bool isPreviousByteConstant = true;
    uint64_t base = 0;
    uint64_t size = 0;
    const auto &__vmmap = vmmap();

    foreach2 (it, __vmmap.begin(), __vmmap.end()) {
        for (uint64_t addr = it.start(); addr <= it.stop(); addr++) {
            if (isSymbolic(addr, 1)) {
                // Start of a symbolic memory region.
                if (isPreviousByteConstant) {
                    base = addr;
                    size = 1;
                } else {
                    size++;
                }
                isPreviousByteConstant = false;
            } else {
                // End of a symbolic memory region.
                if (!isPreviousByteConstant) {
                    ret.insert(std::make_pair(base, size));
                }
                isPreviousByteConstant = true;
                continue;
            }
        }
    }

    return ret;
}

const VirtualMemoryMap &Memory::vmmap() const {
    m_vmmap.rebuild(m_state);
    return m_vmmap;
}

void Memory::showMapInfo() const {
    m_vmmap.rebuild(m_state);
    m_vmmap.dump(m_state);
}


Memory &mem(S2EExecutionState *state) {
    return g_crax->mem(state);
}

}  // namespace s2e::plugins::crax
