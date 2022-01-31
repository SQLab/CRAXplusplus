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

#ifndef S2E_PLUGINS_CRAX_VIRTUAL_MEMORY_MAP_H
#define S2E_PLUGINS_CRAX_VIRTUAL_MEMORY_MAP_H

#include <llvm/ADT/IntervalMap.h>
#include <s2e/S2EExecutionState.h>
#include <s2e/Plugins/OSMonitors/Support/MemoryMap.h>
#include <s2e/Plugins/OSMonitors/Support/ModuleMap.h>

#include <functional>
#include <iterator>
#include <memory>
#include <string>

namespace s2e::plugins::crax {

struct RegionDescriptor {
    bool r, w, x;
    std::string moduleName;
};

// Using pointers to RegionDescriptors as the values of IntervalMap
// saves us from defining RegionDescriptor::operator{==,!=}().
using RegionDescriptorPtr = std::shared_ptr<RegionDescriptor>;

// VirtualMemoryMap, abbreviated as "VMMap" or "vmmap", provides
// the interface to enumerate the mapped memory regions including [stack],
// as well as associate the mapped memory regions with loaded modules.
class VirtualMemoryMap : public llvm::IntervalMap<uint64_t, RegionDescriptorPtr> {
public:
    // LLVM's IntervalMap supports bidirectional iterators: begin(), end(),
    // but strangely, it doesn't support reverse iterators, so we'll do it ourselves.
    using const_reverse_iterator = std::reverse_iterator<const_iterator>;
    using reverse_iterator = std::reverse_iterator<iterator>;

    VirtualMemoryMap()
        : IntervalMap(s_alloc),
          m_memoryMap(),
          m_moduleMap() {}

    const_reverse_iterator rbegin() const { return const_reverse_iterator(end()); }
    const_reverse_iterator rend() const { return const_reverse_iterator(begin()); }
    reverse_iterator rbegin() { return reverse_iterator(end()); }
    reverse_iterator rend() { return reverse_iterator(begin()); }

    void initialize();
    void rebuild(S2EExecutionState *state);
    void dump(S2EExecutionState *state);

    uint64_t getModuleBaseAddress(uint64_t address) const;

private:
    void probeDynamicLoaderRegions(S2EExecutionState *state);
    void probeLibcRegions(S2EExecutionState *state);
    void probeRemainingSharedLibsRegions(S2EExecutionState *state);
    void probeStackRegion(S2EExecutionState *state);

    // This cannot be a non-static variable because it's used by the
    // parent class but would be destroyed first, causing corruptions.
    static Allocator s_alloc;

    MemoryMap *m_memoryMap;
    ModuleMap *m_moduleMap;
};

}  // namespace s2e::plugins::crax


namespace std {

// In VirtualMemoryMap (which inherits from llvm::IntervalMap), we've added
// support for reverse iterators, but the code won't compile if we use them
// with std::find_if(). The problem is that if we pass std::reverse_iterator
// to std::find_if(), std::find_if() dereferences the reverse iterator, obtains
// a non-const reference to a RegionDescriptorPtr, and then tests it against
// the given unary predicate. However, both llvm::IntervalMap::{,const_}iterator
// only support the const version of operator*(), and when stl tries to bind
// a non-const reference to a const object, a compilation error will be emitted.
//
// There are two possible solutions:
//
// 1. Derive a new iterator (VirtualMemoryMap::iterator) and add
//    a non-const version of operator*().
//
// 2. Add a partial template specialization to std::find()
//    for VirtualMemoryMap::reverse_iterator.
//
// I'll use the second solution here since it's easier (and probably safer).

template <class UnaryPredicate>
::s2e::plugins::crax::VirtualMemoryMap::reverse_iterator
find_if(::s2e::plugins::crax::VirtualMemoryMap::reverse_iterator first,
        ::s2e::plugins::crax::VirtualMemoryMap::reverse_iterator last,
        UnaryPredicate p) {
    for (; first != last; ++first) {
        // Dereferencing VirtualMemoryMap::reverse_iterator will cause
        // reference binding problem at compile time. To avoid that,
        // convert it to a forward iterator first, and then we're safe to
        // dereference it.
        auto it = std::next(first).base();
        if (p(*it)) {
            return first;
        }
    }
    return last;
}

}  // namespace std

#endif  // S2E_PLUGINS_CRAX_VIRTUAL_MEMORY_MAP_H
