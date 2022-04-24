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
    // but strangely, it doesn't define reverse iterators, so we'll do it ourselves.
    using const_reverse_iterator = std::reverse_iterator<const_iterator>;
    using reverse_iterator = std::reverse_iterator<iterator>;

    VirtualMemoryMap()
        : IntervalMap(s_alloc),
          m_memoryMap(),
          m_moduleMap(),
          m_libcRegion(),
          m_stackRegion() {}

    const_reverse_iterator rbegin() const { return const_reverse_iterator(end()); }
    const_reverse_iterator rend() const { return const_reverse_iterator(begin()); }
    reverse_iterator rbegin() { return reverse_iterator(end()); }
    reverse_iterator rend() { return reverse_iterator(begin()); }

    void initialize();
    void rebuild(S2EExecutionState *state);
    void dump(S2EExecutionState *state);

    uint64_t getModuleBaseAddress(uint64_t address) const;
    uint64_t getModuleEndAddress(uint64_t address) const;

    static const std::string s_elfLabel;
    static const std::string s_libcLabel;
    static const std::string s_sharedLibraryLabel;
    static const std::string s_ldsoLabel;
    static const std::string s_stackLabel;

private:
    void probeLibcRegion(S2EExecutionState *state);
    void probeStackRegion(S2EExecutionState *state);

    void fillBssRegion(S2EExecutionState *state);
    void fillDynamicLoaderRegions(S2EExecutionState *state);
    void fillLibcRegions(S2EExecutionState *state);
    void fillRemainingSharedLibsRegions(S2EExecutionState *state);
    void fillStackRegion(S2EExecutionState *state);

    // This cannot be a non-static variable because it's used by the
    // parent class but would be destroyed first, causing corruptions.
    static Allocator s_alloc;

    MemoryMap *m_memoryMap;
    ModuleMap *m_moduleMap;

    // [start, end)
    std::pair<uint64_t, uint64_t> m_libcRegion;
    std::pair<uint64_t, uint64_t> m_stackRegion;
};

}  // namespace s2e::plugins::crax


namespace std {

// TL;DR - The following extension to stl bridges compatibility between
//         llvm::IntervalMap, std::reverse_iterator and std::find_if()
//
// Because llvm::IntervalMap::const_iterator only defines `const operator*() const`,
// so the default std::find_if() can fail when it tries to dereference a
// reverse iterator in order to obtain the corresponding iterator.
// For the details, see: /usr/include/c++/9/bits/stl_iterator.h
//
// We add two partial specializations to std::find_if() w.r.t. both
// const_reverse_iterator and reverse_iterator, preventing std::find_if()
// from dereferencing our reverse iterators directly and causing compilation error.

using crax_vmmap = ::s2e::plugins::crax::VirtualMemoryMap;
using crax_vmmap_const_rit = crax_vmmap::const_reverse_iterator;
using crax_vmmap_rit = crax_vmmap::reverse_iterator;

template <typename InputIt, typename UnaryPredicate>
InputIt crax_vmmap_do_find_if(InputIt first, InputIt last, UnaryPredicate p) {
    for (; first != last; ++first) {
        auto it = std::next(first).base();
        if (p(*it)) {
            return first;
        }
    }
    return last;
}

template <typename UnaryPredicate>
crax_vmmap_const_rit
find_if(crax_vmmap_const_rit first, crax_vmmap_const_rit last, UnaryPredicate p) {
    return crax_vmmap_do_find_if(first, last, p);
}

template <typename UnaryPredicate>
crax_vmmap_rit
find_if(crax_vmmap_rit first, crax_vmmap_rit last, UnaryPredicate p) {
    return crax_vmmap_do_find_if(first, last, p);
}

}  // namespace std

#endif  // S2E_PLUGINS_CRAX_VIRTUAL_MEMORY_MAP_H
