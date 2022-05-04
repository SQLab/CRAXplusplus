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

#include <s2e/Plugins/CRAX/Utils/StringUtil.h>

#include "Process.h"

#include <iterator>

namespace s2e::plugins::crax {

Process::Process(const std::string &ldFilename,
                 const std::string &elfFilename,
                 const std::string &libcFilename)
    : m_argv(createDefaultArgv(ldFilename, elfFilename)),
      m_env(createDefaultEnv(libcFilename)),
      m_isAslrEnabled(true) {}

Process::Argv Process::createDefaultArgv(const std::string &ldFilename,
                                         const std::string &elfFilename) const {
    // Example: ['./ld-2.24.so', './target']
    return {
        format("'%s'", ldFilename.c_str()),
        format("'%s'", elfFilename.c_str())
    };
}

Process::Env Process::createDefaultEnv(const std::string &libcFilename) const {
    // Example: {'LD_PRELOAD': './libc-2.24.so'}
    return {
        { "'LD_PRELOAD'", format("'%s'", libcFilename.c_str()) },
    };
}

std::string Process::toDeclStmt() const {
    std::string strArgv = argvToString();
    std::string strEnv = envToString();
    std::string strAslr = m_isAslrEnabled ? "True" : "False";

    return format("proc = process(argv=%s, env=%s, aslr=%s)",
            strArgv.c_str(), strEnv.c_str(), strAslr.c_str());
}

std::string Process::argvToString() const {
    std::string ret;
    ret += '[';
    for (auto it = m_argv.begin(); it != m_argv.end(); it++) {
        ret += *it;
        if (std::next(it) != m_argv.end()) {
            ret += ", ";
        }
    }
    return ret + ']';
}

std::string Process::envToString() const {
    std::string ret;
    ret += '{';
    for (auto it = m_env.begin(); it != m_env.end(); it++) {
        ret += it->first + ": " + it->second;
        if (std::next(it) != m_env.end()) {
            ret += ", ";
        }
    }
    return ret + '}';
}

}  // namespace s2e::plugins::crax
