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

#include "Proxy.h"

#include <cassert>

using namespace klee;

namespace s2e::plugins::crax {

const std::string Proxy::s_symArg = "sym_arg";
const std::string Proxy::s_symEnv = "sym_env";
const std::string Proxy::s_symFile = "sym_file";
const std::string Proxy::s_symSocket = "sym_socket";
const std::string Proxy::s_symStdin = "sym_stdin";

Proxy::Proxy()
    : m_type(Proxy::Type::NONE),
      m_payloadEnvKey(),
      m_destAddr(),
      m_destPort(),
      m_isTcp(),
      m_socketFd(),
      m_isBlockingSocket() {}


std::string Proxy::getConfigKey() const {
    return g_crax->getConfigKey() + ".proxy";
}

void Proxy::maybeDetectProxy(const std::string &imageFileName) {
    assert(m_type == Proxy::Type::NONE && "Proxy already set");

    // For SYM_ARG and SYM_ENV, the stage1 payload is sent as
    // command-line argument(s) and environment variable(s).
    if (imageFileName == s_symArg) {
        m_type = Type::SYM_ARG;
        loadSymArgConfig();
        g_crax->getExploit().getProcess().getArgv().push_back("payload");

    } else if (imageFileName == s_symEnv) {
        m_type = Type::SYM_ENV;
        loadSymEnvConfig();
        g_crax->getExploit().getProcess().getEnv().insert({"'placeholder'", "payload"});

    } else if (imageFileName == s_symFile) {
        m_type = Type::SYM_FILE;
        loadSymFileConfig();

    } else if (imageFileName == s_symSocket) {
        m_type = Type::SYM_SOCKET;
        loadSymSocketConfig();

        auto &proc = g_crax->getExploit().getProcess();
        proc.setRemoteMode(true);
        proc.setDestAddr(m_destAddr);
        proc.setDestPort(m_destPort);
        proc.setTcp(m_isTcp);

    } else if (imageFileName == s_symStdin) {
        m_type = Type::SYM_STDIN;
        loadSymStdinConfig();
    }
}

void Proxy::loadSymArgConfig() {

}

void Proxy::loadSymEnvConfig() {
    m_payloadEnvKey = CRAX_CONFIG_GET_STRING(".payloadEnvKey", "placeholder");
}

void Proxy::loadSymFileConfig() {

}

void Proxy::loadSymSocketConfig() {
    m_destAddr = CRAX_CONFIG_GET_STRING(".destAddr", "");
    m_destPort = CRAX_CONFIG_GET_INT(".destPort", 0);
    m_isTcp = CRAX_CONFIG_GET_BOOL(".tcp", true);
    m_socketFd = CRAX_CONFIG_GET_INT(".socketFd", 0);
    m_isBlockingSocket = CRAX_CONFIG_GET_BOOL(".blocking", 0);
}

void Proxy::loadSymStdinConfig() {

}

}  // namespace s2e::plugins::crax
