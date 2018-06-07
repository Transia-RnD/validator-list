#ifndef _W_UTILS_H_
#define _W_UTILS_H_

#include <string>
#include <ripple/protocol/SecretKey.h>

std::string toBase64 (std::string const& in);

boost::optional<std::string> signUNL (
    ripple::SecretKey const& ephemSecKey,
    std::string const& manifest,
    uint32_t sequence,
    uint32_t expiration,
    std::vector <std::string> const& manifests);

ripple::SecretKey getPass ();

#endif
