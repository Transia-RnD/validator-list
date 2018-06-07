#ifndef _W_MANIFEST_H_
#define _W_MANIFEST_H_

#include <ripple/protocol/PublicKey.h>
#include <ripple/protocol/SecretKey.h>

namespace vlist
{

class Manifest
{
protected:
    ripple::STObject m_;

public:
    Manifest (ripple::STObject const& m) : m_ (m) { ; }

    Manifest () : m_ (ripple::sfGeneric) { ; }

    explicit Manifest (std::string const& raw);

    Manifest (ripple::PublicKey const& master, ripple::PublicKey const& ephemeral, uint32_t seq);

    bool isValid () const;

    void signMaster (ripple::SecretKey const& master);

    void signEphemeral (ripple::SecretKey const& ephemeral);

    std::string getB64() const;

    ripple::PublicKey getPublicKey() const;
};

Manifest
makeManifest (std::pair<ripple::PublicKey, ripple::SecretKey> const& mSecKey,
    std::pair<ripple::PublicKey, ripple::SecretKey> const& ephemKey, std::uint32_t seq);

}
#endif
