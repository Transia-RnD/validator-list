#include "Manifest.h"
#include <beast/core/detail/base64.hpp>
#include <ripple/crypto/KeyType.h>
#include <ripple/protocol/HashPrefix.h>
#include <ripple/protocol/Sign.h>
#include <ripple/protocol/SField.h>

namespace vlist
{

Manifest::Manifest (std::string const& raw) :
    m_ (ripple::SerialIter (raw.data(), raw.size()), ripple::sfGeneric)
{ ; }

Manifest::Manifest (ripple::PublicKey const& master, ripple::PublicKey const& ephemeral, uint32_t seq) :
    m_ (ripple::sfGeneric)
{
    using namespace ripple;
    m_[sfPublicKey] = master;
    m_[sfSigningPubKey] = ephemeral;
    m_[sfSequence] = seq;
}

bool Manifest::isValid () const
{
    using namespace ripple;

    // not a complete check
    return
        m_.isFieldPresent (sfSequence) &&
        m_.isFieldPresent (sfPublicKey) &&
        m_.isFieldPresent (sfSigningPubKey) &&
        publicKeyType (makeSlice(m_.getFieldVL (sfPublicKey)));
}


void Manifest::signMaster (ripple::SecretKey const& master)
{
    using namespace ripple;
    ripple::sign (m_, HashPrefix::manifest, KeyType::ed25519, master, sfMasterSignature);
}

void Manifest::signEphemeral (ripple::SecretKey const& ephemeral)
{
    using namespace ripple;
    ripple::sign (m_, HashPrefix::manifest, KeyType::ed25519, ephemeral);
}

std::string Manifest::getB64() const
{
    using namespace ripple;

    Serializer s;
    m_.add (s);
    return beast::detail::base64_encode (std::string {
        reinterpret_cast<const char *>(s.data()),
            s.size()});
}

ripple::PublicKey Manifest::getPublicKey() const
{
    using namespace ripple;

    return PublicKey (makeSlice(m_.getFieldVL (sfPublicKey)));
}

Manifest
makeManifest (std::pair<ripple::PublicKey, ripple::SecretKey> const& mSecKey,
    std::pair<ripple::PublicKey, ripple::SecretKey> const& ephemKey, std::uint32_t seq)
{
    using namespace ripple;

    Manifest m (mSecKey.first, ephemKey.first, seq);
    m.signMaster (mSecKey.second);
    m.signEphemeral (ephemKey.second);
    return m;
}

} // vlist
