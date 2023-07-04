@@ -0,0 +1,112 @@
#include "utils.h"
#include <beast/core/detail/base64.hpp>
#include <ripple/basics/StringUtilities.h>
#include <ripple/json/to_string.h>
#include "Manifest.h"

// Will need porting to other platforms
// Used to get password/passphrase without echoing
#include <termios.h>

std::string toBase64 (std::string const& in)
{
   return beast::detail::base64_encode (in);
}

boost::optional<std::string> signUNL (
    ripple::SecretKey const& ephemSecKey,
    std::string const& manifest,
    uint32_t sequence,
    uint32_t expiration,
    std::vector <std::string> const& manifests)
{
    using namespace ripple;

    std::string data =
        "{\"sequence\":" + std::to_string(sequence) +
        ",\"expiration\":" + std::to_string(expiration) +
        ",\"validators\":[";

    std::string valsMsg = "Adding the following validator public keys to the list:\n";

    for (auto const& manifest : manifests)
    {
        try
        {
            vlist::Manifest m (beast::detail::base64_decode(manifest));
            if (! m.isValid()) {
                std::cout << "Invalid manifest:" << std::endl;
                std::cout << manifest << std::endl;
                return boost::none;
            }
            auto const pubKey = m.getPublicKey();
            valsMsg += toBase58(TokenType::TOKEN_NODE_PUBLIC, pubKey) + "\n";
            data += "{\"validation_public_key\":\"" + strHex(pubKey) + "\","
                "\"manifest\":\"" + manifest + "\"},";
        }
        catch (...)
        {
            std::cout << "Invalid manifest:" << std::endl;
            std::cout << manifest << std::endl;
            return boost::none;
        }
    }

    data.pop_back();
    data += "]}";
    // std::cout << valsMsg << std::endl;

    auto pubKey = derivePublicKey (KeyType::ed25519, ephemSecKey);

    Json::Value jv;
    jv["blob"] = toBase64 (data);
    jv["manifest"] = manifest;
    jv["signature"] = strHex (sign (pubKey, ephemSecKey, makeSlice(data)));
    jv["version"] = 1;

    return pretty(jv);
}

// Read a character without echoing
// Will need porting to other platforms
int tc_getch()
{
    struct termios t_old, t_new;

    tcgetattr(0, &t_old);
    t_new = t_old;
    t_new.c_lflag &= ~(ICANON | ECHO);

    tcsetattr(0, TCSANOW, &t_new);
    auto ch = getchar();
    tcsetattr(0, TCSANOW, &t_old);

    return ch;
}

// Read a password, echoing *'s
ripple::SecretKey getPass()
{
  std::string pass;
  int ch;

  while ((ch = tc_getch()) != 10)
  {
       if (ch == 127)
       {
           // backspace
           if (pass.length() > 0)
           {
                std::cout << "\b \b" << std::flush;
                pass.resize (pass.length() - 1);
           }
       }
       else
       {
             pass += static_cast<unsigned char>(ch);
             std::cout << '*' << std::flush;
       }
  }
  std::cout << std::endl;
  return ripple::SecretKey(ripple::makeSlice(std::move(ripple::strUnHex(pass).first)));
}