#include "Manifest.h"
#include "utils.h"
#include <fstream>
#include <sys/stat.h>
#include <ripple/basics/StringUtilities.h>

int read_selection()
{
    std::string line;
    do
    {
        std::getline(std::cin, line);
        if (line.empty() && std::cout.fail())
            return -1;
        else 
            return std::atoi(line.c_str());
    } while(1);
}

void sign_unl ()
{
    std::string manifest;
    uint32_t sequence;
    uint32_t expiration;
    int days;
    std::vector <std::string> manifests;

    std::cout << std::endl << "Enter ephemeral private key:" << std::endl;
    ripple::SecretKey const secretKey = getPass();

    std::cout << std::endl << "Enter ephemeral key manifest:" << std::endl;
    std::cin >> manifest;
    std::cin.ignore();

    std::cout << std::endl << "Sequence number: ";
    std::cin >> sequence;
    std::cin.ignore();

    std::cout << std::endl << "Validity in days: ";
    std::cin >> days;
    std::cin.ignore();

    // convert validity in days to seconds since 1/1/2000
    auto now = time (NULL) - 946684800;
    expiration = now - (now % 86400) + ((days + 1) * 86400);

    std::cout << std::endl << "Enter validator manifests, ending with a blank line:" <<
        std::endl;
    while (1)
    {
        std::string j;
        std::getline (std::cin, j);
        if (j.empty())
            break;
        // check validity, WRITEME
        manifests.push_back (j);
    }

    auto unl = signUNL (secretKey, manifest, sequence, expiration, manifests);
    if (unl)
    {
        std::cout << *unl << std::endl << std::endl;
    }
}

bool validator_list_operations ()
{
    while (1)
    {
        std::cout << std::endl << std::endl << std::endl << std::endl;
        printf("Validator List menu\n\n");

        printf("1) Create validator list publisher keys\n\n");
        printf("2) Sign validator list\n\n");
        
        printf("9) Quit\n\n");

        switch (read_selection())
        {
            case 1:
            {
                std::cout << "\nSelect a name for this credential set: ";
                std::string name;
                std::cin >> name;
                std::cin.ignore();
                std::cout << std::endl;
                if (mkdir (name.c_str(), 0700) != 0)
                {
                    std::cout << "Unable to create directory" << std::endl;
                    break;
                }

                using namespace ripple;

                auto const masterKey = randomKeyPair(KeyType::ed25519);

                for (std::uint32_t seq = 1; seq <= 10; ++seq)
                {
                    auto const newKey = randomKeyPair(KeyType::ed25519);
                    auto manifest = vlist::makeManifest (masterKey, newKey, seq);
                    std::ofstream f;
                    f.open (name + "/ephkey" + std::to_string (seq) + ".txt");
                    if (! f.is_open())
                    {
                        std::cout << "Unable to open file" << std::endl;
                        break;
                    }
                    f << "Private Key:\n\n" <<
                        newKey.second.to_string() << std::endl;

                    f << "---------------------" << std::endl << std::endl;
                    f << "Manifest:\n\n" << manifest.getB64() << std::endl;
                }

                std::ofstream priv, pub;
                priv.open ("privkeys.txt", std::fstream::app);
                pub.open ("pubkeys.txt", std::fstream::app);
                priv << name << " privkey: " <<
                    masterKey.second.to_string() << std::endl;
                pub << name << " pubkey: " << strHex(masterKey.first) << std::endl;
                std::cout << "Publisher keys stored in privkeys.txt and pubkeys.txt" << std::endl;
                std::cout << "Ephemeral keys stored in " << name << "/" << std::endl;
                break;
            }

            case 2:
                sign_unl ();
                break;

            case 9:
            case -1:
                return false;
        }
        return true;
    }
}

int main (int argc, char *argv[])
{
    while(1)
    {
        if (! validator_list_operations())
            break;
    }

    return 0;
}
