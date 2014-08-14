#include "generatekey.h"

void generate_keys(PGPPublicKey & public_key, PGPSecretKey & private_key, const std::string & passphrase, const std::string & user, const std::string & comment, const std::string & email, const unsigned int DSA_bits, const unsigned int ElGamal_bits){
    BBS(static_cast <PGPMPI> (static_cast <uint32_t> (now()))); // seed just in case not seeded

    if (((DSA_bits < 512)) || (ElGamal_bits < 512)){
        throw std::runtime_error("Error: Keysize must be at least 512 bits.");
    }

    if (DSA_bits & 1023){
        throw std::runtime_error("Error: DSA keysize should be 1024, 2048, or 3072 bits.");
    }

    // generate pka values
    std::vector <PGPMPI> dsa_pub = new_DSA_public(DSA_bits, (DSA_bits == 1024)?160:256);
    std::vector <PGPMPI> dsa_pri = DSA_keygen(dsa_pub);

    std::vector <PGPMPI> elgamal_pub = ElGamal_keygen(ElGamal_bits);
    PGPMPI elgamal_pri = elgamal_pub[3];
    elgamal_pub.pop_back();

    // Key creation time
    time_t time = now();

    // hash algorithm for signature
    uint8_t hash_alg = (DSA_bits == 1024)?2:8;

    // Secret Key Packet
    Tag5::Ptr sec = std::make_shared<Tag5>();
    sec -> set_version(4);
    sec -> set_time(time);
    sec -> set_pka(17);// DSA
    sec -> set_mpi(dsa_pub);
    sec -> set_s2k_con(254);
    sec -> set_sym(9);// AES256

    // Secret Key Packet S2K
    S2K3::Ptr sec_s2k3 = std::make_shared<S2K3>();
    sec_s2k3 -> set_hash(2);
    sec_s2k3 -> set_salt(unhexlify(bintohex(BBS().rand(64))));
    sec_s2k3 -> set_count(96);

    // calculate the key from the passphrase
    std::string key = sec_s2k3 -> run(passphrase, Symmetric_Algorithm_Key_Length.at(Symmetric_Algorithms.at(sec -> get_sym())) >> 3);

    // encrypt private key value
    sec -> set_s2k(sec_s2k3);
    sec -> set_IV(unhexlify(bintohex(BBS().rand(Symmetric_Algorithm_Block_Length.at(Symmetric_Algorithms.at(sec -> get_sym()))))));
    std::string secret = write_MPI(dsa_pri[0]);
    sec -> set_secret(use_normal_CFB_encrypt(9, secret + use_hash(2, secret), key, sec -> get_IV()));

    std::string keyid = sec -> get_keyid();

    Tag13::Ptr uid = std::make_shared<Tag13>();
    uid -> set_name(user);
    uid -> set_comment(comment);
    uid -> set_email(email);

    Tag2::Ptr sig = std::make_shared<Tag2>();
    sig -> set_version(4);
    sig -> set_type(0x13);
    sig -> set_pka(17);
    sig -> set_hash(hash_alg);
    Tag2Sub2::Ptr tag2sub2 = std::make_shared<Tag2Sub2>(); tag2sub2 -> set_time(time);
    sig -> set_hashed_subpackets({tag2sub2});
    Tag2Sub16::Ptr tag2sub16 = std::make_shared<Tag2Sub16>(); tag2sub16 -> set_keyid(keyid);
    sig -> set_unhashed_subpackets({tag2sub16});
    std::string sig_hash = to_sign_13(sec, uid, sig);
    sig -> set_left16(sig_hash.substr(0, 2));
    sig -> set_mpi(DSA_sign(sig_hash, dsa_pri, dsa_pub));

    // Secret Subkey Packet
    Tag7::Ptr ssb = std::make_shared<Tag7>();
    ssb -> set_version(4);
    ssb -> set_time(time);
    ssb -> set_pka(16);// ElGamal
    ssb -> set_mpi(elgamal_pub);
    ssb -> set_s2k_con(254);
    ssb -> set_sym(9);// AES256

    // Secret Subkey S2K
    S2K3::Ptr ssb_s2k3 = std::make_shared<S2K3>();
    ssb_s2k3 -> set_hash(2);
    ssb_s2k3 -> set_salt(unhexlify(bintohex(BBS().rand(64)))); // new salt value
    ssb_s2k3 -> set_count(96);
    key = ssb_s2k3 -> run(passphrase, Symmetric_Algorithm_Key_Length.at(Symmetric_Algorithms.at(ssb -> get_sym())) >> 3);

    ssb -> set_s2k(ssb_s2k3);
    ssb -> set_IV(unhexlify(bintohex(BBS().rand(Symmetric_Algorithm_Block_Length.at(Symmetric_Algorithms.at(ssb -> get_sym()))))));
    secret = write_MPI(elgamal_pri);
    ssb -> set_secret(use_normal_CFB_encrypt(9, secret + use_hash(2, secret), key, ssb -> get_IV()));

    // Subkey Binding Signature
    Tag2::Ptr subsig = std::make_shared<Tag2>();
    subsig -> set_version(4);
    subsig -> set_type(0x18);
    subsig -> set_pka(17);
    subsig -> set_hash(hash_alg);
    subsig -> set_hashed_subpackets({tag2sub2});
    subsig -> set_unhashed_subpackets({tag2sub16});
    sig_hash = to_sign_18(sec, ssb, subsig);
    subsig -> set_left16(sig_hash.substr(0, 2));
    subsig -> set_mpi(DSA_sign(sig_hash, dsa_pri, dsa_pub));

    private_key.set_ASCII_Armor(2);
    private_key.set_Armor_Header({std::pair <std::string, std::string> ("Version", "CC")});
    private_key.set_packets({sec, uid, sig, ssb, subsig});

    public_key = PGPPublicKey(private_key);

    sec.reset();
    sec_s2k3.reset();
    uid.reset();
    sig.reset();
    tag2sub2.reset();
    tag2sub16.reset();
    ssb.reset();
    ssb_s2k3.reset();
    subsig.reset();
}

void add_key_values(PGPPublicKey & public_key, PGPSecretKey & private_key, const std::string & passphrase, const bool new_keyid, const unsigned int pri_key_size, const unsigned int subkey_size){
    BBS(static_cast <PGPMPI> (static_cast <uint32_t> (now()))); // seed just in case not seeded

    // at most only 1 of each pair is expected
    std::vector <PGPMPI> pub_key;
    std::vector <PGPMPI> pri_key;
    std::vector <PGPMPI> pub_subkey;
    std::vector <PGPMPI> pri_subkey;

    Tag5::Ptr prikey;
    Tag7::Ptr prisubkey;
    Tag13::Ptr uid = std::make_shared<Tag13>();
    Tag17::Ptr attr  = std::make_shared<Tag17>();
    bool id = false;            // default UID came first
    bool key = false;           // default main key came first

    std::vector <Packet::Ptr> packets = private_key.get_packets();
    for(Packet::Ptr & p : packets){
        std::string data = p -> raw();
        if (p -> get_tag() == 5){     // Secret Key Packet
            prikey  = std::make_shared<Tag5>(data);

            // Generate keypair
            std::vector <unsigned int> param;
            // RSA
            if ((prikey -> get_pka() == 1) || (prikey -> get_pka() == 2)/* || (prikey -> get_pka() == 3)*/){
                param = {pri_key_size};
            }
            // ElGamal
            else if (prikey -> get_pka() == 16){
                if (prikey -> get_version() == 3){
                    throw std::runtime_error("Error: Only RSA is defined for version 3 key packets.");
                }
                param = {pri_key_size};
            }
            // DSA
            else if (prikey -> get_pka() == 17){
                if (prikey -> get_version() == 3){
                    throw std::runtime_error("Error: Only RSA is defined for version 3 key packets.");
                }
                param = {pri_key_size};
                if (pri_key_size == 1024){
                    param.push_back(160);
                }
                else if (pri_key_size == 2048){
                    param.push_back(256);
                }
                else if (pri_key_size == 3072){
                    param.push_back(256);
                }
                else{
                    std::stringstream s; s << pri_key_size;
                    throw std::runtime_error("Error: Undefined bit size for DSA: " + s.str());
                }
            }
            else{
                std::stringstream s; s << static_cast <unsigned int> (prikey -> get_pka());
                throw std::runtime_error("Error: Undefined or reserved PKA number: " + s.str());
            }

            generate_key_pair(prikey -> get_pka(), param, pub_key, pri_key);

            // put public key into packet
            prikey -> set_mpi(pub_key);

            // put private key into packet
            std::string secret = "";
            for(PGPMPI & i : pri_key){
                secret += write_MPI(i);
            }

            std::string check;
            if (prikey -> get_s2k_con() == 254){
                check = use_hash(2, secret);
            }
            else{
                uint16_t sum = 0;
                for(char & c : secret){
                    sum += static_cast <uint8_t> (c);
                }
                check = unhexlify(makehex(sum, 4));
            }
            std::string k = prikey -> get_s2k() -> run(passphrase, 16);
            prikey -> set_secret(use_normal_CFB_encrypt(prikey -> get_sym(), secret + check, k, prikey -> get_IV()));
            p = prikey;

            key = false;
        }
        else if (p -> get_tag() == 13){    // User ID packet
            uid -> read(data);
            id = false;
        }
        else if (p -> get_tag() == 17){    // User Attribute Packet
            attr -> read(data);
            id = true;
        }
        else if (p -> get_tag() == 2){     // Signature Packet
            Tag2::Ptr sig(new Tag2(data));

            // check that there is a key to be signed
            if (!prikey){
                throw std::runtime_error("Error: No primary key to be signed.");
            }

            // the correct key id
            std::string keyid = prikey -> get_keyid();

            // if fill in the new key id
            if (new_keyid){
                // find Key ID subpacket in the hashed subpackets
                std::vector <Tag2Subpacket::Ptr> subpackets = sig -> get_hashed_subpackets();
                for(Tag2Subpacket::Ptr & s : subpackets){
                    if (s -> get_type() == 16){
                        Tag2Sub16::Ptr t = std::make_shared<Tag2Sub16>();
                        t -> set_keyid(keyid);
                        s = t;
                        break;
                    }
                }

                // find Key ID subpacket in the unhashed subpackets
                bool found = false;
                subpackets = sig -> get_unhashed_subpackets();
                for(Tag2Subpacket::Ptr & s : subpackets){
                    if (s -> get_type() == 16){
                        Tag2Sub16::Ptr t = std::make_shared<Tag2Sub16>();
                        t -> set_keyid(keyid);
                        s = t;
                        found = true;
                        break;
                    }
                }

                // add a new unhashed subpacket
                if (!found){
                    Tag2Sub16::Ptr t = std::make_shared<Tag2Sub16>();
                    t -> set_keyid(keyid);
                    subpackets.push_back(t);
                }

                // put new subpackets back, since they are clone of the original
                sig -> set_unhashed_subpackets(subpackets);
            }

            std::string sig_hash;
            if (!key){  // if the key is a primary key
                // get the user id/attribute packet
                ID::Ptr i = uid;
                if (id){
                    i = attr;
                }
                if (!i){
                    throw std::runtime_error("Error: No User ID or Attribute packet to be signed.");
                }
                if (sig -> get_type() == 0x10){
                    sig_hash = to_sign_10(prikey, i, sig);
                }
                else if (sig -> get_type() == 0x11){
                    sig_hash = to_sign_11(prikey, i, sig);
                }
                else if (sig -> get_type() == 0x12){
                    sig_hash = to_sign_12(prikey, i, sig);
                }
                else if (sig -> get_type() == 0x13){
                    sig_hash = to_sign_13(prikey, i, sig);
                }
            }
            else{       // if the key is a subkey
                if (!prisubkey){
                    throw std::runtime_error("Error: No primary key to be signed.");
                }
                if (sig -> get_type() == 0x18){
                    sig_hash = to_sign_18(prikey, prisubkey, sig);
                }
                else if (sig -> get_type() == 0x19){
                    sig_hash = to_sign_19(prikey, prisubkey, sig);
                }
            }

            // fill in signature fields
            sig -> set_left16(sig_hash.substr(0, 2));
            sig -> set_mpi(pka_sign(sig_hash, sig -> get_pka(), (key?pub_subkey:pub_key), (key?pri_subkey:pri_key)));
            p = sig;
        }
        else if (p -> get_tag() == 7){     // Secret Subkey Packet
            prisubkey = std::make_shared<Tag7>(data);

            // Generate keypair
            std::vector <unsigned int> param;
            // RSA
            if ((prisubkey -> get_pka() == 1) || (prisubkey -> get_pka() == 2) /*|| (prisubkey -> get_pka() == 3)*/){
                param = {subkey_size};
            }
            // ElGamal
            else if (prisubkey -> get_pka() == 16){
                if (prisubkey -> get_version() == 3){
                    throw std::runtime_error("Error: Only RSA is defined for version 3 key packets.");
                }
                param = {subkey_size};
            }
            // DSA
            else if (prisubkey -> get_pka() == 17){
                if (prisubkey -> get_version() == 3){
                    throw std::runtime_error("Error: Only RSA is defined for version 3 key packets.");
                }
                param = {subkey_size};
                if (subkey_size == 1024){
                    param.push_back(160);
                }
                else if (subkey_size == 2048){
                    param.push_back(256);
                }
                else if (subkey_size == 3072){
                    param.push_back(256);
                }
                else{
                    std::stringstream s; s << subkey_size;
                    throw std::runtime_error("Error: Undefined bit size for DSA: " + s.str());
                }
            }
            else{
                std::stringstream s; s << static_cast <unsigned int> (prisubkey -> get_pka());
                throw std::runtime_error("Error: Undefined or reserved PKA number: " + s.str());
            }

            generate_key_pair(prisubkey -> get_pka(), param, pub_subkey, pri_subkey);

            // put publc key into packet
            prisubkey -> set_mpi(pub_subkey);

            // put private key into packet
            std::string secret = "";
            for(PGPMPI & i : pri_subkey){
                secret += write_MPI(i);
            }

            std::string check;
            if (prisubkey -> get_s2k_con() == 254){
                check = use_hash(2, secret);
            }
            else{
                uint16_t sum = 0;
                for(char & c : secret){
                    sum += static_cast <uint8_t> (c);
                }
                check = unhexlify(makehex(sum, 4));
            }
            std::string k = prisubkey -> get_s2k() -> run(passphrase, 16);
            prisubkey -> set_secret(use_normal_CFB_encrypt(prisubkey -> get_sym(), secret + check, k, prisubkey -> get_IV()));
            p = prisubkey;

            key = true;
        }
        else{
            std::stringstream s; s << static_cast <unsigned int> (p -> get_tag());
            throw std::runtime_error("Error: Packet Tag " + s.str() + " does not belong in a private key.");
            break;
        }
    }

    // write changes to public key
    std::vector <Packet::Ptr> pub_packets;
    for(Packet::Ptr const & p : packets){
        std::string data = p -> raw();
        if (p -> get_tag() == 5){ // Secret Key packet
            Tag6::Ptr tag6(new Tag6(data));
            pub_packets.push_back(tag6);
        }
        else if (p -> get_tag() == 7){ // Secret Subkey packet
            Tag14::Ptr tag14(new Tag14(data));
            pub_packets.push_back(tag14);
        }
        else if ((p -> get_tag() == 2) || (p -> get_tag() == 13) || (p -> get_tag() == 17)){
            pub_packets.push_back(p -> clone());
        }
        else{
            std::stringstream s; s << static_cast <unsigned int> (p -> get_tag());
            throw std::runtime_error("Error: Packet Tag " + s.str() + " doesn't belong here.");
            break;
        }
    }
    public_key.set_packets(pub_packets);
}
