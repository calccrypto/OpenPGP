#include "sigcalc.h"

std::string addtrailer(const std::string & data, const Tag2::Ptr & sig){
    if (!sig){
        throw std::runtime_error("Error: No signature packet");
    }

    const std::string trailer = sig -> get_up_to_hashed();
    if (sig -> get_version() == 3){
        return data + trailer.substr(1, trailer.size() - 1); // remove version from trailer
    }
    else if (sig -> get_version() == 4){
        return data + trailer + "\x04\xff" + unhexlify(makehex(trailer.size(), 8));
    }
    else{
        throw std::runtime_error("Error: addtrailer for version " + std::to_string(sig -> get_version()) + " not defined.");
    }

    return ""; // should never reach here; mainly just to remove compiler warnings
}

std::string overkey(const Key::Ptr & key){
    if (!key){
        throw std::runtime_error("Error: No key packet.");
    }

    std::string str = key -> raw_common();
    return "\x99" + unhexlify(makehex(str.size(), 4)) + str;
}

std::string certification(uint8_t version, const User::Ptr & id){
    if (!id){
        throw std::runtime_error("Error: No ID packet.");
    }

    if (version == 3){
        return id -> raw();
    }
    else if (version == 4){
        std::string data = id -> raw();
        if (id -> get_tag() == Packet::USER_ID){
            return "\xb4" + unhexlify(makehex(data.size(), 8)) + data;
        }
        else if (id -> get_tag() == Packet::USER_ATTRIBUTE){
            return "\xd1" + unhexlify(makehex(data.size(), 8)) + data;
        }
    }
    else{
        throw std::runtime_error("Error: Certification for version " + std::to_string(version) + " not defined.");
    }
    return ""; // should never reach here; mainly just to remove compiler warnings
}

const std::string & binary_to_canonical(const std::string & data){
    return data;
}

std::string to_sign_00(const std::string & data, const Tag2::Ptr & tag2){
    if (!tag2){
        throw std::runtime_error("Error: No signature packet");
    }

    return use_hash(tag2 -> get_hash(), addtrailer(data, tag2));
}

std::string text_to_canonical(const std::string & data){
    // convert line endings to <CR><LF>
    if (!data.size()){
        return "";
    }

    std::string out = "";

    std::stringstream s(data);
    std::string line;
    while (std::getline(s, line)){
        out += line;
        if (!line.size() || (line[line.size() - 1] != '\r')){
            out += "\r";    // append <CR>
        }
        out += "\n";        // append <LF>
    }

    return out;
}

std::string to_sign_01(const std::string & data, const Tag2::Ptr & tag2){
    if (!tag2){
        throw std::runtime_error("Error: No signature packet");
    }

    const std::string canonical = text_to_canonical(data); // still has trailing <CR><LF>
    return use_hash(tag2 -> get_hash(), addtrailer(canonical.substr(0, canonical.size() - 2), tag2));
}

std::string to_sign_02(const Tag2::Ptr & tag2){
    if (!tag2){
        throw std::runtime_error("Error: No signature packet");
    }

    if (tag2 -> get_version() == 3){
        throw std::runtime_error("Error: It does not make sense to have a V3 standalone signature.");
    }
    return use_hash(tag2 -> get_hash(), addtrailer("", tag2));
}

std::string to_sign_10(const Key::Ptr & key, const User::Ptr & id, const Tag2::Ptr & tag2){
    if (!tag2){
        throw std::runtime_error("Error: No signature packet");
    }

    if (tag2 -> get_type() != Signature_Type::GENERIC_CERTIFICATION_OF_A_USER_ID_AND_PUBLIC_KEY_PACKET){
        throw std::runtime_error("Error: Bad signature type.");
    }

    return use_hash(tag2 -> get_hash(), addtrailer(overkey(key) + certification(tag2 -> get_version(), id), tag2));
}

std::string to_sign_11(const Key::Ptr & key, const User::Ptr & id, const Tag2::Ptr & tag2){
    if (!tag2){
        throw std::runtime_error("Error: No signature packet");
    }

    if (tag2 -> get_type() != Signature_Type::PERSONA_CERTIFICATION_OF_A_USER_ID_AND_PUBLIC_KEY_PACKET){
        throw std::runtime_error("Error: Bad signature type.");
    }

    return use_hash(tag2 -> get_hash(), addtrailer(overkey(key) + certification(tag2 -> get_version(), id), tag2));
}

std::string to_sign_12(const Key::Ptr & key, const User::Ptr & id, const Tag2::Ptr & tag2){
    if (!tag2){
        throw std::runtime_error("Error: No signature packet");
    }

    if (tag2 -> get_type() != Signature_Type::CASUAL_CERTIFICATION_OF_A_USER_ID_AND_PUBLIC_KEY_PACKET){
        throw std::runtime_error("Error: Bad signature type.");
    }

    return use_hash(tag2 -> get_hash(), addtrailer(overkey(key) + certification(tag2 -> get_version(), id), tag2));
}

std::string to_sign_13(const Key::Ptr & key, const User::Ptr & id, const Tag2::Ptr & tag2){
    if (!tag2){
        throw std::runtime_error("Error: No signature packet");
    }

    if (tag2 -> get_type() != Signature_Type::POSITIVE_CERTIFICATION_OF_A_USER_ID_AND_PUBLIC_KEY_PACKET){
        throw std::runtime_error("Error: Bad signature type.");
    }

    return use_hash(tag2 -> get_hash(), addtrailer(overkey(key) + certification(tag2 -> get_version(), id), tag2));
}

std::string to_sign_cert(const uint8_t cert, const Key::Ptr & key, const User::Ptr & id, const Tag2::Ptr & sig){
    std::string digest;

    if (cert == Signature_Type::GENERIC_CERTIFICATION_OF_A_USER_ID_AND_PUBLIC_KEY_PACKET){
        digest = to_sign_10(key, id, sig);
    }
    else if (cert == Signature_Type::PERSONA_CERTIFICATION_OF_A_USER_ID_AND_PUBLIC_KEY_PACKET){
        digest = to_sign_11(key, id, sig);
    }
    else if (cert == Signature_Type::CASUAL_CERTIFICATION_OF_A_USER_ID_AND_PUBLIC_KEY_PACKET){
        digest = to_sign_12(key, id, sig);
    }
    else if (cert == Signature_Type::POSITIVE_CERTIFICATION_OF_A_USER_ID_AND_PUBLIC_KEY_PACKET){
        digest = to_sign_13(key, id, sig);
    }
    else{
        throw std::runtime_error("Error: Bad certification type.");
    }

    return digest;
}

std::string to_sign_18(const Key::Ptr & primary, const Key::Ptr & key, const Tag2::Ptr & tag2){
    if (!tag2){
        throw std::runtime_error("Error: No signature packet");
    }

    return use_hash(tag2 -> get_hash(), addtrailer(overkey(primary) + overkey(key), tag2));
}

std::string to_sign_19(const Key::Ptr & primary, const Key::Ptr & subkey, const Tag2::Ptr & tag2){
    if (!tag2){
        throw std::runtime_error("Error: No signature packet");
    }

    return use_hash(tag2 -> get_hash(), addtrailer(overkey(primary) + overkey(subkey), tag2));
}

std::string to_sign_1f(const Tag2::Ptr & /*tag2*/){
    throw std::runtime_error("Error: Signature directly on a key has not implemented.");
    // if (!tag2){
        // throw std::runtime_error("Error: No signature packet");
    // }

    //    return use_hash(tag2 -> get_hash(), addtrailer("", tag2));
    return "";
}

std::string to_sign_20(const Key::Ptr & key, const Tag2::Ptr & tag2){
    if (!tag2){
        throw std::runtime_error("Error: No signature packet");
    }
    
    if (tag2 -> get_type() != Signature_Type::KEY_REVOCATION_SIGNATURE){
        throw std::runtime_error("Error: Bad signature type.");
    }
    
    return use_hash(tag2 -> get_hash(), addtrailer(overkey(key), tag2));
}

std::string to_sign_28(const Key::Ptr & key, const Tag2::Ptr & tag2){
    if (!tag2){
        throw std::runtime_error("Error: No signature packet");
    }
    
    if (tag2 -> get_type() != Signature_Type::SUBKEY_REVOCATION_SIGNATURE){
        throw std::runtime_error("Error: Bad signature type.");
    }
    
    return use_hash(tag2 -> get_hash(), addtrailer(overkey(key), tag2));
}

std::string to_sign_30(const Key::Ptr & key, const User::Ptr & id, const Tag2::Ptr & tag2){
    if (!tag2){
        throw std::runtime_error("Error: No signature packet");
    }

    if (tag2 -> get_type() != Signature_Type::CERTIFICATION_REVOCATION_SIGNATURE){
        throw std::runtime_error("Error: Bad signature type.");
    }

    return use_hash(tag2 -> get_hash(), addtrailer(overkey(key) + certification(tag2 -> get_version(), id), tag2));
}

std::string to_sign_40(const Tag2::Ptr & /*tag2*/){
    throw std::runtime_error("Error: Signature directly on a key has not implemented.");
    // if (!tag2){
        // throw std::runtime_error("Error: No signature packet");
    // }

    //    return use_hash(tag2 -> get_hash(), addtrailer("", tag2));
    return "";
}

std::string to_sign_50(const Tag2 & sig, const Tag2::Ptr & /*tag2*/){
    std::string data = sig.get_without_unhashed();
    return "\x88" + unhexlify(makehex(data.size(), 8)) + data;
}
