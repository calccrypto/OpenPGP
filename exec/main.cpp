/*
OpenPGP main file
*/

#include <fstream>
#include <iostream>

#include "../OpenPGP.h"

#include "../encrypt.h"
#include "../decrypt.h"
#include "../generatekey.h"
#include "../sign.h"
#include "../verify.h"

std::vector <std::string> commands = {
    "exit|quit\n",                                                                              // end program
    "list key_file",                                                                            // list keys in file, like 'gpg --list-keys'
    "show -k|-m file_name",                                                                     // display contents of a key file; -k for key, -m for (unencrypted) message
    "generatekeypair output_name [-pw passphrase [-u username [-c comment [-e email]]]]",       // generate new key pair
    "encrypt data_file public_key output_name [-delete t/f]",                                   // encrypt a file; optional: delete original file (default false)
    "decrypt data_file private_key passphrase output_name",                                     // decrypt a file
    "sign data_file private_key passphrase output_name",                                        // sign a string (outputs to PGPMessage)
    "verify-file data_file signature_file public_key",                                          // verify detached signature
    "verify-message data_file public_key",                                                      // verify signed message
    "verify-key key_file signer_key_file",                                                      // verify revocation signature
};

// function to parse above commands
bool parse_command(std::string & input){
    std::stringstream tokens(input);
    std::string cmd; tokens >> cmd;
    if (cmd == ""){
        return 1;
    }
    else if ((cmd == "exit") || (cmd == "quit")){
        return 0;
    }
    else if ((cmd == "?") || (cmd == "help")){
        std::cout << "Commands:\n";
        for(std::string & c : commands){
            std::cout << "    " << c << std::endl;
        }
        std::cout << std::endl << std::endl;
    }
    else if (cmd == "list"){
        std::string file_name; tokens >> file_name;
        if (file_name == ""){
            std::cout << "Syntax: " << commands[2] << std::endl;
            return 1;
        }
        std::ifstream f(file_name.c_str());
        if (!f){
            std::cerr << "Error: File " << file_name << " not opened" << std::endl;
            return 1;
        }

        PGP k(f);

        std::cout << k.list_keys() << std::endl;
    }
    else if (cmd == "show"){
        std::string type; tokens >> type;
        std::string file_name; tokens >> file_name;

        if (file_name == ""){
            std::cout << "Syntax: " << commands[2] << std::endl;
            return 1;
        }
        std::ifstream f(file_name.c_str());
        if (!f){
            std::cerr << "Error: File " << file_name << " not opened" << std::endl;
            return 1;
        }
        if ((type == "-k") || (type == "-K")){
            PGP key(f);
            std::cout << key.show() << std::endl;
        }
        else if ((type == "-m") || (type == "-M")){
            PGPMessage message(f);
            std::cout << message.show() << std::endl;
        }
        else{
            std::cout << "Syntax: " << commands[1] << std::endl;
        }
    }
    else if (cmd == "generatekeypair"){
        std::cout << "Function not completed. Nothing done" << std::endl;
        return 1;
        std::cout <<  "Warning: Generating keys takes extremely long. Do no use unless absolutely necessary" << std::endl;
        std::string file_name; tokens >> file_name;
        if (file_name == ""){
            std::cout << "Syntax: " << commands[3] << std::endl;
            return 1;
        }
        std::string passphrase = "", user = "", comment = "", email = "";
        while (tokens.str().size()){
            std::string temp; tokens >> temp;
            if (temp == "-pw")
                tokens >> passphrase;
            if (temp == "-u")
                tokens >> user;
            if (temp == "-c")
                tokens >> comment;
            if (temp == "-e")
                tokens >> email;
        }
        std::string pub, pri;
        generate_keys(pub, pri, passphrase, user, comment, email);
        std::ofstream PUB((file_name + " public").c_str());
        std::ofstream PRI((file_name + " private").c_str());
        PUB << pub;
        PRI << pri;
        PUB.close();
        PRI.close();
    }
    else if (cmd == "encrypt"){
        std::string data; tokens >> data;
        std::string pub; tokens >> pub;
        std::string write_to; tokens >> write_to;
        if ((data == "") || (pub == "") || (write_to == "")){
            std::cout << "Syntax: " << commands[4] << std::endl;
            return 1;
        }
        std::ifstream f(data.c_str());
        if (!f){
            std::cerr << "Error: File " << data << " not opened" << std::endl;
            return 1;
        }
        std::ifstream k(pub.c_str());
        if (!k){
            std::cerr << "Error: File " << pub << " not opened" << std::endl;
            return 1;
        }

        PGP key(k);
        std::stringstream s;
        s << f.rdbuf();
        std::ofstream out(write_to.c_str());
        if (!out){
           std::cerr << "IOError: file " << write_to << " could not be created. Wrote to std::cout instead" << std::endl;
           std::cout << s.str() << std::endl;
        }
        else{
            out << encrypt(s.str(), key);
            std::string t; tokens >> input;
            if (input == "-delete"){
                std::string del; tokens >> del;
                if ((del == "T") || (del == "t")){
                    f.close();
                    remove(data.c_str());
                }
            }
        }
    }
    else if (cmd == "decrypt"){
        std::string data; tokens >> data;
        std::string pri; tokens >> pri;
        std::string passphrase; tokens >> passphrase;
        std::string write_to; tokens >> write_to;
        if ((data == "") || (pri == "") || (passphrase == "") || (write_to == "")){
            std::cout << "Syntax: " << commands[5] << std::endl;
            return 1;
        }
        std::ifstream f(data.c_str());
        if (!f){
            std::cerr << "Error: File " << data << " not opened" << std::endl;
            return 1;
        }
        std::ifstream k(pri.c_str());
        if (!k){
            std::cerr << "Error: File " << pri << " not opened" << std::endl;
            return 1;
        }
        std::ofstream out(write_to.c_str());
        if (!out){
            std::cerr << "IOError: file " << write_to << " could not be created" << std::endl;
            return 1;
        }

        PGP key(k);
        PGP message(f);

        out << decrypt_message(message, key, passphrase);
    }
    else if (cmd == "sign"){
        std::string filename; tokens >> filename;
        std::string pri; tokens >> pri;
        std::string passphrase; tokens >> passphrase;
        std::string write_to; tokens >> write_to;
        if ((filename == "") || (pri == "") || (passphrase == "") || (write_to == "")){
            std::cout << "Syntax: " << commands[6] << std::endl;
            return 1;
        }
        std::ifstream k(pri.c_str());
        if (!k){
            std::cerr << "IOError: File " << pri << " not opened" << std::endl;
            return 1;
        }

        PGP key(k);
        std::ofstream out(write_to.c_str(), std::ios::binary);
        if (!out){
            std::cerr << "IOError: file " << write_to << " could not be created" << std::endl;
            return 1;
        }

        Tag5 * tag5 = find_signing_packet(key);
        if (!tag5){
            std::cerr << "Error: Private key not found" << std::endl;
            return 1;
        }

        Tag13 * tag13 = find_signer_id(key);
        if (!tag13){
            std::cerr << "Error: User ID not found" << std::endl;
            return 1;
        }

        Tag2 * sig = new Tag2;
        sig -> set_version(4);
        sig -> set_type(0);
        sig -> set_pka(17);
        sig -> set_hash(2);

        std::vector <Subpacket *> subpackets;

        // Signature Creation Time
        Tag2Sub2 * tag2sub2 = new Tag2Sub2;
        tag2sub2 -> set_time(now());

        // Signer ID
        Tag2Sub28 * tag2sub28 = new Tag2Sub28;
        tag2sub28 -> set_signer(tag13 -> raw());
        subpackets = {tag2sub2, tag2sub28};
        sig -> set_hashed_subpackets(subpackets);

        // Signer's Key ID
        Tag2Sub16 * tag2sub16 = new Tag2Sub16;
        tag2sub16 -> set_keyid(tag5 -> get_keyid());
        subpackets = {tag2sub16};
        sig -> set_unhashed_subpackets(subpackets);

        std::string data = to_sign_00(filename, sig);
        sig = sign(0x00, data, tag5, passphrase, sig);

        PGP signature;
        signature.set_ASCII_Armor(5);
        std::vector <std::pair <std::string, std::string> > h = {std::pair <std::string, std::string>("Version", "cc")};
        signature.set_Armor_Header(h);
        std::vector <Packet *> p = {sig};
        signature.set_packets(p);
        out << signature.write();
    }
    else if (cmd == "verify-file"){
        std::string filename; tokens >> filename;
        std::string signame; tokens >> signame;
        std::string pub; tokens >> pub;
        if ((filename == "") || (signame == "") || (pub == "")){
            std::cout << "Syntax: " << commands[7] << std::endl;
            return 1;
        }
        std::ifstream s(signame.c_str());
        if (!s){
            std::cerr << "Error: File " << signame << " not opened" << std::endl;
            return 1;
        }
        std::ifstream k(pub.c_str());
        if (!k){
            std::cerr << "Error: File " << pub << " not opened" << std::endl;
            return 1;
        }

        PGP key(k);
        PGP sig(s);

        std::cout << "File '" << filename << "' was" << (verify_file(filename, sig, key)?"":" not") << " signed by key " << key << std::endl;
    }
    else if (cmd == "verify-message"){
        std::string data; tokens >> data;
        std::string pub; tokens >> pub;
        if ((data == "") || (pub == "")){
            std::cout << "Syntax: " << commands[8] << std::endl;
            return 1;
        }
        std::ifstream m(data.c_str());
        if (!m){
            std::cerr << "Error: File " << data << " not opened" << std::endl;
            return 1;
        }
        std::ifstream k(pub.c_str());
        if (!k){
            std::cerr << "Error: File " << pub << " not opened" << std::endl;
            return 1;
        }

        PGP key(k);
        PGPMessage message(m);

        std::cout << "This message was" << (verify_message(message, key)?"":" not") << " signed by this key" << std::endl;
    }
    else if (cmd == "verify-key"){
        std::string key_file; tokens >> key_file;
        std::string signer_file; tokens >> signer_file;
        if ((key_file == "") || (signer_file == "")){
            std::cout << "Syntax: " << commands[9] << std::endl;
            return 1;
        }

        std::ifstream k(key_file.c_str());
        if (!k){
            std::cerr << "Error: File " << key_file << " not opened" << std::endl;
            return 1;
        }
        std::ifstream s(signer_file.c_str());
        if (!s){
            std::cerr << "Error: File " << signer_file << " not opened" << std::endl;
            return 1;
        }

        PGP key(k);
        PGP signer(s);

        std::cout << "Key " << key << " was" << std::string(verify_signature(key, signer)?"":" not") << " signed by key " << signer << std::endl;
    }
    else{
        std::cerr << "CommandError: " << cmd << " not defined" << std::endl;
    }
    return 1;
}

int main(int argc, char * argv[]){
    std::string input = "";
    // no commandline arguments
    if (argc == 1){
        std::cout << "An OpenPGP implementation (RFC 4880)\nby Jason Lee @ calccrypto@gmail.com\n\n"
                  << "Type help or ? for command syntax\n\n"
                  << std::endl;
        while (parse_command(input)){
            std::cout << "> ";
            getline(std::cin, input);
        }
    }
    // has commandline arguments
    else{
        for(int x = 1; x < argc; x++){
            input += std::string(argv[x]) + " ";
        }
        parse_command(input);
    }
    return 0;
}
