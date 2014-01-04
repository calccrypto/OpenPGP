/*
main.cpp
OpenPGP commandline source

Copyright (c) 2013 Jason Lee

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in
all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
THE SOFTWARE.
*/

#include <chrono>
#include <fstream>
#include <iostream>
#include <map>
#include <sstream>
#include <vector>

#include "../PGP.h"
#include "../PGPSignedMessage.h"

#include "../decrypt.h"
#include "../encrypt.h"
#include "../generatekey.h"
#include "../revoke.h"
#include "../sign.h"
#include "../verify.h"

typedef std::map <std::string, std::string> Options;

std::vector <std::string> commands = {
    "exit|quit\n",                                                          // end program

    "test",                                                                 // test the program

    "list key_file",                                                        // list keys in file, like 'gpg --list-keys'

    "show -k|-m file_name",                                                 // display contents of a key file; -k for key, -m for (unencrypted) message

    "generatekeypair [options]\n"                                           // generate new key pair
    "        options:\n"
    "            -h\n"                                                      // help, since there is no way to fail token reading
    "            -o output name\n"                                          // filename; default stdout
    "            -pks public key size\n"                                    // bits; default 2048
    "            -sks subkey size\n"                                        // bits; default 2048
    "            -pw passphrase\n"                                          // string; default ""
    "            -u username\n"                                             // string; default ""
    "            -c comment\n"                                              // string; default ""
    "            -e email",                                                 // string; default ""

    "generate-revoke-cert private_key passphrase [options]\n"               // generate a revocation certificate for later
    "        options:\n"
    "            -o output name\n"                                          // filename; default stdout
    "            -c code\n"                                                 // 0, 1, 2, or 3
    "            -r reason",                                                // some string

    "encrypt data_file public_key\n"                                        // encrypt a string
    "        options:\n"
    "            -o output name\n"                                          // filename; default stdout
    "            -d delete original?",                                      // t or f; default false

    "decrypt data_file private_key passphrase [options]\n"                  // decrypt a file
    "        options:\n"
    "            -o output name\n"                                          // filename; default stdout
    "            -d delete original?",                                      // t or f; default false

    "revoke-key private_key passphrase [options]\n"                         // revoke a primary key
    "        options:\n"
    "            -o output name\n"                                          // filename; default stdout
    "            -c code\n"                                                 // 0, 1, 2, or 3
    "            -r reason",                                                // some string

    "revoke-subkey private_key passphrase [options]\n"                      // revoke a subkey
    "        options:\n"
    "            -o output name\n"                                          // filename; default stdout
    "            -c code\n"                                                 // 0, 1, 2, or 3
    "            -r reason",                                                // some string

    "sign-file data_file private_key passphrase [options]\n"                // sign a file
    "        options:\n"
    "            -o output name",                                           // filename; default stdout

    "sign-message data_file private_key passphrase [options]\n"             // sign a string in a file
    "        options:\n"
    "            -o output name",                                           // filename; default stdout

    "verify-file data_file signature_file public_key",                      // verify detached signature

    "verify-message data_file public_key",                                  // verify signed message

    "verify-key key_file signer_key_file",                                  // verify signature
};

void parse_options(std::stringstream & tokens, Options & options){
    std::string o, v;
    while (tokens >> o >> v){
        options[o] = v;
    }
}

// Output data into a file, or if not possible, to stdout
void output(const std::string & data, const std::string & filename = ""){
    if (filename != ""){
        try{
            std::ofstream out(filename.c_str());
            if (!out){
                std::cerr << "Error: File " << filename << " could not be opened." << std::endl;
                throw 1;
            }

            out << data;
        }
        catch (int & i){
            std::cout << data << std::endl;
        }
        catch (const std::exception & e){
            std::cerr << "Error: " << e.what() << std::endl;
        }
    }
    else{
        std::cout << data << std::endl;
    }
}

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
        std::cout << std::endl;
    }
    else if (cmd == "test"){
        try{
            std::chrono::high_resolution_clock::time_point start = std::chrono::high_resolution_clock::now();

            const std::string passphrase = "abc";
            const std::string message = "testing testing 123";

            std::cout << "Generate Keys" << std::endl;
            PGP pub, pri;
            generate_keys(pub, pri, passphrase, "test key", "", "test@test.ing", 2048, 2048);

            std::cout << "Show Keys" << std::endl;
            null_out << pub.show() << pri.show() << std::endl;

            std::cout << "Encrypt Message" << std::endl;
            PGP en = encrypt(message, pub);

            std::cout << "Decrypt Message" << std::endl;
            decrypt_message(en, pri, passphrase);

            std::cout << "Sign Message" << std::endl;
            PGPSignedMessage m = sign_message(message, pri, passphrase);

            std::cout << "Verify Message" << std::endl;
            if (!verify_message(m, pub)){
                std::cerr << "Error: Could not verify message signature." << std::endl;
                throw 1;
            }

            std::cout << "Verify Key" << std::endl;
            if (!verify_signature(pub, pri)){
                std::cerr << "Error: Could not verify key signature." << std::endl;
                throw 1;
            }

            std::cout << "Revoke Key" << std::endl;
            PGP rev = revoke_key(pri, passphrase, 0);

            std::cout << "Test took " << std::chrono::duration_cast<std::chrono::duration<double> >(std::chrono::high_resolution_clock::now() - start).count() << " seconds." << std::endl;
        }
        catch (int & i){
            std::cerr << "Error: Test Failed." << std::endl;
        }
        catch (const std::exception & e){
            std::cerr << "Error: " << e.what() << std::endl;
        }
    }
    else if (cmd == "list"){
        std::string file_name;
        if (!(tokens >> file_name) || (file_name == "")){
            std::cout << "Syntax: " << commands[2] << std::endl;
            return 1;
        }
        std::ifstream f(file_name.c_str());
        if (!f){
            std::cerr << "Error: File " << file_name << " not opened." << std::endl;
            return 1;
        }
        try{
            PGP k(f);
            std::cout << k.list_keys() << std::endl;
        }
        catch (int & i){
            std::cerr << "Error: Unable to list keys." << std::endl;
        }
        catch (const std::exception & e){
            std::cerr << "Error: " << e.what() << std::endl;
        }
    }
    else if (cmd == "show"){
        std::string type, file_name;

        if (!(tokens >> type >> file_name) ||
           (!((type == "-k") || (type == "-K")) && !((type == "-m") || (type == "-M"))) ||
            (file_name == "")){
            std::cout << "Syntax: " << commands[3] << std::endl;
            return 1;
        }

        std::ifstream f(file_name.c_str());
        if (!f){
            std::cerr << "Error: File " << file_name << " not opened." << std::endl;
            return 1;
        }
        if ((type == "-k") || (type == "-K")){
            PGP key(f);
            std::cout << key.show() << std::endl;
        }
        else if ((type == "-m") || (type == "-M")){
            PGPSignedMessage message(f);
            std::cout << message.show() << std::endl;
        }
        else{
            std::cout << "Syntax: " << commands[3] << std::endl;
        }
    }
    else if (cmd == "generatekeypair"){
        Options options;
        options["-o"] = "";
        options["-pks"] = "1024";
        options["-sks"] = "1024";
        options["-pws"] = "";
        options["-u"] = "";
        options["-c"] = "";
        options["-e"] = "";

        parse_options(tokens, options);

        if (options.find("-h") != options.end()){
            std::cout << "Syntax: " << commands[4] << std::endl;
            return 1;
        }

        try{
            PGP pub, pri;
            generate_keys(pub, pri, options["-pw"], options["-u"], options["-c"], options["-e"], mpz_class(options["-pks"], 10).get_ui(), mpz_class(options["-sks"], 10).get_ui());

            output(pub.write(), options["-o"] + ".public");
            output(pri.write(), options["-o"] + ".private");
        }
        catch (int & i){
            std::cerr << "Error: Unable to generate key pair." << std::endl;
        }
        catch (const std::exception & e){
            std::cerr << "Error: " << e.what() << std::endl;
        }
    }
    else if (cmd == "generate-revoke-cert"){
        std::string pri_file, passphrase;
        if (!(tokens >> pri_file >> passphrase) || (pri_file == "")){
            std::cout << "Syntax: " << commands[5] << std::endl;
            return 1;
        }
        std::ifstream f(pri_file.c_str());
        if (!f){
            std::cerr << "Error: Could not open private key file." << std::endl;
            return 1;
        }

        Options options;
        options["-o"] = "";
        options["-c"] = "0";
        options["-r"] = "";
        parse_options(tokens, options);

        try{
            PGP pri(f);
            PGP rev = revoke_primary_key_cert_key(pri, passphrase, options["-c"][0] - '0', options["-r"]);
            output(rev.write(), options["-o"]);
        }
        catch (int & i){
            std::cerr << "Error: Unable to revoke key." << std::endl;
        }
        catch (const std::exception & e){
            std::cerr << "Error: " << e.what() << std::endl;
        }
    }
    else if (cmd == "encrypt"){
        std::string data_file, pub_file;
        if (!(tokens >> data_file >> pub_file) || (data_file == "") || (pub_file == "")){
            std::cout << "Syntax: " << commands[6] << std::endl;
            return 1;
        }

        Options options;
        options["-o"] = "";
        options["-d"] = "f";
        parse_options(tokens, options);

        std::ifstream d(data_file.c_str(), std::ios::binary);
        if (!d){
            std::cout << "Error: Could not open source file." << std::endl;
            return 1;
        }
        std::stringstream s;
        s << d.rdbuf();

        std::ifstream k(pub_file.c_str());
        if (!k){
            std::cout << "Error: Could not open key file." << std::endl;
            return 1;
        }

        try{
            PGP key(k);
            output(encrypt(s.str(), key).write(), options["-o"]);
        }
        catch (int & i){
            std::cerr << "Error: Unable to encrypt data." << std::endl;
        }
        catch (const std::exception & e){
            std::cerr << "Error: " << e.what() << std::endl;
        }

        if (((options["-f"] == "t") || (options["-f"] == "b")) && (tolower(options["-d"][0]) == 't')){
            remove(data_file.c_str());
        }
    }
    else if (cmd == "decrypt"){
        std::string data_file, pri, passphrase;
        if (!(tokens >> data_file >> pri >> passphrase) || (data_file == "") || (pri == "")){
            std::cout << "Syntax: " << commands[7] << std::endl;
            return 1;
        }

        std::ifstream k(pri.c_str());
        if (!k){
            std::cerr << "Error: File " << pri << " not opened." << std::endl;
            return 1;
        }

        std::ifstream f(data_file.c_str());
        if (!f){
            std::cerr << "Error: File " << data_file << " not opened." << std::endl;
            return 1;
        }

        Options options;
        options["-o"] = "";
        options["-d"] = "f";
        parse_options(tokens, options);

        try{
            PGP key(k);
            PGP message(f);
            std::string cleartext = decrypt_message(message, key, passphrase);
            output(cleartext, options["-o"]);
        }
        catch (int & i){
            std::cerr << "Error: Unable to decrypt message block." << std::endl;
        }
        catch (const std::exception & e){
            std::cerr << "Error: " << e.what() << std::endl;
        }

        if (tolower(options["-d"][0]) == 't'){
            remove(data_file.c_str());
        }
    }
    else if (cmd == "revoke-key"){
        std::string pri, passphrase;
        if (!(tokens >> pri >> passphrase) || (pri == "")){
            std::cout << "Syntax: " << commands[8] << std::endl;
            return 1;
        }

        std::ifstream f(pri.c_str());
        if (!f){
            std::cerr << "Error: Could not open private key file." << std::endl;
            return 1;
        }

        Options options;
        options["-o"] = "";
        options["-c"] = "0";
        options["-r"] = "";
        parse_options(tokens, options);

        try{
            PGP key(f);
            PGP rev = revoke_key(key, passphrase, options["-c"][0] - '0', options["-r"]);
            output(rev.write(), options["-o"]);
        }
        catch (int & i){
            std::cerr << "Error: Unable to revoke key." << std::endl;
        }
        catch (const std::exception & e){
            std::cerr << "Error: " << e.what() << std::endl;
        }
    }
    else if (cmd == "revoke-subkey"){
        std::string pri, passphrase;
        if (!(tokens >> pri >> passphrase) || (pri == "")){
            std::cout << "Syntax: " << commands[9] << std::endl;
            return 1;
        }

        std::ifstream f(pri.c_str());
        if (!f){
            std::cerr << "Error: Could not open private key file." << std::endl;
            return 1;
        }
        PGP key(f);
        if (key.get_ASCII_Armor() != 2){
            std::cerr << "Error: Data is not a private key block." << std::endl;
            return 1;
        }

        std::vector <Packet *> packets = key.get_packets();
        bool found = false;
        for(Packet *& p : packets){
            if (p -> get_tag() == 7){
                found = true;
                break;
            }
        }

        if (!found){
            std::cerr << "Error: No Private Key Packet (Tag 5) found." << std::endl;
            return 1;
        }

        Options options;
        options["-o"] = "";
        options["-c"] = "0";
        options["-r"] = "";
        parse_options(tokens, options);

        try{
            PGP rev = revoke_subkey(key, passphrase, options["-c"][0] - '0', options["-r"]);
            output(rev.write(), options["-o"]);
        }
        catch (int & i){
            std::cerr << "Error: Unable to revoke subkey." << std::endl;
        }
        catch (const std::exception & e){
            std::cerr << "Error: " << e.what() << std::endl;
        }
    }
    else if (cmd == "sign-file"){
        std::string filename, pri, passphrase;
        if (!(tokens >> filename >> pri >> passphrase) || (filename == "") || (pri == "")){
            std::cout << "Syntax: " << commands[10] << std::endl;
            return 1;
        }

        std::ifstream k(pri.c_str());
        if (!k){
            std::cerr << "IOError: File " << pri << " not opened." << std::endl;
            return 1;
        }
        std::ifstream f(filename.c_str(), std::ios::binary);
        if (!f){
            std::cerr << "IOError: file " << filename << " could not be created." << std::endl;
            return 1;
        }

        Options options;
        options["-o"] = "";
        parse_options(tokens, options);

        try{
            PGP key(k);
            PGP signature = sign_file(f, key, passphrase);
            output(signature.write(), options["-o"]);
        }
        catch (int & i){
            std::cerr << "Error Unable to sign file." << std::endl;
        }
        catch (const std::exception & e){
            std::cerr << "Error: " << e.what() << std::endl;
        }
    }
    else if (cmd == "sign-message"){
        std::string data_file, pri, passphrase;
        if (!(tokens >> data_file >> pri >> passphrase) || (pri == "")){
            std::cout << "Syntax: " << commands[11] << std::endl;
            return 1;
        }

        std::ifstream d(data_file.c_str());
        if (!d){
            std::cerr << "IOError: File " << data_file << " not opened." << std::endl;
            return 1;
        }
        std::stringstream s;
        s << d.rdbuf();
        std::string text = s.str();

        std::ifstream k(pri.c_str());
        if (!k){
            std::cerr << "IOError: File " << pri << " not opened." << std::endl;
            return 1;
        }

        Options options;
        options["-o"] = "";
        parse_options(tokens, options);

        try{
            PGP key(k);
            PGPSignedMessage message = sign_message(text, key, passphrase);
            output(message.write(), options["-o"]);
        }
        catch (int & i){
            std::cerr << "Error Unable to sign message." << std::endl;
        }
        catch (const std::exception & e){
            std::cerr << "Error: " << e.what() << std::endl;
        }
    }
    else if (cmd == "verify-file"){
        std::string filename, signame, pub;
        if (!(tokens >> filename >> signame >> pub) || (filename == "") || (signame == "") || (pub == "")){
            std::cout << "Syntax: " << commands[12] << std::endl;
            return 1;
        }

        std::ifstream f(filename.c_str(), std::ios::binary);
        if (!f){
            std::cerr << "Error: File " << filename << " not opened." << std::endl;
            return 1;
        }
        std::ifstream s(signame.c_str());
        if (!s){
            std::cerr << "Error: File " << signame << " not opened." << std::endl;
            return 1;
        }
        std::ifstream k(pub.c_str());
        if (!k){
            std::cerr << "Error: File " << pub << " not opened." << std::endl;
            return 1;
        }
        try{
            PGP key(k), sig(s);
            std::cout << "File " << filename << " was" << (verify_file(f, sig, key)?"":" not") << " signed by key " << key << "." << std::endl;
        }
        catch (int & i){
            std::cerr << "Error Unable to verify file (Not \"not signed by this key\")." << std::endl;
        }
        catch (const std::exception & e){
            std::cerr << "Error: " << e.what() << std::endl;
        }
    }
    else if (cmd == "verify-message"){
        std::string data, pub;
        if (!(tokens >> data >> pub) || (data == "") || (pub == "")){
            std::cout << "Syntax: " << commands[13] << std::endl;
            return 1;
        }
        std::ifstream m(data.c_str());
        if (!m){
            std::cerr << "Error: File " << data << " not opened." << std::endl;
            return 1;
        }
        std::ifstream k(pub.c_str());
        if (!k){
            std::cerr << "Error: File " << pub << " not opened." << std::endl;
            return 1;
        }
        try {
            PGP key(k);
            PGPSignedMessage message(m);
            std::cout << "This message was" << (verify_message(message, key)?"":" not") << " signed by this key." << std::endl;
        }
        catch (int & i){
            std::cerr << "Error Unable to verify file (Not \"not signed by this key\")." << std::endl;
        }
        catch (const std::exception & e){
            std::cerr << "Error: " << e.what() << std::endl;
        }
    }
    else if (cmd == "verify-key"){
        std::string key_file, signer_file;
        if (!(tokens >> key_file >> signer_file) || (key_file == "") || (signer_file == "")){
            std::cout << "Syntax: " << commands[14] << std::endl;
            return 1;
        }

        std::ifstream k(key_file.c_str());
        if (!k){
            std::cerr << "Error: File " << key_file << " not opened." << std::endl;
            return 1;
        }
        std::ifstream s(signer_file.c_str());
        if (!s){
            std::cerr << "Error: File " << signer_file << " not opened." << std::endl;
            return 1;
        }

        try{
            PGP key(k);
            PGP signer(s);
            std::cout << "Key " << key << " was" << std::string(verify_signature(key, signer)?"":" not") << " signed by key " << signer << "." << std::endl;
        }
        catch (int & i){
            std::cerr << "Error Unable to verify file (Not \"not signed by this key\")." << std::endl;
        }
        catch (const std::exception & e){
            std::cerr << "Error: " << e.what() << std::endl;
        }
    }
    else{
        std::cerr << "CommandError: " << cmd << " not defined." << std::endl;
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
