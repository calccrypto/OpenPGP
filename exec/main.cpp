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
#include <stdexcept>
#include <vector>

#include "../PGP.h"
#include "../PGPSignedMessage.h"

#include "../decrypt.h"
#include "../encrypt.h"
#include "../generatekey.h"
#include "../revoke.h"
#include "../sign.h"
#include "../verify.h"

typedef std::map <std::string, std::string> Options;                        // simple type for storing function options + values

const std::vector <std::string> commands = {
    "help [optional search string]",                                        // get help on commands; if there is a search string, it only searches the front of strings for matches

    "exit | quit\n",                                                        // end program

    "test",                                                                 // test some functions

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

    "revoke target revocation_certificate\n"                                // revoke a key with a revocation certificate
    "        options:\n"
    "            -o output name",                                           // filename; default stdout

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

    "sign-key signee signer passphrase\n"                                   // sign a key
    "        options:\n"
    "            -o output name\n"                                          // filename; default stdout
    "            -c certification level",                                   // 0x10 - 0x13; default 0x13 (without "0x")

    "sign-message data_file private_key passphrase [options]\n"             // sign a string in a file
    "        options:\n"
    "            -o output name",                                           // filename; default stdout

    "verify-file data_file signature_file public_key",                      // verify detached signature

    "verify-message data_file public_key",                                  // verify signed message

    "verify-key key_file signer_key_file",                                  // verify signature
};

// simple stringstream to option + value
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
                throw std::runtime_error("Error: File " + filename + " could not be opened.");
            }

            out << data;
        }
        catch (const std::exception & e){
            std::cerr << "Error: " << e.what() << "\n" << data << std::endl;
        }
    }
    else{
        std::cout << data << std::endl;
    }
}

// function to parse commands
bool parse_command(std::string & input){
    try{
        std::stringstream tokens(input);
        std::string cmd; tokens >> cmd;
        if (cmd == ""){
            return 1;
        }
        else if ((cmd == "exit") || (cmd == "quit")){
            return 0;
        }
        else if (cmd == "help"){
            std::string which;
            tokens >> which;
            if (!which.size()){
                std::cout << "Commands:\n";
                for(const std::string & c : commands){
                    std::cout << "    " << c << std::endl;
                }
                std::cout << std::endl;
            }
            else{
                bool found = false;
                for(const std::string & c : commands){
                    if (c.substr(0, which.size()) == which){ // only check if front matches
                        std::cout << "" + c << std::endl;
                        found = true;
                    }
                }
                if (!found){
                    std::cerr << "Error: Search string \"" + which + "\" does not match any commands." << std::endl;
                }
            }
        }
        else if (cmd == "test"){
            std::chrono::high_resolution_clock::time_point start = std::chrono::high_resolution_clock::now();

            const std::string passphrase = "abc";
            const std::string message = "testing testing 123";

            std::cout << "Generate Keys" << std::endl;
            PGP pub, pri;
            generate_keys(pub, pri, passphrase, "test key", "", "test@test.ing", 2048, 2048);

            std::cout << "Generate Revocation Certificate" << std::endl;
            PGP rev = revoke_primary_key_cert_key(pri, passphrase, 1, "Test Key");

            std::cout << "Show Keys (sent into null stream)" << std::endl;
            null_out << pub.show() << pri.show();

            std::cout << "Encrypt Message" << std::endl;
            PGP en = encrypt(message, pub);

            std::cout << "Decrypt Message" << std::endl;
            decrypt_message(en, pri, passphrase);

            std::cout << "Sign Message" << std::endl;
            PGPSignedMessage m = sign_message(message, pri, passphrase);

            std::cout << "Verify Message" << std::endl;
            if (!verify_message(m, pub)){
                throw std::runtime_error("Error: Could not verify message signature.");
            }

            std::cout << "Verify Key" << std::endl;
            if (!verify_signature(pub, pri)){
                throw std::runtime_error("Error: Could not verify key signature.");
            }

            std::cout << "Revoke Primary Key" << std::endl;
            revoke_with_cert(pub, rev);

            std::cout << "Revoke User ID" << std::endl;
            revoke_uid(pub, pri, passphrase, 32, "Test Key");

            std::cout << "Test took " << std::chrono::duration_cast<std::chrono::duration<double> >(std::chrono::high_resolution_clock::now() - start).count() << " seconds." << std::endl;
        }
        else if (cmd == "list"){
            std::string file_name;
            if (!(tokens >> file_name) || (file_name == "")){
                throw std::runtime_error("Syntax: " + commands[3]);
            }
            std::ifstream f(file_name.c_str());
            if (!f){
                throw std::runtime_error("Error: File " + file_name + " not opened.");
            }

            PGP k(f);
            std::cout << k.list_keys() << std::endl;
        }
        else if (cmd == "show"){
            std::string type, file_name;
            if (!(tokens >> type >> file_name) ||
               (!((type == "-k") || (type == "-K")) && !((type == "-m") || (type == "-M"))) ||
                (file_name == "")){
                throw std::runtime_error("Syntax: " + commands[4]);
                return 1;
            }

            std::ifstream f(file_name.c_str());
            if (!f){
                throw std::runtime_error("Error: File " + file_name + " not opened.");
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
                std::cout << "Syntax: " << commands[4] << std::endl;
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
                throw std::runtime_error("Syntax: " + commands[5]);
            }

            PGP pub, pri;
            generate_keys(pub, pri, options["-pw"], options["-u"], options["-c"], options["-e"], mpz_class(options["-pks"], 10).get_ui(), mpz_class(options["-sks"], 10).get_ui());

            output(pub.write(), options["-o"] + ".public");
            output(pri.write(), options["-o"] + ".private");
        }
        else if (cmd == "generate-revoke-cert"){
            std::string pri_file, passphrase;
            if (!(tokens >> pri_file >> passphrase) || (pri_file == "")){
                throw std::runtime_error("Syntax: " + commands[6]);
            }
            std::ifstream f(pri_file.c_str());
            if (!f){
                throw std::runtime_error("Error: File " + pri_file + " not opened.");
            }

            Options options;
            options["-o"] = "";
            options["-c"] = "0";
            options["-r"] = "";
            parse_options(tokens, options);

            PGP pri(f);
            output(revoke_primary_key_cert_key(pri, passphrase, options["-c"][0] - '0', options["-r"]).write(), options["-o"]);
        }
        else if (cmd == "encrypt"){
            std::string data_file, pub_file;
            if (!(tokens >> data_file >> pub_file) || (data_file == "") || (pub_file == "")){
                throw std::runtime_error("Syntax: " + commands[7]);
            }

            Options options;
            options["-o"] = "";
            options["-d"] = "f";
            parse_options(tokens, options);

            std::ifstream d(data_file.c_str(), std::ios::binary);
            if (!d){
                throw std::runtime_error("Error: File " + data_file + " not opened.");
            }

            std::ifstream k(pub_file.c_str());
            if (!k){
                throw std::runtime_error("Error: File " + pub_file + " not opened.");
            }

            std::stringstream s;
            s << d.rdbuf();

            PGP key(k);
            output(encrypt(s.str(), key).write(), options["-o"]);

            if (((options["-f"] == "t") || (options["-f"] == "b")) && (tolower(options["-d"][0]) == 't')){
                remove(data_file.c_str());
            }
        }
        else if (cmd == "decrypt"){
            std::string data_file, pri, passphrase;
            if (!(tokens >> data_file >> pri >> passphrase) || (data_file == "") || (pri == "")){
                throw std::runtime_error("Syntax: " + commands[8]);
            }

            std::ifstream k(pri.c_str());
            if (!k){
                throw std::runtime_error("Error: File " + pri + " not opened.");
            }

            std::ifstream f(data_file.c_str());
            if (!f){
                throw std::runtime_error("Error: File " + data_file + " not opened.");
            }

            Options options;
            options["-o"] = "";
            options["-d"] = "f";
            parse_options(tokens, options);

            PGP key(k);
            PGP message(f);
            output(decrypt_message(message, key, passphrase), options["-o"]);
            if (tolower(options["-d"][0]) == 't'){
                remove(data_file.c_str());
            }
        }
        else if (cmd == "revoke"){
            std::string target_file, rev_cert_file;
            if (!(tokens >> target_file >> rev_cert_file) || (target_file == "") || (rev_cert_file == "")){
                throw std::runtime_error("Syntax: " + commands[9]);
            }
            std::ifstream t(target_file.c_str());
            if (!t){
                throw std::runtime_error("IOError: File " + target_file + " not opened.");
            }
            std::ifstream cert(rev_cert_file.c_str());
            if (!cert){
                throw std::runtime_error("IOError: File " + rev_cert_file + " not opened.");
            }

            Options options;
            options["-o"] = "";
            parse_options(tokens, options);

            PGP key(t);
            PGP rev(cert);
            output(revoke_with_cert(key, rev).write(), options["-o"]);
        }
        else if (cmd == "revoke-key"){
            std::string pri, passphrase;
            if (!(tokens >> pri >> passphrase) || (pri == "")){
                throw std::runtime_error("Syntax: " + commands[10]);
            }

            std::ifstream f(pri.c_str());
            if (!f){
                throw std::runtime_error("Error: Could not open private key file.");
            }

            Options options;
            options["-o"] = "";
            options["-c"] = "0";
            options["-r"] = "";
            parse_options(tokens, options);

            PGP key(f);
            output(revoke_key(key, passphrase, options["-c"][0] - '0', options["-r"]).write(), options["-o"]);
        }
        else if (cmd == "revoke-subkey"){
            std::string pri, passphrase;
            if (!(tokens >> pri >> passphrase) || (pri == "")){
                throw std::runtime_error("Syntax: " + commands[11]);
            }

            std::ifstream f(pri.c_str());
            if (!f){
                std::cerr << "Error: Could not open private key file." << std::endl;
                return 1;
            }

            PGP key(f);

            // find private subkey
            std::vector <Packet *> packets = key.get_packets();
            bool found = false;
            for(Packet *& p : packets){
                if (p -> get_tag() == 7){
                    found = true;
                    break;
                }
            }

            if (!found){
                throw std::runtime_error("Error: No Private Subkey Packet (Tag 5) found.");
            }

            Options options;
            options["-o"] = "";
            options["-c"] = "0";
            options["-r"] = "";
            parse_options(tokens, options);

            output(revoke_subkey(key, passphrase, options["-c"][0] - '0', options["-r"]).write(), options["-o"]);
        }
        else if (cmd == "sign-file"){
            std::string filename, pri, passphrase;
            if (!(tokens >> filename >> pri >> passphrase) || (filename == "") || (pri == "")){
                throw std::runtime_error("Syntax: " + commands[12]);
            }

            std::ifstream k(pri.c_str());
            if (!k){
                throw std::runtime_error("IOError: File " + pri + " not opened.");
            }
            std::ifstream f(filename.c_str(), std::ios::binary);
            if (!f){
                throw std::runtime_error("IOError: file " + filename + " could not be created.");
            }

            Options options;
            options["-o"] = "";
            parse_options(tokens, options);

            PGP key(k);
            output(sign_file(f, key, passphrase).write(), options["-o"]);
        }
        else if (cmd == "sign-key"){
            std::string signee_filename, signer_filename, passphrase;
            if (!(tokens >> signee_filename >> signer_filename >> passphrase) || (signee_filename == "") || (signer_filename == "")){
                throw std::runtime_error("Syntax: " + commands[13]);
            }

            std::ifstream signee_file(signee_filename.c_str());
            if (!signee_file){
                throw std::runtime_error("IOError: File " + signee_filename + " not opened.");
            }
            std::ifstream signer_file(signer_filename.c_str());
            if (!signer_file){
                throw std::runtime_error("IOError: File " + signer_filename + " not opened.");
            }

            Options options;
            options["-o"] = "";
            options["-c"] = "13";
            parse_options(tokens, options);

            PGP signee(signee_file);
            PGP signer(signer_file);
            output(sign_primary_key(signee, signer, passphrase, mpz_class(options["-c"], 16).get_ui()).write(), options["-o"]);
        }
        else if (cmd == "sign-message"){
            std::string data_file, pri, passphrase;
            if (!(tokens >> data_file >> pri >> passphrase) || (pri == "")){
                throw std::runtime_error("Syntax: " + commands[14]);
            }

            std::ifstream d(data_file.c_str());
            if (!d){
                std::cerr << "IOError: File " << data_file << " not opened." << std::endl;
            }
            std::stringstream s;
            s << d.rdbuf();
            std::string text = s.str();

            std::ifstream k(pri.c_str());
            if (!k){
                throw std::runtime_error("IOError: File " + pri + " not opened.");
            }

            Options options;
            options["-o"] = "";
            parse_options(tokens, options);

            PGP key(k);
            output(sign_message(text, key, passphrase).write(), options["-o"]);
        }
        else if (cmd == "verify-file"){
            std::string filename, signame, pub;
            if (!(tokens >> filename >> signame >> pub) || (filename == "") || (signame == "") || (pub == "")){
                throw std::runtime_error("Syntax: " + commands[15]);
            }

            std::ifstream f(filename.c_str(), std::ios::binary);
            if (!f){
                throw std::runtime_error("Error: File " + filename + " not opened.");
            }
            std::ifstream s(signame.c_str());
            if (!s){
                throw std::runtime_error("Error: File " + signame + " not opened.");
                return 1;
            }
            std::ifstream k(pub.c_str());
            if (!k){
                throw std::runtime_error("Error: File " + pub + " not opened.");
            }

            PGP key(k), sig(s);
            std::cout << "File " << filename << " was" << (verify_file(f, sig, key)?"":" not") << " signed by key " << key << "." << std::endl;
        }
        else if (cmd == "verify-message"){
            std::string data, pub;
            if (!(tokens >> data >> pub) || (data == "") || (pub == "")){
                throw std::runtime_error("Syntax: " + commands[16]);
            }
            std::ifstream m(data.c_str());
            if (!m){
                throw std::runtime_error("Error: File " + data + " not opened.");
            }
            std::ifstream k(pub.c_str());
            if (!k){
                throw std::runtime_error("Error: File " + pub + " not opened.");
            }

            PGP key(k);
            PGPSignedMessage message(m);
            std::cout << "This message was" << (verify_message(message, key)?"":" not") << " signed by this key." << std::endl;
        }
        else if (cmd == "verify-key"){
            std::string key_file, signer_file;
            if (!(tokens >> key_file >> signer_file) || (key_file == "") || (signer_file == "")){
                throw std::runtime_error("Syntax: " + commands[17]);
            }

            std::ifstream k(key_file.c_str());
            if (!k){
                throw std::runtime_error("Error: File " + key_file + " not opened.");
            }
            std::ifstream s(signer_file.c_str());
            if (!s){
                throw std::runtime_error("Error: File " + signer_file + " not opened.");
            }

            PGP key(k);
            PGP signer(s);
            std::cout << "Key " << key << " was" << std::string(verify_signature(key, signer)?"":" not") << " signed by key " << signer << "." << std::endl;
        }
        else{
            std::cerr << "CommandError: " << cmd << " not defined." << std::endl;
        }
    }
    catch (const std::exception & e){
        std::cerr << e.what() << std::endl;
    }
    return 1;
}

int main(int argc, char * argv[]){
    std::string input = "";
    // no commandline arguments
    if (argc == 1){
        std::cout << "An OpenPGP implementation (RFC 4880)\nby Jason Lee @ calccrypto@gmail.com\n\n"
                  << "Type help or ? for command syntax\n\n" << std::endl;
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
