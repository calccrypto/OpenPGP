/*
main.cpp
OpenPGP commandline source

Copyright (c) 2013, 2014 Jason Lee

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

#include "../PGP.h"                     // abstract base class
#include "../PGPCleartextSignature.h"   // Cleartext Signatures
#include "../PGPDetachedSignature.h"    // Detached Signatures
#include "../PGPKey.h"                  // Transferable Keys
#include "../PGPMessage.h"              // OpenPGP Messages

#include "../decrypt.h"                 // decrypt stuff
#include "../encrypt.h"                 // encrypt stuff
#include "../generatekey.h"             // generate OpenPGP keys
#include "../revoke.h"                  // revoke OpenPGP keys
#include "../sign.h"                    // sign stuff
#include "../verify.h"                  // verify signatures

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

    "encrypt public_key data_file [options]\n"                              // encrypt a string
    "        options:\n"
    "            -o output name\n"                                          // filename; default stdout
    "            -c compression algorithm\n"                                // 0, 1, 2, or 3; default 2; see consts.h or RFC 4880 sec 9.3 for details
    "            -d delete original?\n"                                     // t or f; default f
    "            -mdc use_mdc?\n"                                           // t or f; default t
    "            -s symmetric encryption algorithm",                        // 0 - 13; default 9; see consts.h or RFC 4880 sec 9.2 for details

    "decrypt private_key passphrase data_file [options]\n"                  // decrypt a file
    "        options:\n"
    "            -o output name\n"                                          // filename; default stdout
    "            -d delete original?",                                      // t or f; default f

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

    "sign-cleartext private_key passphrase data_file [options]\n"           // sign a string in a file
    "        options:\n"
    "            -o output name",                                           // filename; default stdout

    "sign-file private_key passphrase data_file [options]\n"                // sign a file
    "        options:\n"
    "            -o output name",                                           // filename; default stdout

    "sign-key signer passphrase data_file\n"                                // sign a key
    "        options:\n"
    "            -o output name\n"                                          // filename; default stdout
    "            -c certification level",                                   // 0x10 - 0x13; default 0x13 (without "0x")

    "verify-clearsign public_key data_file",                                // verify cleartext signature

    "verify-detach public_key data_file signature_file",                    // verify detached signature

    "verify-message public_key signature_file",                             // verify detached signature

    "verify-key signer_key_file signee_key_file",                           // verify signature
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
            std::ofstream out(filename.c_str(), std::ios::binary);
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
            return true;
        }
        else if ((cmd == "exit") || (cmd == "quit")){
            return false;
        }
        else if ((cmd == "help") || (cmd == "?")){
            std::string which;
            tokens >> which;
            if (!which.size()){
                std::cout << "Commands:\n";
                for(const std::string & c : commands){
                    std::cout << "    " << c << std::endl;
                }
                std::cout << "Passed" << std::endl;
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

            std::cout << "Generate Keys ";
            PGPPublicKey pub;
            PGPSecretKey pri;
            generate_keys(pub, pri, passphrase, "test key", "", "test@test.ing", 2048, 2048);
            std::cout << "Passed" << std::endl;

            std::cout << "Generate Revocation Certificate ";
            PGPPublicKey rev = revoke_primary_key_cert_key(pri, passphrase, 1, "Test Key");
            std::cout << "Passed" << std::endl;

            std::cout << "Show Keys (sent into null stream) ";
            null_out << pub.show() << pri.show();
            std::cout << "Passed" << std::endl;

            std::cout << "Encrypt Message ";
            PGPMessage en = encrypt(pub, message);
            std::cout << "Passed" << std::endl;

            std::cout << "Decrypt Message ";
            decrypt_message(pri, en, passphrase);
            std::cout << "Passed" << std::endl;

            std::cout << "Sign Message ";
            PGPCleartextSignature m = sign_cleartext(pri, passphrase, message);
            std::cout << "Passed" << std::endl;

            std::cout << "Verify Message ";
            if (!verify_cleartext_signature(pub, m)){
                throw std::runtime_error("Error: Could not verify message signature.");
            }
            std::cout << "Passed" << std::endl;

            std::cout << "Verify Key ";
            if (!verify_signature(pri, pub)){
                throw std::runtime_error("Error: Could not verify key signature.");
            }
            std::cout << "Passed" << std::endl;

            std::cout << "Revoke Primary Key ";
            revoke_with_cert(pub, rev);
            std::cout << "Passed" << std::endl;

            std::cout << "Revoke User ID ";
            revoke_uid(pub, pri, passphrase, 32, "Test Key");
            std::cout << "Passed" << std::endl;

            std::cout << "Test took " << std::chrono::duration_cast<std::chrono::duration<double> >(std::chrono::high_resolution_clock::now() - start).count() << " seconds." << std::endl;
        }
        else if (cmd == "list"){
            std::string file_name;
            if (!(tokens >> file_name) || (file_name == "")){
                throw std::runtime_error("Syntax: " + commands[3]);
            }
            std::ifstream f(file_name.c_str(), std::ios::binary);
            if (!f){
                throw std::runtime_error("Error: File '" + file_name + "' not opened.");
            }

            PGPPublicKey k(f);
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

            std::ifstream f(file_name.c_str(), std::ios::binary);
            if (!f){
                throw std::runtime_error("Error: File '" + file_name + "' not opened.");
            }
            if ((type == "-k") || (type == "-K")){
                PGPKey key(f);
                std::cout << key.show() << std::endl;
            }
            else if ((type == "-m") || (type == "-M")){
                PGPCleartextSignature message(f);
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

            PGPPublicKey pub;
            PGPSecretKey pri;
            generate_keys(pub, pri, options["-pw"], options["-u"], options["-c"], options["-e"], mpitoulong(dectompi(options["-pks"])), mpitoulong(dectompi(options["-sks"])));

            output(pub.write(), options["-o"] + ".public");
            output(pri.write(), options["-o"] + ".private");
        }
        else if (cmd == "generate-revoke-cert"){
            std::string pri_file, passphrase;
            if (!(tokens >> pri_file >> passphrase) || (pri_file == "")){
                throw std::runtime_error("Syntax: " + commands[6]);
            }
            std::ifstream f(pri_file.c_str(), std::ios::binary);
            if (!f){
                throw std::runtime_error("Error: File '" + pri_file + "' not opened.");
            }

            Options options;
            options["-o"] = "";
            options["-c"] = "0";
            options["-r"] = "";
            parse_options(tokens, options);

            PGPSecretKey pri(f);
            output(revoke_primary_key_cert_key(pri, passphrase, options["-c"][0] - '0', options["-r"]).write(), options["-o"]);
        }
        else if (cmd == "encrypt"){
            std::string pub_file, data_file;
            if (!(tokens >> pub_file >> data_file) || (data_file == "") || (pub_file == "")){
                throw std::runtime_error("Syntax: " + commands[7]);
            }

            Options options;
            options["-o"] = "";
            options["-c"] = "2";
            options["-d"] = "f";
            options["-mdc"] = "t";
            options["-s"] = "9";
            parse_options(tokens, options);

            std::ifstream d(data_file.c_str(), std::ios::binary);
            if (!d){
                throw std::runtime_error("Error: File '" + data_file + "' not opened.");
            }

            std::ifstream k(pub_file.c_str(), std::ios::binary);
            if (!k){
                throw std::runtime_error("Error: File '" + pub_file + "' not opened.");
            }

            std::stringstream s;
            s << d.rdbuf();

            PGPPublicKey key(k);
            output(encrypt(key, s.str(), data_file, options["-s"][0] - '0', options["-c"][0] - '0', (options["-mdc"] == "t")).write(), options["-o"]);

            if (((options["-f"] == "t") || (options["-f"] == "b")) && (tolower(options["-d"][0]) == 't')){
                remove(data_file.c_str());
            }
        }
        else if (cmd == "decrypt"){
            std::string pri, passphrase, data_file;
            if (!(tokens >> pri >> passphrase >> data_file) || (data_file == "") || (pri == "")){
                throw std::runtime_error("Syntax: " + commands[8]);
            }

            std::ifstream k(pri.c_str(), std::ios::binary);
            if (!k){
                throw std::runtime_error("Error: File '" + pri + "' not opened.");
            }

            std::ifstream f(data_file.c_str(), std::ios::binary);
            if (!f){
                throw std::runtime_error("Error: File '" + data_file + "' not opened.");
            }

            Options options;
            options["-o"] = "";
            options["-d"] = "f";
            parse_options(tokens, options);

            PGPSecretKey key(k);
            PGPMessage message(f);
            output(decrypt_message(key, message, passphrase), options["-o"]);
            if (tolower(options["-d"][0]) == 't'){
                remove(data_file.c_str());
            }
        }
        else if (cmd == "revoke"){
            std::string target_file, rev_cert_file;
            if (!(tokens >> target_file >> rev_cert_file) || (target_file == "") || (rev_cert_file == "")){
                throw std::runtime_error("Syntax: " + commands[9]);
            }
            std::ifstream t(target_file.c_str(), std::ios::binary);
            if (!t){
                throw std::runtime_error("IOError: File '" + target_file + "' not opened.");
            }
            std::ifstream cert(rev_cert_file.c_str(), std::ios::binary);
            if (!cert){
                throw std::runtime_error("IOError: File '" + rev_cert_file + "' not opened.");
            }

            Options options;
            options["-o"] = "";
            parse_options(tokens, options);

            PGPSecretKey key(t);
            PGPPublicKey rev(cert);
            output(revoke_with_cert(key, rev).write(), options["-o"]);
        }
        else if (cmd == "revoke-key"){
            std::string pri, passphrase;
            if (!(tokens >> pri >> passphrase) || (pri == "")){
                throw std::runtime_error("Syntax: " + commands[10]);
            }

            std::ifstream f(pri.c_str(), std::ios::binary);
            if (!f){
                throw std::runtime_error("Error: Could not open private key file.");
            }

            Options options;
            options["-o"] = "";
            options["-c"] = "0";
            options["-r"] = "";
            parse_options(tokens, options);

            PGPSecretKey key(f);
            output(revoke_key(key, passphrase, options["-c"][0] - '0', options["-r"]).write(), options["-o"]);
        }
        else if (cmd == "revoke-subkey"){
            std::string pri, passphrase;
            if (!(tokens >> pri >> passphrase) || (pri == "")){
                throw std::runtime_error("Syntax: " + commands[11]);
            }

            std::ifstream f(pri.c_str(), std::ios::binary);
            if (!f){
                throw std::runtime_error("IOError: File '" + pri + "' not opened.");
                return 1;
            }

            PGPSecretKey key(f);

            // find private subkey
            std::vector <Packet::Ptr> packets = key.get_packets();
            bool found = false;
            for(Packet::Ptr const & p : packets){
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
        else if (cmd == "sign-cleartext"){
            std::string pri, passphrase, data_file;
            if (!(tokens >> pri >> passphrase >> data_file) || (pri == "")){
                throw std::runtime_error("Syntax: " + commands[12]);
            }

            std::ifstream d(data_file.c_str(), std::ios::binary);
            if (!d){
                std::cerr << "IOError: File '" << data_file << "' not opened." << std::endl;
            }
            std::stringstream s;
            s << d.rdbuf();
            std::string text = s.str();

            std::ifstream k(pri.c_str(), std::ios::binary);
            if (!k){
                throw std::runtime_error("IOError: File '" + pri + "' not opened.");
            }

            Options options;
            options["-o"] = "";
            parse_options(tokens, options);

            PGPSecretKey key(k);
            output(sign_cleartext(key, passphrase, text).write(), options["-o"]);
        }
        else if (cmd == "sign-file"){
            std::string pri, passphrase, filename;
            if (!(tokens >> pri >> passphrase >> filename) || (filename == "") || (pri == "")){
                throw std::runtime_error("Syntax: " + commands[13]);
            }

            std::ifstream k(pri.c_str(), std::ios::binary);
            if (!k){
                throw std::runtime_error("IOError: File '" + pri + "' not opened.");
            }
            std::ifstream f(filename.c_str(), std::ios::binary);
            if (!f){
                throw std::runtime_error("IOError: file '" + filename + "' could not be created.");
            }

            Options options;
            options["-o"] = "";
            parse_options(tokens, options);

            PGPSecretKey key(k);
            output(sign_file(key, passphrase, f).write(), options["-o"]);
        }
        else if (cmd == "sign-key"){
            std::string signer_filename, passphrase, signee_filename;
            if (!(tokens >> signer_filename >> passphrase >> signee_filename) || (signer_filename == "") || (signee_filename == "")){
                throw std::runtime_error("Syntax: " + commands[14]);
            }

            std::ifstream signee_file(signee_filename.c_str(), std::ios::binary);
            if (!signee_file){
                throw std::runtime_error("IOError: File '" + signee_filename + "' not opened.");
            }
            std::ifstream signer_file(signer_filename.c_str(), std::ios::binary);
            if (!signer_file){
                throw std::runtime_error("IOError: File '" + signer_filename + "' not opened.");
            }

            Options options;
            options["-o"] = "";
            options["-c"] = "13";
            parse_options(tokens, options);

            PGPPublicKey signee(signee_file);
            PGPSecretKey signer(signer_file);
            output(sign_primary_key(signer, passphrase, signee, mpitoulong(hextompi(options["-c"]))).write(), options["-o"]);
        }
        else if (cmd == "verify-clearsign"){
            std::string pub, data;
            if (!(tokens >> pub >> data) || (pub == "") || (data == "")){
                throw std::runtime_error("Syntax: " + commands[15]);
            }
            std::ifstream m(data.c_str(), std::ios::binary);
            if (!m){
                throw std::runtime_error("Error: File '" + data + "' not opened.");
            }
            std::ifstream k(pub.c_str(), std::ios::binary);
            if (!k){
                throw std::runtime_error("Error: File '" + pub + "' not opened.");
            }

            PGPPublicKey key(k);
            PGPCleartextSignature message(m);
            std::cout << "This message was" << (verify_cleartext_signature(key, message)?"":" not") << " signed by this key." << std::endl;
        }
        else if (cmd == "verify-detach"){
            std::string pub, filename, signame;
            if (!(tokens >> pub >> filename >> signame) || (pub == "") || (filename == "") || (signame == "")){
                throw std::runtime_error("Syntax: " + commands[16]);
            }

            std::ifstream f(filename.c_str(), std::ios::binary);
            if (!f){
                throw std::runtime_error("Error: Data file '" + filename + "' not opened.");
            }
            std::ifstream s(signame.c_str(), std::ios::binary);
            if (!s){
                throw std::runtime_error("Error: Signature file '" + signame + "' not opened.");
                return 1;
            }
            std::ifstream k(pub.c_str(), std::ios::binary);
            if (!k){
                throw std::runtime_error("Error: Key file '" + pub + "' not opened.");
            }

            PGPPublicKey key(k);
            PGPDetachedSignature sig(s);
            std::cout << "File '" << filename << "' was" << (verify_detachedsig(key, f, sig)?"":" not") << " signed by key " << key << "." << std::endl;
        }
        else if (cmd == "verify-message"){
            std::string key_file, message_file;
            if (!(tokens >> key_file >> message_file) || (key_file == "") || (message_file == "")){
                throw std::runtime_error("Syntax: " + commands[17]);
            }

            std::ifstream k(key_file.c_str(), std::ios::binary);
            if (!k){
                throw std::runtime_error("Error: Key file '" + key_file + "' not opened.");
            }
            std::ifstream m(message_file.c_str(), std::ios::binary);
            if (!m){
                throw std::runtime_error("Error: Message file '" + message_file + "' not opened.");
            }

            PGPPublicKey pub(k);
            PGPMessage message(m);
            std::cout << "The data in '" << message_file << "' was" << (verify_message(pub, message)?"": " not") << " signed by the key " << pub << std::endl;
        }
        else if (cmd == "verify-key"){
            std::string signer_file, signee_file;
            if (!(tokens >> signer_file >> signee_file) || (signer_file == "") || (signee_file == "")){
                throw std::runtime_error("Syntax: " + commands[18]);
            }
            std::ifstream signer(signer_file.c_str(), std::ios::binary);
            if (!signer){
                throw std::runtime_error("Error: Key file '" + signer_file + "' not opened.");
            }
            std::ifstream signee(signee_file.c_str(), std::ios::binary);
            if (!signee){
                throw std::runtime_error("Error: Signing Key file '" + signee_file + "' not opened.");
            }

            PGPPublicKey signerkey(signer), signeekey(signee);
            std::cout << "Key " << signee_file << " was" << std::string(verify_signature(signerkey, signeekey)?"":" not") << " signed by key " << signerkey << "." << std::endl;
        }
        else{
            std::cerr << "CommandError: " << cmd << " not defined." << std::endl;
        }
    }
    catch (const std::exception & e){
        std::cerr << e.what() << std::endl;
    }
    return true;
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
