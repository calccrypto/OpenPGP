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

#include <cctype>
#include <chrono>
#include <fstream>
#include <iostream>
#include <map>
#include <sstream>
#include <stdexcept>
#include <vector>

#include "../OpenPGP.h"

typedef std::map <std::string, std::string> Options;                        // simple type for storing function options + values

const std::vector <std::string> commands = {
    // 0
    "help [optional search string]",                                        // get help on commands; if there is a search string, it only searches the front of strings for matches
    // 1
    "exit | quit\n",                                                        // end program
    // 2
    "test",                                                                 // test some functions
    // 3
    "list key-file",                                                        // list keys in file, like 'gpg --list-keys'
    // 4
    "show -p|-c filename [options]\n"                                       // display contents of a key file; -p for general PGP data, -c for cleartext signed data
    "        options:\n"
    "            -o output file\n",                                         // where to output data
    // 5
    "generatekeypair [options]\n"                                           // generate new key pair
    "        options:\n"
    "            -o output file\n"                                          // where to output data
    "            -a armored\n"                                              // d (default: "pre-existing internal value"), t, or f; default d; whether or not to armor output
    "            -h\n"                                                      // help, since there is no way to fail token reading
    "            -pks public key size\n"                                    // bits; default 2048
    "            -sks subkey size\n"                                        // bits; default 2048
    "            -pw passphrase\n"                                          // string; default ""
    "            -u username\n"                                             // string; default ""
    "            -c comment\n"                                              // string; default ""
    "            -e email",                                                 // string; default ""
    // 6
    "generate-revoke-cert private-key passphrase [options]\n"               // generate a revocation certificate for later
    "        options:\n"
    "            -o output file\n"                                          // where to output data
    "            -a armored\n"                                              // d (default: "pre-existing internal value"), t, or f; default d; whether or not to armor output
    "            -c code\n"                                                 // 0, 1, 2, or 3
    "            -r reason",                                                // some string
    // 7
    "encrypt-pka public-key data-file [options]\n"                          // encrypt with a public key
    "        options:\n"
    "            -o output file\n"                                          // where to output data
    "            -a armored\n"                                              // d (default: "pre-existing internal value"), t, or f; default d; whether or not to armor output
    "            -c compression algorithm\n"                                // Uncompressed, ZIP (DEFLATE), ZLIB, BZIP2; default ZLIB; see consts.h or RFC 4880 sec 9.3 for details
    "            -d delete original?\n"                                     // t or f; default f
    "            -mdc use-mdc?\n"                                           // t or f; default t
    "            -p passphrase for signing key\n"                           // used with "-sign"
    "            -sign private key file\n"                                  // private key filename; option "-p" must also be used
    "            -sym symmetric encryption algorithm",                      // default AES256; see consts.h or RFC 4880 sec 9.2 for details
    // 8
    "decrypt-pka private-key passphrase data-file [options]\n"              // decrypt with a private key
    "        options:\n"
    "            -a armored\n"                                              // d (default: "pre-existing internal value"), t, or f; default d; whether or not to armor output
    "            -d delete original?\n"                                     // t or f; default f
    "            -v signing public key\n"                                   // public key file of signer
    "            -w write to file?",                                        // t or f; default t
    // 9
    "revoke target revocation-certificate [options]\n"                      // revoke a key with a revocation certificate
    "            -o output file\n"                                          // where to output data
    "            -a armored",                                               // d (default: "pre-existing internal value"), t, or f; default d; whether or not to armor output
    // 10
    "revoke-key private-key passphrase [options]\n"                         // revoke a primary key
    "        options:\n"
    "            -o output file\n"                                          // where to output data
    "            -a armored\n"                                              // d (default: "pre-existing internal value"), t, or f; default d; whether or not to armor output
    "            -c code\n"                                                 // 0, 1, 2, or 3
    "            -r reason",                                                // some string
    // 11
    "revoke-subkey private-key passphrase [options]\n"                      // revoke a subkey
    "        options:\n"
    "            -o output file\n"                                          // where to output data
    "            -a armored\n"                                              // d (default: "pre-existing internal value"), t, or f; default d; whether or not to armor output
    "            -c code\n"                                                 // 0, 1, 2, or 3
    "            -r reason",                                                // some string
    // 12
    "sign-cleartext private-key passphrase data-file [options]\n"           // sign a string in a file
    "        options:\n"
    "            -o output file\n"                                          // where to output data
    "            -a armored\n"                                              // d (default: "pre-existing internal value"), t, or f; default d; whether or not to armor output
    "            -h hash algorithm",                                        // default SHA1; see consts.h or RFC 4880 sec for values
    // 13
    "sign-detach private-key passphrase data-file [options]\n"              // sign a file
    "        options:\n"
    "            -o output file\n"                                          // where to output data
    "            -a armored\n"                                              // d (default: "pre-existing internal value"), t, or f; default d; whether or not to armor output
    "            -h hash algorithm",                                        // default SHA1; see consts.h or RFC 4880 sec for values
    // 14
    "sign-file private-key passphrase data-file [options]\n"                // sign a file
    "        options:\n"
    "            -o output file\n"                                          // where to output data
    "            -a armored\n"                                              // d (default: "pre-existing internal value"), t, or f; default d; whether or not to armor output
    "            -c compression algorithm\n"                                // Uncompressed, ZIP (DEFLATE), ZLIB, BZIP2; default ZLIB; see consts.h or RFC 4880 sec 9.3 for details
    "            -h hash algorithm",                                        // default SHA1; see consts.h or RFC 4880 sec for values
    // 15
    "sign-key signer passphrase data-file\n"                                // sign a key
    "        options:\n"
    "            -o output file\n"                                          // where to output data
    "            -a armored\n"                                              // d (default: "pre-existing internal value"), t, or f; default d; whether or not to armor output
    "            -c certification level",                                   // 0x10 - 0x13; default 0x13 (without "0x")
    // 16
    "verify-clearsign public-key data-file",                                // verify cleartext signature
    // 17
    "verify-detach public-key data-file signature-file",                    // verify detached signature
    // 18
    "verify-message public-key signature-file",                             // verify detached signature
    // 19
    "verify-revoke public-key revocation-certificate",                      // verify a revocation certificate is valid; used after generating the certificate
    // 20
    "verify-key signer-key-file signee-key-file",                           // verify signature
};

// simple stringstream to option + value
void parse_options(std::stringstream & tokens, Options & options){
    std::string o, v;
    while (tokens >> o >> v){
        options[o] = v;
    }
}

// force all characters to lowercase
std::string lower(const std::string & in){
    std::string out = "";
    for(char const & c : in){
        out += std::string(1, tolower(c));
    }
    return out;
}

// force all characters to uppercase
std::string upper(const std::string & in){
    std::string out = "";
    for(char const & c : in){
        out += std::string(1, toupper(c));
    }
    return out;
}

// find all commands that match given input
std::string find_command(const std::string & input){
    std::stringstream out;
    unsigned int len = input.size();
    bool found = false;
    for(const std::string & c : commands){
        if (c.substr(0, len) == input){ // only check if front matches
            out << c << "\n\n";
            found = true;
        }
    }
    if (!found){
        out << "Error: Search string \"" + input + "\" does not match any commands.";
    }
    return out.str();
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
// args: whether or not input was passed from terminal
bool parse_command(std::string & input, bool args = false){
    try{
        std::stringstream tokens(input);
        std::string cmd; tokens >> cmd;

        // remove "--" from front of input, if they came from console
        if (args && (cmd.substr(0, 2) == "--")){
            cmd = cmd.substr(2, cmd.size() - 2);
        }

        if (!args && (cmd == "")){
            return true;
        }
        else if ((cmd == "exit") || (cmd == "quit")){
            return false;
        }
        else if ((cmd == "help") || (cmd == "?")){
            std::string which;
            tokens >> which;
            if (!which.size()){
                std::cout << "\nCommands:\n";
                for(const std::string & c : commands){
                    std::cout << "    " << c << "\n\n";
                }
                std::cout << std::endl;
            }
            else{
                std::cout << find_command(which) << std::endl;;
            }
        }
        else if (cmd == "test"){
            // These test do not check against known values. Rather,
            // they only make sure that the functions don't throw
            // exceptions (which for the most part, also means that
            // the values are correct).

            std::chrono::high_resolution_clock::time_point start = std::chrono::high_resolution_clock::now();

            const std::string passphrase = "abc";
            const std::string message = "testing testing 123";

            std::cout << "Generate Keys "; std::cout.flush();
            PGPPublicKey pub;
            PGPSecretKey pri;
            generate_keys(pub, pri, passphrase, "test key", "", "test@test.ing", 2048, 2048);
            std::cout << "Passed" << std::endl;

            std::cout << "Generate Revocation Certificate "; std::cout.flush();
            PGPPublicKey rev = revoke_primary_key_cert_key(pri, passphrase, 1, "Test Key");
            std::cout << "Passed" << std::endl;

            std::cout << "Show Keys (sent into null stream) "; std::cout.flush();
            null_out << pub.show() << pri.show();
            std::cout << "Passed" << std::endl;

            std::cout << "Encrypt Message "; std::cout.flush();
            PGPMessage en = encrypt_pka(pub, message, "", 9, 2, true, nullptr, "");
            std::cout << "Passed" << std::endl;

            std::cout << "Decrypt Message "; std::cout.flush();
            decrypt_pka(pri, en, passphrase, false, nullptr);
            std::cout << "Passed" << std::endl;

            std::cout << "Sign Message "; std::cout.flush();
            PGPCleartextSignature m = sign_cleartext(pri, passphrase, message, 2);
            std::cout << "Passed" << std::endl;

            std::cout << "Verify Message "; std::cout.flush();
            if (!verify_cleartext_signature(pub, m)){
                throw std::runtime_error("Error: Could not verify message signature.");
            }
            std::cout << "Passed" << std::endl;

            std::cout << "Verify Key "; std::cout.flush();
            if (!verify_key(pri, pub)){
                throw std::runtime_error("Error: Could not verify key signature.");
            }
            std::cout << "Passed" << std::endl;

            std::cout << "Revoke Primary Key "; std::cout.flush();
            revoke_with_cert(pub, rev);
            std::cout << "Passed" << std::endl;

            std::cout << "Revoke User ID "; std::cout.flush();
            revoke_uid(pub, pri, passphrase, 32, "Test Key");
            std::cout << "Passed" << std::endl;

            std::cout << "Test took " << std::chrono::duration_cast<std::chrono::duration<double> >(std::chrono::high_resolution_clock::now() - start).count() << " seconds." << std::endl;
        }
        else if (cmd == "list"){
            std::string filename;
            if (!(tokens >> filename) || (filename == "")){
                throw std::runtime_error("Syntax: " + commands[3]);
            }
            std::ifstream f(filename.c_str(), std::ios::binary);
            if (!f){
                throw std::runtime_error("Error: File '" + filename + "' not opened.");
            }

            PGPPublicKey k(f);
            std::cout << k.list_keys() << std::endl;
        }
        else if (cmd == "show"){
            std::string type, filename;
            if (!(tokens >> type >> filename) || (filename == "")){
                throw std::runtime_error("Syntax: " + commands[4]);
                return 1;
            }

            type = lower(type);
            if (!(type == "-p") && !(type == "-c")){
                throw std::runtime_error("Syntax: " + commands[4]);
                return 1;
            }

            std::ifstream f(filename.c_str(), std::ios::binary);
            if (!f){
                throw std::runtime_error("Error: File '" + filename + "' not opened.");
            }

            Options options;
            options["-o"] = "";
            parse_options(tokens, options);

            if (type == "-p"){
                PGPMessage data(f);
                output(data.show(), options["-o"]);
            }
            else if (type == "-c"){
                PGPCleartextSignature message(f);
                output(message.show(), options["-o"]);
            }
            else{
                std::cout << "Syntax: " << commands[4] << std::endl;
            }
        }
        else if (cmd == "generatekeypair"){
            Options options;
            options["-o"] = "";
            options["-a"] = "d";
            options["-pks"] = "1024";
            options["-sks"] = "1024";
            options["-pws"] = "";
            options["-u"] = "";
            options["-c"] = "";
            options["-e"] = "";
            parse_options(tokens, options);
            options["-a"] = lower(options["-a"]);

            if (options.find("-h") != options.end()){
                throw std::runtime_error("Syntax: " + commands[5]);
            }

            PGPPublicKey pub;
            PGPSecretKey pri;

            generate_keys(pub, pri, options["-pw"], options["-u"], options["-c"], options["-e"], mpitoulong(dectompi(options["-pks"])), mpitoulong(dectompi(options["-sks"])));

            output(pub.write((options["-a"] == "f")?1:(options["-a"] == "t")?2:0), options["-o"] + ".public");
            output(pri.write((options["-a"] == "f")?1:(options["-a"] == "t")?2:0), options["-o"] + ".private");
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
            options["-a"] = "d";
            options["-c"] = "0";
            options["-r"] = "";
            parse_options(tokens, options);
            options["-a"] = lower(options["-a"]);

            PGPSecretKey pri(f);

            output(revoke_primary_key_cert_key(pri, passphrase, options["-c"][0] - '0', options["-r"]).write((options["-a"] == "f")?1:(options["-a"] == "t")?2:0), options["-o"]);
        }
        else if (cmd == "encrypt-pka"){
            std::string pub_file, data_file;
            if (!(tokens >> pub_file >> data_file) || (data_file == "") || (pub_file == "")){
                throw std::runtime_error("Syntax: " + commands[7]);
            }

            Options options;
            options["-o"] = "";
            options["-a"] = "d";
            options["-c"] = "ZLIB";
            options["-d"] = "f";
            options["-mdc"] = "t";
            // options["-p"] = "";
            options["-sign"] = "";
            options["-sym"] = "AES256";
            parse_options(tokens, options);
            options["-a"] = lower(options["-a"]);
            options["-c"] = upper(options["-c"]);
            options["-d"] = lower(options["-d"]);
            options["-mdc"] = lower(options["-mdc"]);
            options["-sym"] = upper(options["-sym"]);

            // check input
            std::ifstream d(data_file.c_str(), std::ios::binary);
            if (!d){
                throw std::runtime_error("Error: File '" + data_file + "' not opened.");
            }

            std::ifstream k(pub_file.c_str(), std::ios::binary);
            if (!k){
                throw std::runtime_error("Error: File '" + pub_file + "' not opened.");
            }

            if (Compression_Numbers.find(options["-c"]) == Compression_Numbers.end()){
                throw std::runtime_error("Error: Bad Compression Algorithm Number");
            }

            if (Symmetric_Algorithms_Numbers.find(options["-sym"]) == Symmetric_Algorithms_Numbers.end()){
                throw std::runtime_error("Error: Bad Symmetric Key Algorithm Number");
            }

            PGPSecretKey::Ptr signer = nullptr;
            if (options["-sign"].size()){
                if (options.find("-p") == options.end()){ // need to check whether or not "-p" was used, not whether or not the passphrase is an empty string
                    throw std::runtime_error("Error: Option \"-p\" and singer passphrase needed.");
                }

                std::ifstream signing(options["-sign"], std::ios::binary);
                if (!signing){
                    throw std::runtime_error("Error: File '" + options["-sign"] + "' not opened.");
                }
                signer = std::make_shared <PGPSecretKey> (signing);
            }
            else {
                if (options.find("-p") != options.end()){
                    std::cerr << "Warning: Passphrase provided without a Signing Key. Ignored." << std::endl;
                }
            }

            std::stringstream s;
            s << d.rdbuf();

            PGPPublicKey key(k);

            output(encrypt_pka(key, s.str(), data_file, Symmetric_Algorithms_Numbers.at(options["-sym"]), Compression_Numbers.at(options["-c"]), (options["-mdc"] == "t"), signer, options["-p"]).write((options["-a"] == "f")?1:(options["-a"] == "t")?2:0), options["-o"]);

            if (((options["-f"] == "t") || (options["-f"] == "b")) && (options["-d"] == "t")){
                remove(data_file.c_str());
            }
        }
        else if (cmd == "decrypt-pka"){
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
            options["-a"] = "d";
            options["-d"] = "f";
            options["-v"] = "";
            options["-w"] = "t";
            parse_options(tokens, options);
            options["-a"] = lower(options["-a"]);
            options["-d"] = lower(options["-d"]);
            options["-w"] = lower(options["-w"]);

            PGPPublicKey::Ptr signer = nullptr;
            if (options["-v"].size()){
                std::ifstream v(options["-v"], std::ios::binary);
                if (!v){
                    throw std::runtime_error("Error: File '" + options["-v"] + "' not opened.");
                }
                signer = std::make_shared <PGPPublicKey> (v);
            }

            PGPSecretKey key(k);
            PGPMessage message(f);

            output(decrypt_pka(key, message, passphrase, (options["-w"] == "t"), signer), "");
            if (options["-d"] == "t"){
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
            options["-a"] = "d";
            parse_options(tokens, options);
            options["-a"] = lower(options["-a"]);

            PGPSecretKey key(t);
            PGPPublicKey rev(cert);

            output(revoke_with_cert(key, rev).write((options["-a"] == "f")?1:(options["-a"] == "t")?2:0), options["-o"]);
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
            options["-a"] = "d";
            options["-c"] = "0";
            options["-r"] = "";
            parse_options(tokens, options);
            options["-a"] = lower(options["-a"]);

            PGPSecretKey key(f);

            output(revoke_key(key, passphrase, options["-c"][0] - '0', options["-r"]).write((options["-a"] == "f")?1:(options["-a"] == "t")?2:0), options["-o"]);
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
            options["-a"] = "d";
            options["-c"] = "0";
            options["-r"] = "";
            parse_options(tokens, options);
            options["-a"] = lower(options["-a"]);

            output(revoke_subkey(key, passphrase, options["-c"][0] - '0', options["-r"]).write((options["-a"] == "f")?1:(options["-a"] == "t")?2:0), options["-o"]);
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
            options["-a"] = "d";
            options["-h"] = "SHA1";
            parse_options(tokens, options);
            options["-a"] = lower(options["-a"]);
            options["-h"] = upper(options["-h"]);

            if (Hash_Numbers.find(options["-h"]) == Hash_Numbers.end()){
                throw std::runtime_error("Error: Bad Hash Algorithm Number");
            }

            PGPSecretKey key(k);

            output(sign_cleartext(key, passphrase, text).write((options["-a"] == "f")?1:(options["-a"] == "t")?2:0), options["-o"]);
        }
        else if (cmd == "sign-detach"){
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
                throw std::runtime_error("IOError: file '" + filename + "' could not be opened.");
            }

            Options options;
            options["-o"] = "";
            options["-a"] = "d";
            options["-h"] = "SHA1";
            parse_options(tokens, options);
            options["-a"] = lower(options["-a"]);
            options["-h"] = upper(options["-h"]);

            if (Hash_Numbers.find(options["-h"]) == Hash_Numbers.end()){
                throw std::runtime_error("Error: Bad Hash Algorithm Number");
            }

            PGPSecretKey key(k);

            output(sign_detach(key, passphrase, f, Hash_Numbers.at(options["-h"])).write((options["-a"] == "f")?1:(options["-a"] == "t")?2:0), options["-o"]);
        }
        else if (cmd == "sign-file"){
            std::string pri, passphrase, filename;
            if (!(tokens >> pri >> passphrase >> filename) || (filename == "") || (pri == "")){
                throw std::runtime_error("Syntax: " + commands[14]);
            }

            std::ifstream k(pri.c_str(), std::ios::binary);
            if (!k){
                throw std::runtime_error("IOError: File '" + pri + "' not opened.");
            }
            std::ifstream f(filename.c_str(), std::ios::binary);
            if (!f){
                throw std::runtime_error("IOError: file '" + filename + "' could not be opened.");
            }

            Options options;
            options["-o"] = "";
            options["-a"] = "d";
            options["-c"] = "ZLIB";
            options["-h"] = "SHA1";
            parse_options(tokens, options);
            options["-a"] = lower(options["-a"]);
            options["-c"] = upper(options["-c"]);
            options["-h"] = upper(options["-h"]);

            if (Compression_Numbers.find(options["-c"]) == Compression_Numbers.end()){
                throw std::runtime_error("Error: Bad Compression Algorithm Number");
            }

            if (Hash_Numbers.find(options["-h"]) == Hash_Numbers.end()){
                throw std::runtime_error("Error: Bad Hash Algorithm Number");
            }

            PGPSecretKey key(k);

            output(sign_message(key, passphrase, filename, f, Hash_Numbers.at(options["-h"]), Compression_Numbers.at(options["-c"])).write((options["-a"] == "f")?1:(options["-a"] == "t")?2:0), options["-o"]);
        }
        else if (cmd == "sign-key"){
            std::string signer_filename, passphrase, signee_filename;
            if (!(tokens >> signer_filename >> passphrase >> signee_filename) || (signer_filename == "") || (signee_filename == "")){
                throw std::runtime_error("Syntax: " + commands[15]);
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
            options["-a"] = "d";
            options["-c"] = "13";
            parse_options(tokens, options);
            options["-a"] = lower(options["-a"]);

            PGPPublicKey signee(signee_file);
            PGPSecretKey signer(signer_file);

            output(sign_primary_key(signer, passphrase, signee, mpitoulong(hextompi(options["-c"]))).write((options["-a"] == "f")?1:(options["-a"] == "t")?2:0), options["-o"]);
        }
        else if (cmd == "verify-clearsign"){
            std::string pub, data;
            if (!(tokens >> pub >> data) || (pub == "") || (data == "")){
                throw std::runtime_error("Syntax: " + commands[16]);
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
                throw std::runtime_error("Syntax: " + commands[17]);
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
                throw std::runtime_error("Syntax: " + commands[18]);
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
        else if (cmd == "verify-revoke"){
            std::string key_file, cert_file;
            if (!(tokens >> key_file >> cert_file) || (key_file == "") || (cert_file == "")){
                throw std::runtime_error("Syntax: " + commands[19]);
            }

            std::ifstream k(key_file.c_str(), std::ios::binary);
            if (!k){
                throw std::runtime_error("Error: Key file '" + key_file + "' not opened.");
            }
            std::ifstream c(cert_file.c_str(), std::ios::binary);
            if (!c){
                throw std::runtime_error("Error: Revocation certificate file '" + cert_file + "' not opened.");
            }

            PGPPublicKey pub(k);
            PGPPublicKey cert(c);

            std::cout << "The certificate in '" << cert_file << "' " << (verify_revoke(pub, cert)?std::string("revokes"):std::string("does not revoke")) << " key " << pub << std::endl;
        }
        else if (cmd == "verify-key"){
            std::string signer_file, signee_file;
            if (!(tokens >> signer_file >> signee_file) || (signer_file == "") || (signee_file == "")){
                throw std::runtime_error("Syntax: " + commands[20]);
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

            std::cout << "Key in '" << signee_file << "' was" << std::string(verify_key(signerkey, signeekey)?"":" not") << " signed by key " << signerkey << "." << std::endl;
        }
        else{
            if (args){
                std::stringstream out; out << "Error: Search string \"" + input + "\" does not match any commands.";
                throw std::runtime_error(out.str());
            }
            else {
                std::cout << find_command(cmd) << std::endl;
            }
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
        while (parse_command(input, false)){
            std::cout << "> ";
            getline(std::cin, input);
        }
    }
    // has commandline arguments
    else{
        for(int x = 1; x < argc; x++){
            input += std::string(argv[x]) + " ";
        }
        parse_command(input, true);
    }
    return 0;
}
