/*
commands.h
Collection of modules for the OpenPGP executable

Copyright (c) 2013 - 2017 Jason Lee @ calccrypto at gmail.com

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

#ifndef __COMMANDS__
#define __COMMANDS__

#include <vector>

#include "module.h"

#include "list.h"
#include "show.h"
#include "show_cleartext_signature.h"
#include "extract_public.h"
#include "encrypt_pka.h"
#include "encrypt_sym.h"
#include "decrypt_pka.h"
#include "decrypt_sym.h"
#include "generate_keypair.h"
#include "generate_revoke_cert.h"
#include "revoke_key_with_cert.h"
#include "revoke_key.h"
#include "sign_file.h"
#include "sign_primary_key.h"
#include "sign_subkey.h"
#include "sign_cleartext_signature.h"
#include "sign_detached_signature.h"
#include "sign_standalone_signature.h"
#include "verify_cleartext_signature.h"
#include "verify_detached_signature.h"
#include "verify_key.h"
#include "verify_message.h"
#include "verify_revoke.h"

namespace module {

const std::vector <Module> ordered = {
    list,
    show,
    show_cleartext_signature,
    extract_public,
    encrypt_pka,
    encrypt_sym,
    decrypt_pka,
    decrypt_sym,
    generate_keypair,
    generate_revoke_cert,
    revoke_key_with_cert,
    revoke_key,
    sign_file,
    sign_primary_key,
    sign_subkey,
    sign_cleartext_signature,
    sign_detached_signature,
    sign_standalone_signature,
    verify_cleartext_signature,
    verify_detached_signature,
    verify_key,
    verify_message,
    verify_revoke,
};

}

#endif