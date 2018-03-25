/*
commands.h
Collection of modules for the OpenPGP executable

Copyright (c) 2013 - 2018 Jason Lee @ calccrypto at gmail.com

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
#include "fingerprint.h"
#include "show.h"
#include "show_cleartext_signature.h"
#include "extract_public.h"
#include "encrypt_pka.h"
#include "encrypt_sym.h"
#include "decrypt_pka.h"
#include "decrypt_sym.h"
#include "generate_keypair.h"
#include "generate_revoke_key_cert.h"
#include "generate_revoke_subkey_cert.h"
#include "generate_revoke_uid_cert.h"
#include "revoke_with_cert.h"
#include "revoke_primary_key.h"
#include "revoke_subkey.h"
#include "revoke_uid.h"
#include "sign_cleartext_signature.h"
#include "sign_detached_signature.h"
#include "sign_file.h"
#include "sign_primary_key.h"
#include "sign_subkey.h"
#include "sign_timestamp.h"
#include "verify_cleartext_signature.h"
#include "verify_detached_signature.h"
#include "verify_file.h"
#include "verify_primary_key.h"
#include "verify_revoke.h"
#include "verify_timestamp.h"

namespace module {

const std::vector <Module> ordered = {
    list,
    fingerprint,
    show,
    show_cleartext_signature,
    extract_public,
    encrypt_pka,
    encrypt_sym,
    decrypt_pka,
    decrypt_sym,
    generate_keypair,
    generate_revoke_key_cert,
    generate_revoke_subkey_cert,
    generate_revoke_uid_cert,
    revoke_with_cert,
    revoke_primary_key,
    revoke_subkey,
    revoke_uid,
    sign_cleartext_signature,
    sign_detached_signature,
    sign_file,
    sign_primary_key,
    sign_subkey,
    sign_timestamp,
    verify_cleartext_signature,
    verify_detached_signature,
    verify_file,
    verify_primary_key,
    verify_revoke,
    verify_timestamp,
};

}

#endif
