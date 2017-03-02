/*
commands.h
Collection of modules for the OpenPGP executable

Copyright (c) 2013 - 2017 Jason Lee @ calccrypto@gmail.com

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
#include "show_clearsign.h"
#include "encrypt_pka.h"
#include "decrypt_pka.h"
#include "generate_key_pair.h"
#include "generate_revoke_cert.h"
#include "revoke.h"
#include "revoke_key.h"
#include "revoke_subkey.h"
#include "sign_cleartext.h"
#include "sign_detach.h"
#include "sign_file.h"
#include "sign_key.h"
#include "verify_cleartext_signature.h"
#include "verify_detachedsig.h"
#include "verify_key.h"
#include "verify_message.h"
#include "verify_revoke.h"

namespace module {

const std::vector <Module> ordered = {
    list,
    show,
    show_clearsign,
    encrypt_pka,
    decrypt_pka,
    generate_key_pair,
    generate_revoke_cert,
    revoke,
    revoke_key,
    revoke_subkey,
    sign_cleartext,
    sign_detach,
    sign_file,
    sign_key,
    verify_cleartext_signature,
    verify_detachedsig,
    verify_key,
    verify_message,
    verify_revoke,
};

}

#endif