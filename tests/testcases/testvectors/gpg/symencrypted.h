#ifndef __GPG_SYM_ENCRYPTED__
#define __GPG_SYM_ENCRYPTED__

#include <string>

const std::string GPG_SYM_ENCRYPT_TO_ALICE =
    "-----BEGIN PGP MESSAGE-----" "\n"
    "Version: GnuPG v1" "\n"
    "" "\n"
    "jA0EBwMCjmSL4aoWRspg0mABHUQbtGvYwturxuayuyFNCM1tFKhqg7Ig8RhmTAwN" "\n"
    "IyUrZuHtC0EUbxcAc1jFfuhG13/IOXhJUNCmkIXVA5PO3sH6t1If91jSGDpcV3Cp" "\n"
    "HZ8+p6UN4dDk0AiEb6CuI6M=" "\n"
    "=MBkH" "\n"
    "-----END PGP MESSAGE-----"
    ;

const std::string GPG_SYM_ENCRYPT_NO_MDC_TO_ALICE =
    "-----BEGIN PGP MESSAGE-----" "\n"
    "Version: GnuPG v1" "\n"
    "" "\n"
    "jA0EBwMCVkzo0nDGIK5gyUl9fNuN+zbLwd7gSfQS2ovO+QyTa1ju48dLVVudyWGw" "\n"
    "h1lUPPPKLM7cW9RcCcBcZG0IPC+qD88OvnwDa7YmNEKniorZa03L1YwS" "\n"
    "=Vc28" "\n"
    "-----END PGP MESSAGE-----"
    ;

#endif