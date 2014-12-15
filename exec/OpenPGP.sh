# Tab completion for OpenPGP
# by Jason Lee @ calccrypto at gmail.compgen
#
# copy this into /etc/bash_completion.d if desired

_OpenPGP(){
    local cur=${COMP_WORDS[COMP_CWORD]}
    COMPREPLY=()

    opts="--help --test --list --show --generatekeypair
          --generate-revoke-cert --encrypt-pka
          --decrypt-pka --revoke --revoke-subkey
          --sign-cleartext --sign-detach --sign-file
          --sign-key --verify-clearsign --verify-detach
          --verify-message --verify-revoke --verify-key"

    # only tab complete if first argument has not been completed
    if [[ "${COMP_CWORD}" -eq 1 ]]
    then
        COMPREPLY=( $(compgen -W "${opts}" -- ${cur}) )
    fi

    return 0
}

complete -F _OpenPGP OpenPGP
