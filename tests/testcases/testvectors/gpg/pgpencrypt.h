#ifndef __TESTS_PGPENCRYPT__
#define __TESTS_PGPENCRYPT__

#include <string>

static const std::string GPG_PKA_ENCRYPT_TO_ALICE =
        "-----BEGIN PGP MESSAGE-----" "\n"
        "Version: GnuPG v1" "\n"
        "" "\n"
        "hQEMA58P9A/ScGHhAQf/UwMe4vS+PqKAjU/HJY91plKvIzrVvgzZEOYV7SZmkeis" "\n"
        "WEs5YLCcbF1lyMaNTKpGxf4XLLpwQqryPaGn98phqtKAFfiJNezZH4UB8/n4UwKl" "\n"
        "B8hiqtLZt+2XW9VwSq61eg7rwsOTMV2+biew4/M0fMxnfxlS36mtK7xpgDhrkIZy" "\n"
        "locRPKyYQva/gCrrN2kydwhE+Olr6mg74UVX9XumtzXx+cXy5aVqy/gQ96rMnZZX" "\n"
        "vmWfcHrsappqo2Fqay4QqNyUzMvKOc+A4dwyBYA6Dr5mFIcb5KUhF7CjmwvGeRnD" "\n"
        "otvPu2ygsh85zY9TdPOt8q3Jf3aX9mP/qYXEfn3hb9JtAQdDbYqyUNHoEWUarEMi" "\n"
        "3Ea9nK0QblfG2Oz7RwWdBzDpGgZMfUI4E9N+JgewnhfhhS38lsDXSQvKukCSsm6Y" "\n"
        "lBLM0RAwqxG+JGB2CkbXDeInqAelHZuSa8ZVO9jrjGjyB3fvMvZxLKsxPiBRVg==" "\n"
        "=mCKG" "\n"
        "-----END PGP MESSAGE-----"
        ;

static const std::string GPG_PKA_ENCRYPT_ALICE_TO_BOB =
        "-----BEGIN PGP MESSAGE-----" "\n"
        "Version: GnuPG v1" "\n"
        "" "\n"
        "hQEMA9QjCqNoYcNdAQgApgs5sD8I8rCDyf/m135MqNTtybb/dU9+PjaMe8BnQnY8" "\n"
        "UwXj/CedfWZ+GukGcTDmHiQLa+bkdP6A5iXYbVNoQfbRFhoZR6VvRtHWIvnxR/V6" "\n"
        "UR5iFpmL6aSWa5Lg91H2kTjxtMKTYIrWe0ttFuXO7XnL3AliLiv9Ko3hnUeolGQ3" "\n"
        "yXyluV9twaalzobgQdZ4WWLWTY2W+DCVC/ESUJoUbb2TIvVDQ6L/ulQ4WdgZSIkL" "\n"
        "4gnm4SQMvgK55Z0wbhaXoyhC+eNgWW49hm9iGbATGqR1d89iJ3jmrk3noNt69RHi" "\n"
        "IPY/esD4Aw5eQ1g8Ni67qWRtUFox0CAYZAtF51yP19LA3wH/sUrMEeudL5H8FTjk" "\n"
        "acaKfhhHQ0VveKz21aVz4pGRCujcPxzhslhD6LnZuxFEugaqVfPpjHiqvBCkMkIm" "\n"
        "85xea+0g0IZJlcoh4aVBUqRyagKlsy434fqMfGjOM70D3LNheZGLEBhfgdPaHbYN" "\n"
        "VCQljZDTyMq0i0VYmzSKMVDA07FnLZOJg/REx3+2n9OysYS3BZukIfZigH6Flx2a" "\n"
        "fedrAN4hRgploOh3MDdNgFmVv2CilgaeZkrXPN7EecahKI7EYyBKjcLzDkTKu7Pw" "\n"
        "0k1Id4C6NZSt0wyz4L4hiQ8WtYSaGmRXLLBA+GCIASre4E2f+qSNeEB6xQOdHuZ+" "\n"
        "84EFxyuCupuSRj1/6rluUe7K8NXvzoq6lrnuYLHSLI/xk08mRNMGdZG1AiVWFjvA" "\n"
        "lvMo+TUp8vBJrE86NgLdvpyip5JQ9LjjaHcwFjFEbAzGztswfLs6j/Q10e6MQNXs" "\n"
        "Dlyl7J8y+pvmmBsPuAZvQRZVVzoNbRMDfaBgUx7lm2LP4vuCrwfitnfExcJA3eYb" "\n"
        "BFWyJke4a5Nluw/gLhyi1+8=" "\n"
        "=/hTO" "\n"
        "-----END PGP MESSAGE-----"
        ;

static const std::string GPG_SYMMETRIC_ENCRYPT_TO_ALICE =
        "-----BEGIN PGP MESSAGE-----" "\n"
        "Version: GnuPG v1" "\n"
        "" "\n"
        "hQEMA58P9A/ScGHhAQf+KJgvZ0a4rLKIW063wHpcLf6ukOnEdlUNkBB3GZFTQPkG" "\n"
        "yjAW+81uCFRkjmEuWgTIDVLoGE9viQkgdpsHQgXFs6goaJimOfdKck5OUpcJgS/r" "\n"
        "Jcd9nzRJU6QnYM2/SK3LuBydgp6xAQosj2vCM0oS03A9uaKui70rOy7tqAWIPBER" "\n"
        "SJ0jq8LHrFnVU1xjOhFeqq/DQzyuejYWe04kfwcvyWhVVGJKOED1KoEY88DYs0EG" "\n"
        "Oqi+TvF/i1CR5gNEhrT8uzTyqGWIRgC3hhRo6PmZJAyIgYxGqDo/dT3OWTCiBy4x" "\n"
        "AZpPEZMUlOn2vtrLvWXUNqzzFPNqMJLK5bZ7M+NqN4wuBAMDAl8EHF1mNsiVYGq+" "\n"
        "lTvld4dwexLgr3oIAPM4nLt/3QWDegipHxPXZUpcWtJtAZBe42dZp2ykgM6otpvd" "\n"
        "Xs+p+n4WWlo7GgEmD0uDmZovp1JnKqxv7K7xNlQq2l/989eDlUWJBGxDhF4uPFZ+" "\n"
        "gBY8dv7mNIrYKbJ9BC7xEpGkAgABTESjTtT/JFFUg/EiAw5BY6au6K+VWf9hzA==" "\n"
        "=Ve5X" "\n"
        "-----END PGP MESSAGE-----"
        ;

#endif // __TESTS_PGPENCRYPT__
