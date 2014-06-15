#ifndef __TESTS_TRIPLEDESECBSUBTAB__
#define __TESTS_TRIPLEDESECBSUBTAB__

#include <string>
#include <vector>

// Test vectors from <http://csrc.nist.gov/groups/STM/cavp/documents/des/KAT_TDES.zip>

static const std::vector<std::string> TDES_ECB_SUBTAB_KEY = {
    "7ca110454a1a6e57",
    "0131d9619dc1376e",
    "07a1133e4a0b2686",
    "3849674c2602319e",
    "04b915ba43feb5b6",
    "0113b970fd34f2ce",
    "0170f175468fb5e6",
    "43297fad38e373fe",
    "07a7137045da2a16",
    "04689104c2fd3b2f",
    "37d06bb516cb7546",
    "1f08260d1ac2465e",
    "584023641aba6176",
    "025816164629b007",
    "49793ebc79b3258f",
    "4fb05e1515ab73a7",
    "49e95d6d4ca229bf",
    "018310dc409b26d6",
    "1c587f1c13924fef",
};

static const std::vector<std::string> TDES_ECB_SUBTAB_PLAIN = {
    "01a1d6d039776742",
    "5cd54ca83def57da",
    "0248d43806f67172",
    "51454b582ddf440a",
    "42fd443059577fa2",
    "059b5e0851cf143a",
    "0756d8e0774761d2",
    "762514b829bf486a",
    "3bdd119049372802",
    "26955f6835af609a",
    "164d5e404f275232",
    "6b056e18759f5cca",
    "004bd6ef09176062",
    "480d39006ee762f2",
    "437540c8698f3cfa",
    "072d43a077075292",
    "02fe55778117f12a",
    "1d9d5c5018f728c2",
    "305532286d6f295a",
};

static const std::vector<std::string> TDES_ECB_SUBTAB_CIPHER = {
    "690f5b0d9a26939b",
    "7a389d10354bd271",
    "868ebb51cab4599a",
    "7178876e01f19b2a",
    "af37fb421f8c4095",
    "86a560f10ec6d85b",
    "0cd3da020021dc09",
    "ea676b2cb7db2b7a",
    "dfd64a815caf1a0f",
    "5c513c9c4886c088",
    "0a2aeeae3ff4ab77",
    "ef1bf03e5dfa575a",
    "88bf0db6d70dee56",
    "a1f9915541020b56",
    "6fbf1cafcffd0556",
    "2f22e49bab7ca1ac",
    "5a6b612cc26cce4a",
    "5f4c038ed12b2e41",
    "63fac0d034d9f793",
};

#endif // __TESTS_TRIPLEDESECBSUBTAB__
