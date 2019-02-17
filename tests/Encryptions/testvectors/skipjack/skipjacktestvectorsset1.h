#ifndef __SKIPJACKTESTVECTORSSET1__
#define __SKIPJACKTESTVECTORSSET1__

#include "../plainkeycipher.h"

// Test vector from <https://www.cosic.esat.kuleuven.be/nessie/testvectors/bc/skipjack/Skipjack-80-64.unverified.test-vectors>

static const std::vector <PlainKeyCipher> SKIPJACK_TEST_VECTORS_SET_1 = {
    std::make_tuple("0000000000000000", "80000000000000000000", "45DD4CC4A5DC2E85"),
    std::make_tuple("0000000000000000", "40000000000000000000", "68C5C12948FC0530"),
    std::make_tuple("0000000000000000", "20000000000000000000", "2ADD9242FEDAFFFA"),
    std::make_tuple("0000000000000000", "10000000000000000000", "F11E0FEBF47B8B22"),
    std::make_tuple("0000000000000000", "08000000000000000000", "F3CCE8E3EC54AB91"),
    std::make_tuple("0000000000000000", "04000000000000000000", "95C8258B308EF91C"),
    std::make_tuple("0000000000000000", "02000000000000000000", "1747AF58BE173FF8"),
    std::make_tuple("0000000000000000", "01000000000000000000", "1404E22175CD4B8C"),
    std::make_tuple("0000000000000000", "00800000000000000000", "77FDDDE637EB5862"),
    std::make_tuple("0000000000000000", "00400000000000000000", "E60077C1F4883862"),
    std::make_tuple("0000000000000000", "00200000000000000000", "B87D4A97C788EBDD"),
    std::make_tuple("0000000000000000", "00100000000000000000", "68EC08EAC1549B10"),
    std::make_tuple("0000000000000000", "00080000000000000000", "D58EE1B9BBEC603C"),
    std::make_tuple("0000000000000000", "00040000000000000000", "FE9549DB728C2C2F"),
    std::make_tuple("0000000000000000", "00020000000000000000", "141CD335D859DCBF"),
    std::make_tuple("0000000000000000", "00010000000000000000", "0AF4EB2B4E83B133"),
    std::make_tuple("0000000000000000", "00008000000000000000", "D7C84BD7EAFBE650"),
    std::make_tuple("0000000000000000", "00004000000000000000", "66B2408B208328D9"),
    std::make_tuple("0000000000000000", "00002000000000000000", "40490C9F490B1AFB"),
    std::make_tuple("0000000000000000", "00001000000000000000", "3368860FF0D8A908"),
    std::make_tuple("0000000000000000", "00000800000000000000", "EF011CE100413EED"),
    std::make_tuple("0000000000000000", "00000400000000000000", "070B3AB3E2C585C6"),
    std::make_tuple("0000000000000000", "00000200000000000000", "ABC0FB752EA58205"),
    std::make_tuple("0000000000000000", "00000100000000000000", "256747A23FF12BB3"),
    std::make_tuple("0000000000000000", "00000080000000000000", "1E789E8C7D4ACD2B"),
    std::make_tuple("0000000000000000", "00000040000000000000", "E3EEF23A7A130018"),
    std::make_tuple("0000000000000000", "00000020000000000000", "03022DCA7BBF9E4A"),
    std::make_tuple("0000000000000000", "00000010000000000000", "57C8D5B36FB66291"),
    std::make_tuple("0000000000000000", "00000008000000000000", "83FD3535C5F77168"),
    std::make_tuple("0000000000000000", "00000004000000000000", "16B4A9AC4875BCCB"),
    std::make_tuple("0000000000000000", "00000002000000000000", "13451903F3BA8108"),
    std::make_tuple("0000000000000000", "00000001000000000000", "DA7AA8B715FA5037"),
    std::make_tuple("0000000000000000", "00000000800000000000", "DBAC9B6C639D5838"),
    std::make_tuple("0000000000000000", "00000000400000000000", "53B2D4A9C234780B"),
    std::make_tuple("0000000000000000", "00000000200000000000", "211D79B60C9EC8AA"),
    std::make_tuple("0000000000000000", "00000000100000000000", "52CEE2DE8330B29A"),
    std::make_tuple("0000000000000000", "00000000080000000000", "A1942D6B911CBA21"),
    std::make_tuple("0000000000000000", "00000000040000000000", "BD6550EB672F86D1"),
    std::make_tuple("0000000000000000", "00000000020000000000", "E360AF2A7A072336"),
    std::make_tuple("0000000000000000", "00000000010000000000", "C977BE5B71F98FC9"),
    std::make_tuple("0000000000000000", "00000000008000000000", "50E29171084B8FFD"),
    std::make_tuple("0000000000000000", "00000000004000000000", "A53623490BCC3F49"),
    std::make_tuple("0000000000000000", "00000000002000000000", "0B49054EC42095F6"),
    std::make_tuple("0000000000000000", "00000000001000000000", "6E9714659CEB0EC0"),
    std::make_tuple("0000000000000000", "00000000000800000000", "500AA0D3D86ADBAD"),
    std::make_tuple("0000000000000000", "00000000000400000000", "2BB3FF473551A85F"),
    std::make_tuple("0000000000000000", "00000000000200000000", "F4682407D13F3B35"),
    std::make_tuple("0000000000000000", "00000000000100000000", "12E9B52EEEAB7AB5"),
    std::make_tuple("0000000000000000", "00000000000080000000", "CF786272E18129DA"),
    std::make_tuple("0000000000000000", "00000000000040000000", "A366ED4762FA39D0"),
    std::make_tuple("0000000000000000", "00000000000020000000", "30CCFB5F0ACA919D"),
    std::make_tuple("0000000000000000", "00000000000010000000", "9AC9A035047E3A1E"),
    std::make_tuple("0000000000000000", "00000000000008000000", "7AAB0801A79DC0CE"),
    std::make_tuple("0000000000000000", "00000000000004000000", "1F7B50011334B89B"),
    std::make_tuple("0000000000000000", "00000000000002000000", "C2B1EC7E5E33CC76"),
    std::make_tuple("0000000000000000", "00000000000001000000", "D61D66D22D38C65D"),
    std::make_tuple("0000000000000000", "00000000000000800000", "4F746E5CDEAF9AEE"),
    std::make_tuple("0000000000000000", "00000000000000400000", "5CB87EACA4F19FC5"),
    std::make_tuple("0000000000000000", "00000000000000200000", "4998C8818C93B535"),
    std::make_tuple("0000000000000000", "00000000000000100000", "9C7B19C7F51D418A"),
    std::make_tuple("0000000000000000", "00000000000000080000", "6E78ADD65A114A01"),
    std::make_tuple("0000000000000000", "00000000000000040000", "DC58938E2B07AC4F"),
    std::make_tuple("0000000000000000", "00000000000000020000", "AEE5A656EBE265D1"),
    std::make_tuple("0000000000000000", "00000000000000010000", "5B021DEBD4C66F6A"),
    std::make_tuple("0000000000000000", "00000000000000008000", "AF5F1C1FB7A523E3"),
    std::make_tuple("0000000000000000", "00000000000000004000", "A63938A76E331A3F"),
    std::make_tuple("0000000000000000", "00000000000000002000", "0FCCBCA0C0148721"),
    std::make_tuple("0000000000000000", "00000000000000001000", "E69C3177EDDB83F3"),
    std::make_tuple("0000000000000000", "00000000000000000800", "497E1D4AF29881AC"),
    std::make_tuple("0000000000000000", "00000000000000000400", "B58061B82A81A560"),
    std::make_tuple("0000000000000000", "00000000000000000200", "692D1828C7BCDFB7"),
    std::make_tuple("0000000000000000", "00000000000000000100", "00FDABCEBD21A0A3"),
    std::make_tuple("0000000000000000", "00000000000000000080", "8B23F5B021DDDE07"),
    std::make_tuple("0000000000000000", "00000000000000000040", "D430467BAC4299B6"),
    std::make_tuple("0000000000000000", "00000000000000000020", "9A152404942EDDB6"),
    std::make_tuple("0000000000000000", "00000000000000000010", "3D29E8CCEFD27CC1"),
    std::make_tuple("0000000000000000", "00000000000000000008", "61B2ED95251AAF84"),
    std::make_tuple("0000000000000000", "00000000000000000004", "AB2BB15B2D3B22E4"),
    std::make_tuple("0000000000000000", "00000000000000000002", "D4C8FBE975C1D4A1"),
    std::make_tuple("0000000000000000", "00000000000000000001", "5E3966155B19E32F"),
};

#endif // __SKIPJACKTESTVECTORSSET1__