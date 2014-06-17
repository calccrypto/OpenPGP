#ifndef __TESTS_TRIPLEDESECBPERMOP__
#define __TESTS_TRIPLEDESECBPERMOP__

#include <string>
#include <vector>

// Test vectors from <http://csrc.nist.gov/groups/STM/cavp/documents/des/KAT_TDES.zip>

static const std::vector<std::string> TDES_ECB_PERMOP_KEY = {
    "1046913489980131",
    "1007103489988020",
    "10071034c8980120",
    "1046103489988020",
    "1086911519190101",
    "1086911519580101",
    "5107b01519580101",
    "1007b01519190101",
    "3107915498080101",
    "3107919498080101",
    "10079115b9080140",
    "3107911598080140",
    "1007d01589980101",
    "9107911589980101",
    "9107d01589190101",
    "1007d01598980120",
    "1007940498190101",
    "0107910491190401",
    "0107910491190101",
    "0107940491190401",
    "19079210981a0101",
    "1007911998190801",
    "10079119981a0801",
    "1007921098190101",
    "100791159819010b",
    "1004801598190101",
    "1004801598190102",
    "1004801598190108",
    "1002911598100104",
    "1002911598190104",
    "1002911598100201",
    "1002911698100101",
};

static const std::string TDES_ECB_PERMOP_PLAIN = "0000000000000000";

static const std::vector<std::string> TDES_ECB_PERMOP_CIPHER = {
    "88d55e54f54c97b4",
    "0c0cc00c83ea48fd",
    "83bc8ef3a6570183",
    "df725dcad94ea2e9",
    "e652b53b550be8b0",
    "af527120c485cbb0",
    "0f04ce393db926d5",
    "c9f00ffc74079067",
    "7cfd82a593252b4e",
    "cb49a2f9e91363e3",
    "00b588be70d23f56",
    "406a9a6ab43399ae",
    "6cb773611dca9ada",
    "67fd21c17dbb5d70",
    "9592cb4110430787",
    "a6b7ff68a318ddd3",
    "4d102196c914ca16",
    "2dfa9f4573594965",
    "b46604816c0e0774",
    "6e7e6221a4f34e87",
    "aa85e74643233199",
    "2e5a19db4d1962d6",
    "23a866a809d30894",
    "d812d961f017d320",
    "055605816e58608f",
    "abd88e8b1b7716f1",
    "537ac95be69da1e1",
    "aed0f6ae3c25cdd8",
    "b3e35a5ee53e7b8d",
    "61c79c71921a2ef8",
    "e2f5728f0995013c",
    "1aeac39a61f0a464",
};

#endif // __TESTS_TRIPLEDESECBPERMOP__
