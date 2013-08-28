#include "generatekey.h"

void generate_keys(std::string & public_key, std::string & private_key, const std::string & passphrase, const std::string & username, const std::string & comment, const std::string & email){
//    time_t time = now();
//
//    std::vector <integer> mpi;
//    std::vector <Subpacket *> subpackets;
//
//    // generate some pka values here
////    std::vector <integer> dsa_pub = new_DSA_public(1024, 160);
////    integer dsa_pri = DSA_keygen(dsa_pub);
////    std::vector <integer> elgamal_pub = ElGamal_keygen(1024);
////    integer elgamal_pri = elgamal_pub[3];
////    elgamal_pub.pop_back();
//
//    std::vector <integer> DSA_pub = {   integer("175466718616740411615640156350265486163809613514213656685227237159351776260193236923030228927905671867677337184318134702903960237546408302010360724274436019639502405323187799029742776686067449287558904042137172927936686590837020160292525250748155580652384740664931255981772117478967314777932252547256795892071", 10),
//                                        integer("809260232002608708872165272150356204306578772713", 10),
//                                        integer("127751900783328740354741342100721884490035793278553520238434722215554870393020469115393573782393994875216405838455564598493958342322790638050051759023658096740912555025710033120777570527002197424160086000659457154926758682221072408093235236853997248304424303705425567765059722098677806247252106481642577996274", 10),
//                                        integer("172935968966072909036304664996424500241381878537444332146572958203083745609400290814117451480512268901233962890933482206538294509037615827035398352528065134903071886710296983781453184598843331365336270501467458073523376152406987560592548479865116940266729198119357206749848310472131186772143408998928864559411", 10)};
//
//    integer DSA_pri("574961860853886082679320766680196608099720972133", 10);
//
//    std::vector <integer> elgamal_pub = {
//                                    integer("9494fec095f3b85ee286542b3836fc81a5dd0a0349b4c239dd38744d488cf8e31db8bcb7d33b41abb9e5a33cca9144b1cef332c94bf0573bf047a3aca98cdf3b", 16),
//                                    integer("153d5d6172adb43045b68ae8e1de1070b6137005686d29d3d73a7749199681ee5b212c9b96bfdcfa5b20cd5e3fd2044895d609cf9b410b7a0f12ca1cb9a428cc", 16),
//                                    integer("501de84fd9e085a9f1304c09da3a503a094fab60728f65a23d354c0203ba83d9df77fe5d3cffe66d16f7a3656d515ab27ca9f2c346d94f811ce282817f0976d1", 16)};
//
//    integer elgamal_pri = integer("674396915767399126847577835082101185163744384861202856634666173662323559993170265329273708896869586870964508182895809168214525424504917634225790325485298", 16);
//
//    std::string data;
//
//    Tag5 sec;
//    sec.set_version(4);
//    sec.set_time(time);
//    sec.set_pka(17);// DSA
//    sec.set_mpi(dsa_pub);
//    sec.set_sym(9);// AES
//
//    S2K3 s2k3;
//    s2k3.set_hash(2);
//    s2k3.set_salt(unhexlify(bintohex(BBS((unsigned int)64).rand())));
//    s2k3.set_count(96);
//
//    std::string key = s2k3.run(passphrase, 16);
//
//    sec.set_s2k(&s2k3);
//    sec.set_IV(unhexlify(bintohex(BBS((unsigned int) Symmetric_Algorithm_Block_Length.at(Symmetric_Algorithms.at(9))).rand())));
//    std::string secret = write_MPI(dsa_pri);
//    sec.set_secret(use_normal_CFB_encrypt(9, secret + use_hash(2, secret) , key, sec.get_IV()));
//
//    std::string keyid = sec.get_keyid();
//
//    Tag13 uid;
//    uid.set_name(username);
//    uid.set_comment(comment);
//    uid.set_email(email);
//
//    Tag2 sig;
//    sig.set_version(4);
//    sig.set_type(0x13);
//    sig.set_pka(17);
//    sig.set_hash(2);
////    Tag2Sub2 * tag2sub2 = new Tag2Sub2; tag2sub2 -> set_time(time);
////    sig.set_hashed_subpackets({tag2sub2});
////    Tag2Sub16 * tag2sub16 = new Tag2Sub16; tag2sub16 -> set_keyid(keyid);
////    sig.set_unhashed_subpackets({tag2sub16});
////    sig.set_left16(toint(use_hash(2, addtrailer(overkey(&sec) + certification(4, &uid), sig)).substr(0, 2), 256));
//    sig.set_left16(0);
//    data = use_hash(2, overkey(&sec) + certification(4, &uid));
//    std::vector <integer> priv = {dsa_pri};
//    sig.set_mpi(compute_signature(data, sig, dsa_pub, priv));
//
//    Tag7 ssb;
//    ssb.set_version(4);
//    ssb.set_time(time);
//    ssb.set_mpi(elgamal_pub);
//    s2k3.set_salt(unhexlify(bintohex(BBS((unsigned int)64).rand()))); // change salt value
//    ssb.set_s2k(&s2k3);
//    ssb.set_IV(unhexlify(bintohex(BBS((unsigned int) Symmetric_Algorithm_Block_Length.at(Symmetric_Algorithms.at(9))).rand())));
//    secret = write_MPI(elgamal_pri);
//    ssb.set_secret(use_normal_CFB_encrypt(9, secret + use_hash(2, secret), key, ssb.get_IV()));
//
//    Tag2 subsig;
//    subsig.set_version(4);
//    subsig.set_type(0x18);
//    subsig.set_hash(2);
////    subpackets = {tag2sub2};
////    subsig.set_hashed_subpackets(subpackets);
////    subpackets = {tag2sub16};
////    subsig.set_unhashed_subpackets(subpackets);
////    subsig.set_left16(toint(use_hash(2, addtrailer(overkey(&sec) + overkey(&ssb), sig)).substr(0, 2), 256));
//    data = overkey(&sec) + overkey(&ssb);
//    subsig.set_mpi(compute_signature(data, sig, dsa_pub, priv));
//
//    PGP pri_key;
//    pri_key.set_ASCII_Armor(2);
//    pri_key.set_Armor_Header({std::pair <std::string, std::string> ("Version", "CC")});
//    pri_key.set_packets({&sec, &uid, &sig, &ssb, &subsig});
//
//    data = sec.raw();
//    Tag6 pub(data);
//
//    data = ssb.raw();
//    Tag14 sub(data);
//
//    PGP pub_key;
//    pub_key.set_ASCII_Armor(1);
//    pub_key.set_Armor_Header({std::pair <std::string, std::string> ("Version", "CC")});
//    pub_key.set_packets({&pub, &uid, &sig, &sub, &subsig});
//
//    public_key = pub_key.write();
//    private_key = pri_key.write();
}
