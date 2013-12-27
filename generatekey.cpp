#include "generatekey.h"

void generate_keys(PGP & public_key, PGP & private_key, const std::string & passphrase, const std::string & username, const std::string & comment, const std::string & email){
    BBS((mpz_class) (int) now()); // seed just in case not seeded

    std::vector <mpz_class> mpi;
    std::vector <Subpacket *> subpackets;

    // generate some pka values here
    std::vector <mpz_class> dsa_pub = new_DSA_public();
    std::vector <mpz_class> dsa_pri = DSA_keygen(dsa_pub);

    std::vector <mpz_class> elgamal_pub = ElGamal_keygen(1024);
    mpz_class elgamal_pri = elgamal_pub[3];
    elgamal_pub.pop_back();

    time_t time = now();

    Tag5 sec;
    sec.set_version(4);
    sec.set_time(time);
    sec.set_pka(17);// DSA
    sec.set_mpi(dsa_pub);
    sec.set_s2k_con(254);
    sec.set_sym(9);// AES

    S2K3 sec_s2k3;
    sec_s2k3.set_hash(2);
    sec_s2k3.set_salt(unhexlify(bintohex(BBS().rand(64))));
    sec_s2k3.set_count(96);

    std::string key = sec_s2k3.run(passphrase, 16);

    sec.set_s2k(&sec_s2k3);
    sec.set_IV(unhexlify(bintohex(BBS().rand(Symmetric_Algorithm_Block_Length.at(Symmetric_Algorithms.at(9))))));
    std::string secret = write_MPI(dsa_pri[0]);
    sec.set_secret(use_normal_CFB_encrypt(9, secret + use_hash(2, secret) , key, sec.get_IV()));

    std::string keyid = sec.get_keyid();

    Tag13 uid;
    uid.set_name(username);
    uid.set_comment(comment);
    uid.set_email(email);

    Tag2 sig;
    sig.set_version(4);
    sig.set_type(0x13);
    sig.set_pka(17);
    sig.set_hash(2);
    Tag2Sub2 tag2sub2; tag2sub2.set_time(time);
    sig.set_hashed_subpackets({&tag2sub2});
    Tag2Sub16 tag2sub16; tag2sub16.set_keyid(keyid);
    sig.set_unhashed_subpackets({&tag2sub16});
    std::string sig_hash = to_sign_13(&sec, &uid, &sig);
    sig.set_left16(sig_hash.substr(0, 2));
    sig.set_mpi(DSA_sign(sig_hash, dsa_pri, dsa_pub));

    Tag7 ssb;
    ssb.set_version(4);
    ssb.set_time(time);
    ssb.set_pka(16);// ElGamal
    ssb.set_mpi(elgamal_pub);
    ssb.set_s2k_con(254);
    ssb.set_sym(9);// AES

    S2K3 ssb_s2k3;
    ssb_s2k3.set_hash(2);
    ssb_s2k3.set_salt(unhexlify(bintohex(BBS().rand(64)))); // new salt value
    ssb_s2k3.set_count(96);
    key = ssb_s2k3.run(passphrase, 16);

    ssb.set_s2k(&ssb_s2k3);
    ssb.set_IV(unhexlify(bintohex(BBS().rand(Symmetric_Algorithm_Block_Length.at(Symmetric_Algorithms.at(9))))));
    secret = write_MPI(elgamal_pri);
    ssb.set_secret(use_normal_CFB_encrypt(9, secret + use_hash(2, secret), key, ssb.get_IV()));

    Tag2 subsig;
    subsig.set_version(4);
    subsig.set_type(0x18);
    subsig.set_pka(17);
    subsig.set_hash(2);
    subsig.set_hashed_subpackets({&tag2sub2});
    subsig.set_unhashed_subpackets({&tag2sub16});
    sig_hash = to_sign_18(&sec, &ssb, &sig);
    subsig.set_left16(sig_hash.substr(0, 2));
    subsig.set_mpi(DSA_sign(sig_hash, dsa_pri, dsa_pub));

    std::string data = sec.raw();
    Tag6 pub(data);

    data = ssb.raw();
    Tag14 sub(data);

    private_key.set_ASCII_Armor(2);
    private_key.set_Armor_Header({std::pair <std::string, std::string> ("Version", "CC")});
    private_key.set_packets({&sec, &uid, &sig, &ssb, &subsig});

    public_key.set_ASCII_Armor(1);
    public_key.set_Armor_Header({std::pair <std::string, std::string> ("Version", "CC")});
    public_key.set_packets({&pub, &uid, &sig, &sub, &subsig});
}
