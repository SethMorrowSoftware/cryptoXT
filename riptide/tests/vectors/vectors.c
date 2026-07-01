/*
 * vectors.c - Riptide conformance-vector known-answer test.
 *
 * Recomputes the deterministic derivations pinned in 12-conformance-vectors.md
 * DIRECTLY against libsodium (no SodiumXT shim needed, so this is self-contained
 * in the Riptide repo) and asserts each matches its published value. Exits 0 if
 * every vector matches, 1 otherwise. KDF (BLAKE2b), BLAKE2b, and ed25519 outputs
 * are stable across the libsodium 1.0.x line for fixed inputs, so this passes
 * against any 1.0.x (the CI installs the distro package).
 *
 * Build:  cc -O2 vectors.c -lsodium -o vectors && ./vectors
 */
#include <sodium.h>
#include <stdio.h>
#include <string.h>

static int g_fail = 0;

static void check(const char *label, const unsigned char *got, size_t n,
                  const char *expect_hex)
{
    char hex[256];
    sodium_bin2hex(hex, sizeof hex, got, n);
    if (strcmp(hex, expect_hex) == 0) {
        printf("  ok   - %s\n", label);
    } else {
        printf("  FAIL - %s\n         got      %s\n         expected %s\n",
               label, hex, expect_hex);
        g_fail++;
    }
}

int main(void)
{
    if (sodium_init() < 0) { fprintf(stderr, "sodium_init failed\n"); return 2; }
    printf("Riptide conformance vectors (against libsodium %s)\n",
           sodium_version_string());

    /* 12.1 identity: edSeed = KDF(S, id=0, "rp-ident", 32); IK_pub from edSeed */
    unsigned char S[32];
    for (int i = 0; i < 32; i++) S[i] = (unsigned char)i;    /* 00..1f */
    unsigned char edSeed[32];
    crypto_kdf_derive_from_key(edSeed, sizeof edSeed, 0, "rp-ident", S);
    check("12.1 edSeed", edSeed, 32,
          "cac73f09a0478224974a525036ebd73f9727ac8932162eb7fcfb2821ad7eecc7");
    unsigned char ikpub[crypto_sign_PUBLICKEYBYTES];
    unsigned char iksk[crypto_sign_SECRETKEYBYTES];
    crypto_sign_seed_keypair(ikpub, iksk, edSeed);
    check("12.1 IK_pub", ikpub, sizeof ikpub,
          "672e8e0b259627f15c772ec0d61f15cd786ce2bc7244549255f9d6cfaac300b2");

    /* 12.1 encryption keys: boxSeed = KDF(S, id=1, "rp-ident"); kxSeed = KDF(S, id=2, ...) */
    unsigned char box_seed[32], kx_seed[32];
    crypto_kdf_derive_from_key(box_seed, sizeof box_seed, 1, "rp-ident", S);
    crypto_kdf_derive_from_key(kx_seed, sizeof kx_seed, 2, "rp-ident", S);
    unsigned char ikx_pk[crypto_box_PUBLICKEYBYTES], ikx_sk[crypto_box_SECRETKEYBYTES];
    crypto_box_seed_keypair(ikx_pk, ikx_sk, box_seed);
    check("12.1 IK_x_pub", ikx_pk, sizeof ikx_pk,
          "5b9d094b6c0de5c16b3605cffd6d056144384855f82d02c352c5cffd3b60bf65");
    unsigned char kx_pk[crypto_kx_PUBLICKEYBYTES], kx_sk[crypto_kx_SECRETKEYBYTES];
    crypto_kx_seed_keypair(kx_pk, kx_sk, kx_seed);
    check("12.1 KX_pub", kx_pk, sizeof kx_pk,
          "4a9789d887a6dcb2246f1a03833dab4c6c77c57633caef004190ba5f990a3d35");

    /* 12.2 rendezvous id = KDF(ss, id=471000, "rp-rndzv", 20) */
    unsigned char ss[32]; memset(ss, 0x42, sizeof ss);
    unsigned char rid[20];
    crypto_kdf_derive_from_key(rid, sizeof rid, 471000ULL, "rp-rndzv", ss);
    check("12.2 rendezvous id", rid, sizeof rid,
          "8d28959919bb0118762ea0c0b74d4ed7b216fc6f");

    /* 12.3 presence id = KDF(ss, id=471000, "rp-prsnc", 20) */
    unsigned char pid[20];
    crypto_kdf_derive_from_key(pid, sizeof pid, 471000ULL, "rp-prsnc", ss);
    check("12.3 presence id", pid, sizeof pid,
          "e49c0e9369ac8e1a67de21abf2d9fe5f2304fdf2");

    /* 12.4 inbox id = BLAKE2b(IK_x(0x33 x32) || be64(7) || "rp-mbxid", 20) */
    unsigned char rx[32]; memset(rx, 0x33, sizeof rx);
    unsigned char in[32 + 8 + 8];
    memcpy(in, rx, 32);
    memset(in + 32, 0, 8); in[39] = 7;                       /* be64(7) */
    memcpy(in + 40, "rp-mbxid", 8);
    unsigned char iid[20];
    crypto_generichash(iid, sizeof iid, in, sizeof in, NULL, 0);
    check("12.4 inbox id", iid, sizeof iid,
          "5b2db5b4b23a3f72ec7ab7bab4a730cc009e62d6");

    /* 12.5 safety number = BLAKE2b(min||max, 32), a=0xAA b=0xBB so a||b */
    unsigned char a[32], b[32]; memset(a, 0xAA, 32); memset(b, 0xBB, 32);
    unsigned char sn_in[64]; memcpy(sn_in, a, 32); memcpy(sn_in + 32, b, 32);
    unsigned char sn[32];
    crypto_generichash(sn, sizeof sn, sn_in, sizeof sn_in, NULL, 0);
    check("12.5 safety number", sn, sizeof sn,
          "e4351a237b5150f780837f4ef69b4feb9496b48780cb07a8193803840e71a17c");

    /* 12.6 BEP44 signature over "4:salt10:rp-prekeys3:seqi1e1:v2:hi" */
    const char *sb = "4:salt10:rp-prekeys3:seqi1e1:v2:hi";
    unsigned char sig[crypto_sign_BYTES];
    crypto_sign_detached(sig, NULL, (const unsigned char *)sb, strlen(sb), iksk);
    check("12.6 BEP44 signature", sig, sizeof sig,
          "86c843ec4cc2495e025e949dd72658ef01556dbbfb1f5d9b474b5957dbcb26a2"
          "3497efe40f594387cc4f037075669efa4c42cb57c007eb0bddaa24934f3f740b");
    if (crypto_sign_verify_detached(sig, (const unsigned char *)sb, strlen(sb), ikpub) != 0) {
        printf("  FAIL - 12.6 BEP44 signature self-verify\n"); g_fail++;
    } else {
        printf("  ok   - 12.6 BEP44 signature self-verifies\n");
    }

    printf("-------------------\n");
    if (g_fail == 0) { printf("ALL VECTORS MATCH\n"); return 0; }
    printf("%d VECTOR(S) FAILED\n", g_fail); return 1;
}
