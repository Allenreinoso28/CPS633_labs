#include <stdio.h>
#include <openssl/bn.h>

// Helper function to print large numbers in hex format
void printBN(const char *msg, BIGNUM *a) {
    char *number_str = BN_bn2hex(a);
    printf("%s %s\n", msg, number_str);
    OPENSSL_free(number_str);
}

// This program encrypts the message "A top secret!" using RSA:
// C = M^e mod n
int main()
{
    BN_CTX *ctx = BN_CTX_new();

    BIGNUM *n = BN_new();
    BIGNUM *e = BN_new();
    BIGNUM *d = BN_new();
    BIGNUM *messageInHex = BN_new();
    BIGNUM *cipherText = BN_new();
    BIGNUM *decrypt = BN_new();

    // Load provided hex values
    BN_hex2bn(&n, "DCBFFE3E51F62E09CE7032E2677A78946A849DC4CDDE3A4D0CB81629242FB1A5");
    printBN("n = ", n);
    BN_hex2bn(&e, "010001");
    printBN("e = ", e);
    BN_hex2bn(&messageInHex, "4120746f702073656372657421");
    printBN("Message (Hex) = ", messageInHex);

    // Encryption: C = M^e mod n
    BN_mod_exp(cipherText, messageInHex, e, n, ctx);
    printBN("Ciphertext = ", cipherText);

    // Load d to verify decryption (not required but useful)
    BN_hex2bn(&d, "74D806F9F3A62BAE331FFE3F0A68AFE35B3D2E4794148AACBC26AA381CD7D30D");
    printBN("d = ", d);

    // Test decryption: M = C^d mod n
    BN_mod_exp(decrypt, cipherText, d, n, ctx);
    printBN("Decrypted (Hex) = ", decrypt);

    // Cleanup
    BN_free(n);
    BN_free(e);
    BN_free(d);
    BN_free(messageInHex);
    BN_free(cipherText);
    BN_free(decrypt);
    BN_CTX_free(ctx);

    return 0;
}
