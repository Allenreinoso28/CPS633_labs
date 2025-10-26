#include <stdio.h>
#include <openssl/bn.h>

// Helper function to print large numbers in hex format
void printBN(const char *msg, BIGNUM *a) {
    char *number_str = BN_bn2hex(a);
    printf("%s %s\n", msg, number_str);
    OPENSSL_free(number_str);
}

// This program decrypts the ciphertext 
//"8C0F971DF2F3672B28811407E2DABBE1DA0FEBBBDFC7DCB67396567EA1E2493F" 
//using RSA:
// M = C^d mod n
int main()
{
    BN_CTX *ctx = BN_CTX_new();

    BIGNUM *n = BN_new();
    BIGNUM *d = BN_new();
    BIGNUM *messageInHex = BN_new();
    BIGNUM *cipherText = BN_new();

    // Load provided hex values
    BN_hex2bn(&n, "DCBFFE3E51F62E09CE7032E2677A78946A849DC4CDDE3A4D0CB81629242FB1A5");
    printBN("n = ", n);
    BN_hex2bn(&d, "74D806F9F3A62BAE331FFE3F0A68AFE35B3D2E4794148AACBC26AA381CD7D30D");
    printBN("d = ", d);
    BN_hex2bn(&cipherText, "8C0F971DF2F3672B28811407E2DABBE1DA0FEBBBDFC7DCB67396567EA1E2493F");
    printBN("CipherText = ", cipherText);

    // decryption M = C^d mod n
    BN_mod_exp(messageInHex, cipherText, d, n, ctx);
    printBN("Decrypted (Hex) = ", messageInHex);

    // Cleanup
    BN_free(n);
    BN_free(d);
    BN_free(messageInHex);
    BN_free(cipherText);
    BN_CTX_free(ctx);

    return 0;
}
