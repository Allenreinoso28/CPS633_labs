#include <stdio.h>
#include <openssl/bn.h>

// Helper function to print large numbers in hex format
void printBN(const char *msg, BIGNUM *a) {
    char *number_str = BN_bn2hex(a);
    printf("%s %s\n", msg, number_str);
    OPENSSL_free(number_str);
}

// This program will calculate the private key using the formula
// n = p * q
// φ(n) = (p - 1) * (q - 1)
// (e * d) ≡ 1 (mod φ(n))
// d = e^(-1) mod φ(n)
int main()
{
    BN_CTX *ctx = BN_CTX_new();

    BIGNUM *p = BN_new();
    BIGNUM *q = BN_new();
    BIGNUM *e = BN_new();
    BIGNUM *n = BN_new();
    BIGNUM *p1 = BN_new();
    BIGNUM *q1 = BN_new();
    BIGNUM *phi = BN_new();
    BIGNUM *d = NULL; // Let BN_mod_inverse allocate for us

    // Load provided hex values
    BN_hex2bn(&p, "F7E75FDC469067FFDC4E847C51F452DF");
    printBN("p = ", p);
    BN_hex2bn(&q, "E85CED54AF57E53E092113E62F436F4F");
    printBN("q = ", q);
    BN_hex2bn(&e, "0D88C3");
    printBN("e = ", e);

    // n = p * q
    BN_mul(n, p, q, ctx);
    printBN("n = p * q = ", n);

    // p1 = p - 1 ; q1 = q - 1
    BN_sub(p1, p, BN_value_one());
    BN_sub(q1, q, BN_value_one());

    // φ(n) = (p - 1) * (q - 1)
    BN_mul(phi, p1, q1, ctx);

    // d = e^(-1) mod φ(n)
    d = BN_mod_inverse(NULL, e, phi, ctx);
    printBN("d = ", d);

    // Cleanup
    BN_free(p);
    BN_free(q);
    BN_free(e);
    BN_free(n);
    BN_free(p1);
    BN_free(q1);
    BN_free(phi);
    BN_free(d);
    BN_CTX_free(ctx);

    return 0;
}
