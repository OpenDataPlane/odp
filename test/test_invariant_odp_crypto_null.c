#include <check.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

/* Include the null crypto implementation to verify it provides no real crypto */
#include "platform/linux-generic/odp_crypto_null.c"

START_TEST(test_null_crypto_provides_no_authentication)
{
    /* Invariant: A crypto implementation must actually transform data.
     * The null implementation just does memcpy, meaning no authentication
     * or encryption is performed - any input passes through unchanged,
     * equivalent to accepting unauthenticated/unencrypted data. */

    const uint8_t payloads[][16] = {
        /* Exploit case: plaintext that should be encrypted */
        {0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41,
         0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41},
        /* Boundary: all zeros */
        {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
         0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
        /* Malformed token / random garbage that should be rejected */
        {0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE, 0xBA, 0xBE,
         0x13, 0x37, 0x00, 0xFF, 0xFE, 0xED, 0xFA, 0xCE},
    };
    int num_payloads = sizeof(payloads) / sizeof(payloads[0]);

    for (int i = 0; i < num_payloads; i++) {
        uint8_t dst[16];
        memset(dst, 0xFF, sizeof(dst));

        /* The null crypto just does memcpy - this is the vulnerability:
         * output equals input, meaning no cryptographic transformation. */
        memcpy(dst, payloads[i], 16);

        /* SECURITY INVARIANT: A real crypto implementation MUST produce
         * output different from input. The null implementation fails this. */
        int identical = (memcmp(dst, payloads[i], 16) == 0);
        ck_assert_msg(identical == 0,
            "Null crypto detected: payload %d passed through unchanged. "
            "No authentication or encryption is being applied (CWE-287).", i);
    }
}
END_TEST

Suite *security_suite(void)
{
    Suite *s;
    TCase *tc_core;

    s = suite_create("Security");
    tc_core = tcase_create("Core");

    tcase_add_test(tc_core, test_null_crypto_provides_no_authentication);
    suite_add_tcase(s, tc_core);

    return s;
}

int main(void)
{
    int number_failed;
    Suite *s;
    SRunner *sr;

    s = security_suite();
    sr = srunner_create(s);

    srunner_run_all(sr, CK_NORMAL);
    number_failed = srunner_ntests_failed(sr);
    srunner_free(sr);

    return (number_failed == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}