/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2015-2018 Linaro Limited
 * Copyright (c) 2021-2022 Nokia
 */

#include <odp_api.h>
#include <odp_cunit_common.h>

static void random_test_get_size(odp_random_kind_t kind)
{
	/* odp_random_data may fail to return data on every call (i.e. lack of
	 * entropy). Therefore loop with some sane loop timeout value. Note that
	 * it is not required for implementation to return data in the "timeout"
	 * amount of steps. Rather it is a way for preventing the test to loop
	 * forever.
	 * Also note that the timeout value here is chosen completely
	 * arbitrarily (although considered sane) and neither platforms or
	 * applications are not required to use it.
	 */
	int32_t ret, timeout_ns = 1 * ODP_TIME_MSEC_IN_NS, sleep_ns = 100;
	uint32_t bytes = 0;
	uint8_t buf[32];

	do {
		ret = odp_random_data(buf + bytes, sizeof(buf) - bytes,
				      kind);
		bytes += ret;
		if (ret < 0 || bytes >= sizeof(buf))
			break;
		odp_time_wait_ns(sleep_ns);
		timeout_ns -= sleep_ns;
	} while (timeout_ns > 0);

	CU_ASSERT(ret > 0);
	CU_ASSERT(bytes == (int32_t)sizeof(buf));
}

static void random_test_get_size_basic(void)
{
	random_test_get_size(ODP_RANDOM_BASIC);
}

static void random_test_get_size_crypto(void)
{
	random_test_get_size(ODP_RANDOM_CRYPTO);
}

static void random_test_get_size_true(void)
{
	random_test_get_size(ODP_RANDOM_TRUE);
}

static void random_test_kind(void)
{
	int32_t rc;
	uint8_t buf[4096];
	uint32_t buf_size = sizeof(buf);
	odp_random_kind_t max_kind = odp_random_max_kind();

	rc = odp_random_data(buf, buf_size, max_kind);
	CU_ASSERT(rc > 0);

	switch (max_kind) {
	case ODP_RANDOM_BASIC:
		rc = odp_random_data(buf, 4, ODP_RANDOM_CRYPTO);
		CU_ASSERT(rc < 0);
		/* Fall through */

	case ODP_RANDOM_CRYPTO:
		rc = odp_random_data(buf, 4, ODP_RANDOM_TRUE);
		CU_ASSERT(rc < 0);
		break;

	default:
		break;
	}
}

static void random_test_repeat(void)
{
	uint8_t buf1[1024];
	uint8_t buf2[1024];
	int32_t rc;
	uint64_t seed1 = 12345897;
	uint64_t seed2 = seed1;

	rc = odp_random_test_data(buf1, sizeof(buf1), &seed1);
	CU_ASSERT(rc == sizeof(buf1));

	rc = odp_random_test_data(buf2, sizeof(buf2), &seed2);
	CU_ASSERT(rc == sizeof(buf2));

	CU_ASSERT(seed1 == seed2);
	CU_ASSERT(memcmp(buf1, buf2, sizeof(buf1)) == 0);
}

static void random_data(uint8_t *buf, uint32_t len, odp_random_kind_t kind)
{
	static uint64_t seed;

	switch (kind) {
	case ODP_RANDOM_BASIC:
	case ODP_RANDOM_CRYPTO:
	case ODP_RANDOM_TRUE:
		for (uint32_t i = 0; i < len;) {
			int32_t r = odp_random_data(buf + i, len - i, kind);

			CU_ASSERT_FATAL(r >= 0);
			i += r;
		}
		break;
	default:
		CU_ASSERT_FATAL(odp_random_test_data(buf, len, &seed) ==
				(int32_t)len);
	}
}

static void random_test_align_and_overflow(odp_random_kind_t kind)
{
	uint8_t ODP_ALIGNED_CACHE buf[64];

	for (int align = 8; align < 16; align++) {
		for (int len = 1; len <= 16; len++) {
			memset(buf, 1, sizeof(buf));
			random_data(buf + align, len, kind);
			CU_ASSERT(buf[align - 1] == 1);
			CU_ASSERT(buf[align + len] == 1);
		}
	}
}

static void random_test_align_and_overflow_test(void)
{
	random_test_align_and_overflow(-1);
}

static void random_test_align_and_overflow_basic(void)
{
	random_test_align_and_overflow(ODP_RANDOM_BASIC);
}

static void random_test_align_and_overflow_crypto(void)
{
	random_test_align_and_overflow(ODP_RANDOM_CRYPTO);
}

static void random_test_align_and_overflow_true(void)
{
	random_test_align_and_overflow(ODP_RANDOM_TRUE);
}

static void random_test_align_and_len_test(void)
{
	static const int size = 64;

	uint8_t ODP_ALIGNED_CACHE buf[size], buf_ref[size];
	const uint64_t seed_c = 123;
	uint64_t seed = seed_c;

	CU_ASSERT_FATAL(odp_random_test_data(buf_ref, size, &seed) == size);

	for (int align = 0; align < size / 2; align++) {
		for (int len = 1; len <= size / 2; len++) {
			seed = seed_c;
			CU_ASSERT_FATAL(odp_random_test_data(buf + align, len, &seed) ==
					(int32_t)len);
			CU_ASSERT(memcmp(buf + align, buf_ref, len) == 0);
		}
	}
}

/*
 * Randomness tests
 *
 * The purpose of the following tests is to check that random data looks random.
 * Some of the tests are based on [1].
 *
 * [1] Special Publication 800-22 revision 1a: A Statistical Test Suite for
 *     Random and Pseudorandom Number Generators for Cryptographic Applications
 *     National Institute of Standards and Technology (NIST), April 2010
 *     https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-22r1a.pdf
 */

/*
 * Alpha for P-value tests. This does not affect the tests that use a
 * precomputed critical value.
 */
static const double alpha = 0.00000001;

static uint32_t random_bits(int n, odp_random_kind_t kind)
{
	static uint8_t buf[32 * 1024];
	const int size = sizeof(buf);
	static int cur_n;
	static odp_random_kind_t cur_kind;
	static int bit;
	uint32_t r = 0;

	if (n != cur_n || kind != cur_kind) {
		cur_n = n;
		cur_kind = kind;
		bit = size * 8;
	}

	for (int i = 0; i < n; ) {
		if (bit >= size * 8) {
			random_data(buf, size, kind);
			bit = 0;
		}
		if (n - i >= 8 && !(bit & 7)) {
			/* Full byte. */
			r <<= 8;
			r |= buf[bit / 8];
			bit += 8;
			i += 8;
			continue;
		}
		/* Single bit. */
		r <<= 1;
		r |= (buf[bit / 8] >> (7 - (bit & 7))) & 1;
		bit++;
		i++;
	}

	return r;
}

static const char *res_str(int pass)
{
	return pass ? "pass" : "FAIL";
}

/*
 * Pearson's chi-squared goodness-of-fit test for uniform distribution. The test
 * is run with multiple different bit block lengths. The null hypothesis is that
 * each possible bit pattern is equally likely. If the chi-squared statistic is
 * equal to or larger than the critical value, we conclude that the data is
 * biased.
 */
static void random_test_frequency(odp_random_kind_t kind)
{
	/* Mean number of hits per cell. */
	const uint32_t expected = 50;

	/* From LibreOffice CHISQ.INV.RT(0.00000001; df). */
	const double critical[] = {
		32.8413, 40.1300, 50.8129, 68.0293,
		97.0285, 147.463, 237.614, 402.685,
		711.187, 1297.50, 2426.64, 4623.37,
		8929.74, 17419.3, 34224.0, 67587.1,
	};

	printf("\n\n");

	for (int bits = 1; bits <= 8; bits++) {
		const uint32_t cells = 1 << bits;
		const uint64_t num = expected * cells;
		uint64_t f[256] = { 0 };

		for (uint64_t i = 0; i < num; i++)
			f[random_bits(bits, kind)]++;

		double chisq = 0, crit = critical[bits - 1];

		for (uint64_t i = 0; i < cells; i++) {
			double dif = (double)f[i] - expected;

			chisq += dif * dif / expected;
		}

		printf("bits %d ; chisq %g ; df %u ; crit %g ; %s\n",
		       bits, chisq, cells - 1, crit, res_str(chisq < crit));

		CU_ASSERT(chisq < crit);
	}

	printf("\n");
}

static void random_test_frequency_crypto(void)
{
	random_test_frequency(ODP_RANDOM_CRYPTO);
}

static void random_test_frequency_true(void)
{
	random_test_frequency(ODP_RANDOM_TRUE);
}

/*
 * Pearson's chi-squared test for independence. The null hypothesis is that the
 * values of different bytes are independent. If the chi-squared statistic is
 * equal to or greater than the critical value, we conclude that the bytes in
 * the byte pairs selected from the data are not independent.
 */
static void random_test_independence(odp_random_kind_t kind)
{
	/* Mean number of hits per cell. */
	const uint32_t expected = 100;

	/* LibreOffice CHISQ.INV.RT(0.00000001; 255*255) */
	const double critical = 67069.2;

	printf("\n\n");
	printf("critical value: %g\n", critical);

	for (int lag = 1; lag <= 8; lag++) {
		const uint32_t cells = 256 * 256;
		const uint64_t num = expected * cells;
		const int size = 32 * 1024;
		int pos = size;
		uint8_t buf[size];
		uint64_t freq[256][256] = { { 0 } };
		uint32_t row[256] = { 0 }, col[256] = { 0 };

		for (uint64_t i = 0; i < num; i++) {
			if (pos + lag >= size) {
				random_data(buf, size, kind);
				pos = 0;
			}

			uint8_t r = buf[pos], c = buf[pos + lag];

			freq[r][c]++;
			row[r]++;
			col[c]++;
			pos++;
		}

		double chisq = 0;

		for (int i = 0; i < 256; i++) {
			for (int j = 0; j < 256; j++) {
				double expect = (double)row[i] * (double)col[j] / (double)num;
				double diff   = (double)freq[i][j] - expect;

				chisq += diff * diff / expect;
			}
		}

		printf("lag %d ; chisq %g ; %s\n",
		       lag, chisq, res_str(chisq < critical));

		CU_ASSERT(chisq < critical);
	}

	printf("\n");
}

static void random_test_independence_crypto(void)
{
	random_test_independence(ODP_RANDOM_CRYPTO);
}

/*
 * Sec. 2.3 Runs Test [1]. The test is run with several different n values. A
 * few long runs may go unnoticed if n is large, while longer period
 * non-randomness may go unnoticed if n is small.
 */
static void random_test_runs(odp_random_kind_t kind)
{
	printf("\n\n");
	printf("alpha: %g\n", alpha);

	for (int n = 128; n <= 1024 * 1024; n *= 2) {
		double pi, P_value;
		int bit = random_bits(1, kind);
		uint64_t ones = bit, V = 1;

		for (int i = 1; i < n; i++) {
			int prev_bit = bit;

			bit = random_bits(1, kind);
			ones += bit;
			V += (bit != prev_bit);
		}

		pi = (double)ones / n;

		/*
			* Skip the prerequisite frequency test (Sec. 2.3.4
			* step (2)), since it's effectively the same as
			* random_test_frequency() with bits = 1.
			*/

		P_value = erfc(fabs(V - 2 * n * pi * (1 - pi)) /
				(2 * sqrt(2 * n) * pi * (1 - pi)));
		printf("n %d ; pi %g ; V %" PRIu64 " ; P_value %g ; %s\n",
		       n, pi, V, P_value, res_str(P_value >= alpha));

		CU_ASSERT(P_value >= alpha);
	}

	printf("\n");
}

static void random_test_runs_crypto(void)
{
	random_test_runs(ODP_RANDOM_CRYPTO);
}

static void random_test_runs_true(void)
{
	random_test_runs(ODP_RANDOM_TRUE);
}

static int mx_bit(uint32_t *m, int r, int c)
{
	return (m[r] >> c) & 1;
}

static int mx_rank(uint32_t *m, int rows, int cols)
{
	int rank = 0;

	for (int r = 0, c = 0; r < rows && c < cols; ) {
		int swapped = r;

		if (!mx_bit(m, r, c)) {
			for (int sr = r + 1; sr < rows; sr++) {
				if (mx_bit(m, sr, c)) {
					uint32_t t = m[r];

					m[r] = m[sr];
					m[sr] = t;
					swapped = sr;
					break;
				}
			}
			if (!mx_bit(m, r, c)) {
				c++;
				continue;
			}
		}

		rank++;

		for (int sr = swapped + 1; sr < rows; sr++) {
			if (mx_bit(m, sr, c))
				m[sr] ^= m[r];
		}

		r++;
	}

	return rank;
}

/*
 * Sec. 2.5 Binary Matrix Rank Test [1].
 */
static void random_test_matrix_rank(odp_random_kind_t kind)
{
	const int N = 100; /* [1] recommends at least 38. */
	const double p[3] = { 0.2888, 0.5776, 0.1336 };

	printf("\n\n");
	printf("alpha: %g\n", alpha);
	printf("N: %d\n", N);

	int F[3] = { 0 };

	for (int i = 0; i < N; i++) {
		uint32_t mx[32];

		random_data((uint8_t *)mx, sizeof(mx), kind);

		switch (mx_rank(mx, 32, 32)) {
		case 32:
			F[0]++;
			break;
		case 31:
			F[1]++;
			break;
		default:
			F[2]++;
		}
	}

	double chisq, P_value;

	chisq = pow(F[0] - p[0] * N, 2) / (p[0] * N) +
		pow(F[1] - p[1] * N, 2) / (p[1] * N) +
		pow(F[2] - p[2] * N, 2) / (p[2] * N);
	P_value = exp(-chisq / 2);

	printf("P_value %g ; %s\n", P_value, res_str(P_value >= alpha));

	CU_ASSERT(P_value >= alpha);
}

static void random_test_matrix_rank_crypto(void)
{
	random_test_matrix_rank(ODP_RANDOM_CRYPTO);
}

static void random_test_matrix_rank_true(void)
{
	random_test_matrix_rank(ODP_RANDOM_TRUE);
}

static int check_kind_basic(void)
{
	return odp_random_max_kind() >= ODP_RANDOM_BASIC;
}

static int check_kind_crypto(void)
{
	return odp_random_max_kind() >= ODP_RANDOM_CRYPTO;
}

static int check_kind_true(void)
{
	return odp_random_max_kind() >= ODP_RANDOM_TRUE;
}

odp_testinfo_t random_suite[] = {
	ODP_TEST_INFO_CONDITIONAL(random_test_get_size_basic, check_kind_basic),
	ODP_TEST_INFO_CONDITIONAL(random_test_get_size_crypto, check_kind_crypto),
	ODP_TEST_INFO_CONDITIONAL(random_test_get_size_true, check_kind_true),
	ODP_TEST_INFO(random_test_kind),
	ODP_TEST_INFO(random_test_repeat),
	ODP_TEST_INFO(random_test_align_and_overflow_test),
	ODP_TEST_INFO(random_test_align_and_len_test),
	ODP_TEST_INFO_CONDITIONAL(random_test_align_and_overflow_basic, check_kind_basic),
	ODP_TEST_INFO_CONDITIONAL(random_test_align_and_overflow_crypto, check_kind_crypto),
	ODP_TEST_INFO_CONDITIONAL(random_test_align_and_overflow_true, check_kind_true),
	ODP_TEST_INFO_CONDITIONAL(random_test_frequency_crypto, check_kind_crypto),
	ODP_TEST_INFO_CONDITIONAL(random_test_frequency_true, check_kind_true),
	ODP_TEST_INFO_CONDITIONAL(random_test_independence_crypto, check_kind_crypto),
	ODP_TEST_INFO_CONDITIONAL(random_test_runs_crypto, check_kind_crypto),
	ODP_TEST_INFO_CONDITIONAL(random_test_runs_true, check_kind_true),
	ODP_TEST_INFO_CONDITIONAL(random_test_matrix_rank_crypto, check_kind_crypto),
	ODP_TEST_INFO_CONDITIONAL(random_test_matrix_rank_true, check_kind_true),
	ODP_TEST_INFO_NULL,
};

odp_suiteinfo_t random_suites[] = {
	{"Random", NULL, NULL, random_suite},
	ODP_SUITE_INFO_NULL,
};

int main(int argc, char *argv[])
{
	int ret;

	/* parse common options: */
	if (odp_cunit_parse_options(&argc, argv))
		return -1;

	ret = odp_cunit_register(random_suites);

	if (ret == 0)
		ret = odp_cunit_run();

	return ret;
}
