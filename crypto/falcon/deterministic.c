#include <stdint.h>
#include <string.h>

#include "falcon.h"
#include "inner.h"
#include "deterministic.h"

static int falcon_det1024_require_workbuf(void *workbuf, size_t workbuf_len,
	size_t need) {
	if (need > 0 && workbuf == NULL) {
		return FALCON_ERR_BADARG;
	}
	if (workbuf_len < need) {
		return FALCON_ERR_SIZE;
	}
	return 0;
}

static void *falcon_det1024_align_ptr(void *ptr, size_t align) {
	uintptr_t p;

	p = (uintptr_t)ptr;
	p = (p + align - 1) & ~(uintptr_t)(align - 1);
	return (void *)p;
}

int falcon_det1024_keygen_with_workbuf(shake256_context *rng, void *privkey,
	void *pubkey, void *workbuf, size_t workbuf_len) {
	int r;

	r = falcon_det1024_require_workbuf(workbuf, workbuf_len,
		FALCON_DET1024_WORKBUF_KEYGEN_SIZE);
	if (r != 0) {
		return r;
	}
	return falcon_keygen_make(rng, FALCON_DET1024_LOGN,
		privkey, FALCON_DET1024_PRIVKEY_SIZE,
		pubkey, FALCON_DET1024_PUBKEY_SIZE,
		workbuf, FALCON_TMPSIZE_KEYGEN(FALCON_DET1024_LOGN));
}

int falcon_det1024_keygen(shake256_context *rng, void *privkey, void *pubkey) {
	uint8_t workbuf[FALCON_DET1024_WORKBUF_KEYGEN_SIZE];

	return falcon_det1024_keygen_with_workbuf(rng, privkey, pubkey,
		workbuf, sizeof workbuf);
}

// Domain separator used to construct the fixed versioned salt string.
uint8_t falcon_det1024_salt_rest[38] = {"FALCON_DET"};

// Construct the fixed salt for a given version.
void falcon_det1024_write_salt(uint8_t dst[40], uint8_t salt_version) {
	dst[0] = salt_version;
	dst[1] = FALCON_DET1024_LOGN;
	memcpy(dst + 2, falcon_det1024_salt_rest, 38);
}

int falcon_det1024_sign_compressed_with_workbuf(void *sig, size_t *sig_len,
	const void *privkey, const void *data, size_t data_len, void *workbuf,
	size_t workbuf_len) {
	shake256_context detrng;
	shake256_context hd;
	uint8_t *tmpsd;
	uint8_t logn[1] = {FALCON_DET1024_LOGN};
	uint8_t salt[40];
	uint8_t *saltedsig;
	size_t saltedsig_len;
	int r;

	r = falcon_det1024_require_workbuf(workbuf, workbuf_len,
		FALCON_DET1024_WORKBUF_SIGN_COMPRESSED_SIZE);
	if (r != 0) {
		return r;
	}

	tmpsd = workbuf;
	saltedsig = tmpsd + FALCON_TMPSIZE_SIGNDYN(FALCON_DET1024_LOGN);
	saltedsig_len = FALCON_DET1024_SALTED_SIG_COMPRESSED_MAXSIZE;

	if (falcon_get_logn(privkey, FALCON_DET1024_PRIVKEY_SIZE)
		!= FALCON_DET1024_LOGN)
	{
		return FALCON_ERR_FORMAT;
	}

	// SHAKE(logn || privkey || data), set to output mode.
	shake256_init(&detrng);
	shake256_inject(&detrng, logn, 1);
	shake256_inject(&detrng, privkey, FALCON_DET1024_PRIVKEY_SIZE);
	shake256_inject(&detrng, data, data_len);
	shake256_flip(&detrng);

	falcon_det1024_write_salt(salt, FALCON_DET1024_CURRENT_SALT_VERSION);

	// SHAKE(salt || data), still in input mode.
	shake256_init(&hd);
	shake256_inject(&hd, salt, 40);
	shake256_inject(&hd, data, data_len);

	r = falcon_sign_dyn_finish(&detrng, saltedsig, &saltedsig_len,
		FALCON_SIG_COMPRESSED, privkey, FALCON_DET1024_PRIVKEY_SIZE,
		&hd, salt, tmpsd, FALCON_TMPSIZE_SIGNDYN(FALCON_DET1024_LOGN));
	if (r != 0) {
		return r;
	}

	// Transform the salted signature to unsalted format.
	((uint8_t *)sig)[0] = saltedsig[0] | 0x80;
	((uint8_t *)sig)[1] = FALCON_DET1024_CURRENT_SALT_VERSION;
	memcpy((uint8_t *)sig + 2, saltedsig + 41, saltedsig_len - 41);

	*sig_len = saltedsig_len - 40 + 1;
	return 0;
}

int falcon_det1024_sign_compressed(void *sig, size_t *sig_len,
	const void *privkey, const void *data, size_t data_len) {
	uint8_t workbuf[FALCON_DET1024_WORKBUF_SIGN_COMPRESSED_SIZE];

	return falcon_det1024_sign_compressed_with_workbuf(sig, sig_len,
		privkey, data, data_len, workbuf, sizeof workbuf);
}

int falcon_det1024_convert_compressed_to_ct_with_workbuf(void *sig_ct,
	const void *sig_compressed, size_t sig_compressed_len, void *workbuf,
	size_t workbuf_len) {
	int16_t *coeffs;
	size_t v;
	int r;

	r = falcon_det1024_require_workbuf(workbuf, workbuf_len,
		FALCON_DET1024_WORKBUF_CONVERT_TO_CT_SIZE);
	if (r != 0) {
		return r;
	}
	coeffs = falcon_det1024_align_ptr(workbuf, sizeof *coeffs);

	if (((const uint8_t *)sig_compressed)[0] != FALCON_DET1024_SIG_COMPRESSED_HEADER) {
		return FALCON_ERR_BADSIG;
	}

	// Decode signature's s_bytes into 1024 signed-integer coefficients.
	v = Zf(comp_decode)(coeffs, FALCON_DET1024_LOGN,
		(const uint8_t *)sig_compressed + 2, sig_compressed_len - 2);
	if (v == 0) {
		return FALCON_ERR_SIZE;
	}

	((uint8_t *)sig_ct)[0] = FALCON_DET1024_SIG_CT_HEADER;
	((uint8_t *)sig_ct)[1] = ((const uint8_t *)sig_compressed)[1];

	// Encode the signed-integer coefficients into CT format.
	v = Zf(trim_i16_encode)((uint8_t *)sig_ct + 2,
		FALCON_DET1024_SIG_CT_SIZE - 2, coeffs, FALCON_DET1024_LOGN,
		Zf(max_sig_bits)[FALCON_DET1024_LOGN]);
	if (v == 0) {
		return FALCON_ERR_SIZE;
	}

	return 0;
}

int falcon_det1024_convert_compressed_to_ct(void *sig_ct,
	const void *sig_compressed, size_t sig_compressed_len) {
	uint8_t workbuf[FALCON_DET1024_WORKBUF_CONVERT_TO_CT_SIZE];

	return falcon_det1024_convert_compressed_to_ct_with_workbuf(sig_ct,
		sig_compressed, sig_compressed_len, workbuf, sizeof workbuf);
}

// Construct the corresponding salted signature from an unsalted one.
void falcon_det1024_resalt(uint8_t *salted_sig,
	const uint8_t *unsalted_sig, size_t unsalted_sig_len) {
	salted_sig[0] = unsalted_sig[0] & ~0x80; // Reset MSB to 0.
	falcon_det1024_write_salt(salted_sig + 1, unsalted_sig[1]);
	memcpy(salted_sig + 41, unsalted_sig + 2, unsalted_sig_len - 2);
}

int falcon_det1024_verify_compressed_with_workbuf(const void *sig,
	size_t sig_len, const void *pubkey, const void *data, size_t data_len,
	void *workbuf, size_t workbuf_len) {
	uint8_t *tmpvv;
	uint8_t *salted_sig;
	size_t salted_sig_len;
	int r;

	r = falcon_det1024_require_workbuf(workbuf, workbuf_len,
		FALCON_DET1024_WORKBUF_VERIFY_COMPRESSED_SIZE);
	if (r != 0) {
		return r;
	}

	tmpvv = workbuf;
	salted_sig = tmpvv + FALCON_TMPSIZE_VERIFY(FALCON_DET1024_LOGN);

	if (sig_len < 2) {
		return FALCON_ERR_BADSIG;
	}
	if (((const uint8_t *)sig)[0] != FALCON_DET1024_SIG_COMPRESSED_HEADER) {
		return FALCON_ERR_BADSIG;
	}

	// Add back the salt; drop the version byte.
	salted_sig_len = sig_len + 40 - 1;
	if (salted_sig_len > FALCON_DET1024_SALTED_SIG_COMPRESSED_MAXSIZE) {
		return FALCON_ERR_BADSIG;
	}

	falcon_det1024_resalt(salted_sig, sig, sig_len);
	return falcon_verify(salted_sig, salted_sig_len, FALCON_SIG_COMPRESSED,
		pubkey, FALCON_DET1024_PUBKEY_SIZE, data, data_len,
		tmpvv, FALCON_TMPSIZE_VERIFY(FALCON_DET1024_LOGN));
}

int falcon_det1024_verify_compressed(const void *sig, size_t sig_len,
	const void *pubkey, const void *data, size_t data_len) {
	uint8_t workbuf[FALCON_DET1024_WORKBUF_VERIFY_COMPRESSED_SIZE];

	return falcon_det1024_verify_compressed_with_workbuf(sig, sig_len,
		pubkey, data, data_len, workbuf, sizeof workbuf);
}

int falcon_det1024_verify_ct_with_workbuf(const void *sig,
	const void *pubkey, const void *data, size_t data_len, void *workbuf,
	size_t workbuf_len) {
	uint8_t *tmpvv;
	uint8_t *salted_sig;
	int r;

	r = falcon_det1024_require_workbuf(workbuf, workbuf_len,
		FALCON_DET1024_WORKBUF_VERIFY_CT_SIZE);
	if (r != 0) {
		return r;
	}

	tmpvv = workbuf;
	salted_sig = tmpvv + FALCON_TMPSIZE_VERIFY(FALCON_DET1024_LOGN);

	if (((const uint8_t *)sig)[0] != FALCON_DET1024_SIG_CT_HEADER) {
		return FALCON_ERR_BADSIG;
	}

	falcon_det1024_resalt(salted_sig, sig, FALCON_DET1024_SIG_CT_SIZE);
	return falcon_verify(salted_sig, FALCON_DET1024_SALTED_SIG_CT_SIZE,
		FALCON_SIG_CT, pubkey, FALCON_DET1024_PUBKEY_SIZE, data, data_len,
		tmpvv, FALCON_TMPSIZE_VERIFY(FALCON_DET1024_LOGN));
}

int falcon_det1024_verify_ct(const void *sig, const void *pubkey,
	const void *data, size_t data_len) {
	uint8_t workbuf[FALCON_DET1024_WORKBUF_VERIFY_CT_SIZE];

	return falcon_det1024_verify_ct_with_workbuf(sig, pubkey, data, data_len,
		workbuf, sizeof workbuf);
}

int falcon_det1024_get_salt_version(const void *sig) {
	return ((const uint8_t *)sig)[1];
}

#define Q     12289

int falcon_det1024_pubkey_coeffs(uint16_t *h, const void *pubkey) {
	if (Zf(modq_decode)(h, FALCON_DET1024_LOGN, (const uint8_t *)pubkey + 1,
		FALCON_DET1024_PUBKEY_SIZE - 1) != FALCON_DET1024_PUBKEY_SIZE - 1)
	{
		return FALCON_ERR_FORMAT;
	}
	return 0;
}

int falcon_det1024_hash_to_point_coeffs_with_workbuf(uint16_t *c,
	const void *data, size_t data_len, uint8_t salt_version, void *workbuf,
	size_t workbuf_len) {
	uint8_t salt[40];
	shake256_context ctx;
	int r;

	r = falcon_det1024_require_workbuf(workbuf, workbuf_len,
		FALCON_DET1024_WORKBUF_HASH_TO_POINT_SIZE);
	if (r != 0) {
		return r;
	}

	falcon_det1024_write_salt(salt, salt_version);
	shake256_init(&ctx);
	shake256_inject(&ctx, salt, 40);
	shake256_inject(&ctx, data, data_len);
	shake256_flip(&ctx);

	Zf(hash_to_point_ct)((inner_shake256_context *)&ctx, c,
		FALCON_DET1024_LOGN, workbuf);
	return 0;
}

void falcon_det1024_hash_to_point_coeffs(uint16_t *c, const void *data,
	size_t data_len, uint8_t salt_version) {
	uint8_t workbuf[FALCON_DET1024_WORKBUF_HASH_TO_POINT_SIZE];

	(void)falcon_det1024_hash_to_point_coeffs_with_workbuf(c, data, data_len,
		salt_version, workbuf, sizeof workbuf);
}

int falcon_det1024_s2_coeffs(int16_t *s2, const void *sig) {
	unsigned logn;
	size_t v;

	logn = FALCON_DET1024_LOGN;
	if (((const uint8_t *)sig)[0] != FALCON_DET1024_SIG_CT_HEADER) {
		return FALCON_ERR_FORMAT;
	}

	v = Zf(trim_i16_decode)(s2, logn, Zf(max_sig_bits)[logn],
		(const uint8_t *)sig + 2, FALCON_DET1024_SIG_CT_SIZE - 2);
	if (v != FALCON_DET1024_SIG_CT_SIZE - 2) {
		return FALCON_ERR_FORMAT;
	}
	return 0;
}

int falcon_det1024_s1_coeffs_with_workbuf(int16_t *s1, const uint16_t *h,
	const uint16_t *c, const int16_t *s2, void *workbuf, size_t workbuf_len) {
	unsigned logn;
	size_t u, n;
	uint16_t *h_ntt;
	uint16_t *tt;
	int vv;
	int r;

	r = falcon_det1024_require_workbuf(workbuf, workbuf_len,
		FALCON_DET1024_WORKBUF_S1COEFFS_SIZE);
	if (r != 0) {
		return r;
	}

	logn = FALCON_DET1024_LOGN;
	n = (size_t)1 << logn;
	h_ntt = falcon_det1024_align_ptr(workbuf, sizeof *h_ntt);
	tt = h_ntt + n;

	for (u = 0; u < n; u++) {
		h_ntt[u] = h[u];
	}
	Zf(to_ntt_monty)(h_ntt, logn);

	// Copied from verify_raw.
	for (u = 0; u < n; u++) {
		uint32_t w;

		w = (uint32_t)s2[u];
		w += Q & -(w >> 31);
		tt[u] = (uint16_t)w;
	}

	/*
	 * Compute s1 = c - s2*h mod phi mod q (in tt[]).
	 */
	Zf(mq_NTT)(tt, logn); // tt = s2
	Zf(mq_poly_montymul_ntt)(tt, h_ntt, logn); // tt = s2*h
	Zf(mq_iNTT)(tt, logn);
	for (u = 0; u < n; u++) {
		tt[u] = (uint16_t)Zf(mq_sub)(c[u], tt[u]);
	}

	/*
	 * Normalize s1 elements into the [-q/2..q/2] range.
	 */
	for (u = 0; u < n; u++) {
		int32_t w;

		w = (int32_t)tt[u];
		w -= (int32_t)(Q & -(((Q >> 1) - (uint32_t)w) >> 31));
		s1[u] = (int16_t)w;
	}

	/*
	 * Test if the aggregate (s1,s2) vector is short enough.
	 */
	vv = Zf(is_short)(s1, s2, logn);
	if (vv != 1) {
		return FALCON_ERR_BADSIG;
	}
	return 0;
}

int falcon_det1024_s1_coeffs(int16_t *s1, const uint16_t *h,
	const uint16_t *c, const int16_t *s2) {
	uint8_t workbuf[FALCON_DET1024_WORKBUF_S1COEFFS_SIZE];

	return falcon_det1024_s1_coeffs_with_workbuf(s1, h, c, s2,
		workbuf, sizeof workbuf);
}
