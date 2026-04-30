/*
 * Standalone FALCON-DET1024 known-answer-test generator.
 *
 * Drives the vendored Falcon library directly with a fixed 32-byte
 * seed and a fixed message. Emits SHA-256 fingerprints of the
 * resulting private key, public key, and compressed signature so the
 * output can be diffed across builds (e.g. host vs. ARM-with-asm).
 *
 * Build via the crypto/Makefile target `tests/test_falcon_kat`.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "falcon/falcon.h"
#include "falcon/deterministic.h"
#include "sha2.h"

static void print_hex(const char *label, const uint8_t *buf, size_t len) {
	printf("%s = ", label);
	for (size_t i = 0; i < len; i++) {
		printf("%02x", buf[i]);
	}
	printf("\n");
}

static void print_sha256(const char *label, const uint8_t *buf, size_t len) {
	uint8_t digest[SHA256_DIGEST_LENGTH];
	sha256_Raw(buf, len, digest);
	printf("%s_sha256 = ", label);
	for (size_t i = 0; i < SHA256_DIGEST_LENGTH; i++) {
		printf("%02x", digest[i]);
	}
	printf(" (len=%zu)\n", len);
}

int main(void) {
	/*
	 * Fixed seed and message — never change these without bumping the
	 * KAT version in the test harness, otherwise prior reference
	 * vectors stop being comparable.
	 */
	static const uint8_t seed[32] = {
		0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
		0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
		0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
		0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
	};
	static const uint8_t msg[32] = {
		'F', 'A', 'L', 'C', 'O', 'N', '-', 'D',
		'E', 'T', '1', '0', '2', '4', ' ', 'K',
		'A', 'T', ' ', 'v', '1', ' ', '-', ' ',
		'a', 'l', 'g', 'o', 'r', 'a', 'n', 'd',
	};

	uint8_t privkey[FALCON_DET1024_PRIVKEY_SIZE];
	uint8_t pubkey[FALCON_DET1024_PUBKEY_SIZE];
	uint8_t sig[FALCON_DET1024_SIG_COMPRESSED_MAXSIZE];
	size_t sig_len = sizeof(sig);

	/* Static work buffer — sized for signing (the larger of the two). */
	static uint8_t workbuf[FALCON_DET1024_WORKBUF_SIGN_COMPRESSED_SIZE];

	shake256_context rng;
	shake256_init_prng_from_seed(&rng, seed, sizeof(seed));

	int r = falcon_det1024_keygen_with_workbuf(
		&rng, privkey, pubkey, workbuf, sizeof(workbuf));
	if (r != 0) {
		fprintf(stderr, "falcon_det1024_keygen_with_workbuf failed: %d\n", r);
		return 1;
	}

	r = falcon_det1024_sign_compressed_with_workbuf(
		sig, &sig_len, privkey, msg, sizeof(msg),
		workbuf, sizeof(workbuf));
	if (r != 0) {
		fprintf(stderr, "falcon_det1024_sign_compressed_with_workbuf failed: %d\n", r);
		return 1;
	}

	r = falcon_det1024_verify_compressed_with_workbuf(
		sig, sig_len, pubkey, msg, sizeof(msg),
		workbuf, sizeof(workbuf));
	if (r != 0) {
		fprintf(stderr, "falcon_det1024_verify_compressed_with_workbuf failed: %d\n", r);
		return 1;
	}

	print_hex("seed", seed, sizeof(seed));
	print_hex("msg", msg, sizeof(msg));
	print_sha256("privkey", privkey, sizeof(privkey));
	print_sha256("pubkey", pubkey, sizeof(pubkey));
	print_sha256("sig", sig, sig_len);
	print_hex("sig", sig, sig_len);

	return 0;
}
