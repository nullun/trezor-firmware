/*
 * This file is part of the Trezor project, https://trezor.io/
 *
 * Copyright (c) SatoshiLabs
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include "py/objarray.h"
#include "py/objstr.h"
#include "py/runtime.h"

#include "memzero.h"

#include "falcon/deterministic.h"
#include "falcon/falcon.h"

/// package: trezorcrypto.falcon

/*
 * Static work buffer for FALCON-DET1024 keygen and signing.
 *
 * Sized to the larger of the two requirements (signing dominates at ~80 KB).
 * Placed in the .buf linker section so it lands in AUX RAM (separate from
 * the main .bss region) on all STM32 targets.  On the emulator the section
 * attribute is omitted so the buffer falls back to ordinary BSS.
 */
#ifndef TREZOR_EMULATOR
__attribute__((section(".buf")))
#endif
static uint8_t mod_trezorcrypto_falcon_workbuf
    [FALCON_DET1024_WORKBUF_SIGN_COMPRESSED_SIZE];

/// def keygen(seed: bytes) -> tuple[bytearray, bytes]:
///     """
///     Generate a FALCON-DET1024 keypair deterministically from a 32-byte
///     seed. Uses an internal static work buffer (~80 KB).
///
///     Returns a tuple (privkey, pubkey) where privkey is a mutable
///     bytearray (so it can be securely zeroized via falcon.zeroize())
///     of FALCON_DET1024_PRIVKEY_SIZE bytes, and pubkey is bytes of
///     FALCON_DET1024_PUBKEY_SIZE bytes.
///     """
STATIC mp_obj_t mod_trezorcrypto_falcon_keygen(mp_obj_t seed) {
  mp_buffer_info_t seed_buf = {0};
  mp_get_buffer_raise(seed, &seed_buf, MP_BUFFER_READ);

  if (seed_buf.len != 32) {
    mp_raise_ValueError(MP_ERROR_TEXT("seed must be 32 bytes"));
  }

  shake256_context rng = {0};
  shake256_init_prng_from_seed(&rng, seed_buf.buf, seed_buf.len);

  // Allocate the public key in a vstr (immutable bytes on return).
  vstr_t pubkey = {0};
  vstr_init_len(&pubkey, FALCON_DET1024_PUBKEY_SIZE);

  // Allocate the private key as a mutable bytearray so the Python layer
  // can zeroize it via falcon.zeroize() once signing is complete.
  // We first zero the work buffer region we'll use as init data, then
  // pass it to mp_obj_new_bytearray (which requires non-NULL items).
  memzero(mod_trezorcrypto_falcon_workbuf, FALCON_DET1024_PRIVKEY_SIZE);
  mp_obj_array_t *privkey =
      MP_OBJ_TO_PTR(mp_obj_new_bytearray(FALCON_DET1024_PRIVKEY_SIZE,
                                          mod_trezorcrypto_falcon_workbuf));

  int r = falcon_det1024_keygen_with_workbuf(
      &rng, privkey->items, (void *)pubkey.buf, mod_trezorcrypto_falcon_workbuf,
      sizeof(mod_trezorcrypto_falcon_workbuf));

  // Zeroize the work buffer and the SHAKE context regardless of result.
  memzero(mod_trezorcrypto_falcon_workbuf,
          sizeof(mod_trezorcrypto_falcon_workbuf));
  memzero(&rng, sizeof(rng));

  if (r != 0) {
    memzero(privkey->items, FALCON_DET1024_PRIVKEY_SIZE);
    vstr_clear(&pubkey);
    mp_raise_ValueError(MP_ERROR_TEXT("FALCON keygen failed"));
  }

  mp_obj_t items[2] = {
      MP_OBJ_FROM_PTR(privkey),
      mp_obj_new_str_from_vstr(&mp_type_bytes, &pubkey),
  };
  return mp_obj_new_tuple(2, items);
}
STATIC MP_DEFINE_CONST_FUN_OBJ_1(mod_trezorcrypto_falcon_keygen_obj,
                                 mod_trezorcrypto_falcon_keygen);

/// def sign_compressed(privkey: bytes, data: bytes) -> bytes:
///     """
///     Sign data with FALCON-DET1024 in compressed format.
///     Uses an internal static work buffer (~80 KB).
///     Returns a variable-length signature (up to
///     FALCON_DET1024_SIG_COMPRESSED_MAXSIZE bytes).
///     """
STATIC mp_obj_t mod_trezorcrypto_falcon_sign_compressed(mp_obj_t privkey,
                                                        mp_obj_t data) {
  mp_buffer_info_t pk = {0}, msg = {0};
  mp_get_buffer_raise(privkey, &pk, MP_BUFFER_READ);
  mp_get_buffer_raise(data, &msg, MP_BUFFER_READ);

  if (pk.len != FALCON_DET1024_PRIVKEY_SIZE) {
    mp_raise_ValueError(MP_ERROR_TEXT("invalid FALCON private key length"));
  }
  if (msg.len == 0) {
    mp_raise_ValueError(MP_ERROR_TEXT("empty data to sign"));
  }

  vstr_t sig = {0};
  vstr_init_len(&sig, FALCON_DET1024_SIG_COMPRESSED_MAXSIZE);
  size_t sig_len = sig.len;

  int r = falcon_det1024_sign_compressed_with_workbuf(
      (void *)sig.buf, &sig_len, pk.buf, msg.buf, msg.len,
      mod_trezorcrypto_falcon_workbuf, sizeof(mod_trezorcrypto_falcon_workbuf));

  // Always zeroize the work buffer; it contains intermediate values
  // derived from the private key.
  memzero(mod_trezorcrypto_falcon_workbuf,
          sizeof(mod_trezorcrypto_falcon_workbuf));

  if (r != 0) {
    vstr_clear(&sig);
    mp_raise_ValueError(MP_ERROR_TEXT("FALCON signing failed"));
  }

  // Truncate to the actual signature length reported by the library.
  sig.len = sig_len;
  return mp_obj_new_str_from_vstr(&mp_type_bytes, &sig);
}
STATIC MP_DEFINE_CONST_FUN_OBJ_2(mod_trezorcrypto_falcon_sign_compressed_obj,
                                 mod_trezorcrypto_falcon_sign_compressed);

/// def zeroize(buf: bytearray) -> None:
///     """
///     Securely zeroize a mutable buffer (typically a FALCON private key
///     held in a bytearray). Resists compiler dead-store elimination.
///     """
STATIC mp_obj_t mod_trezorcrypto_falcon_zeroize(mp_obj_t buf) {
  mp_buffer_info_t b = {0};
  mp_get_buffer_raise(buf, &b, MP_BUFFER_RW);
  memzero(b.buf, b.len);
  return mp_const_none;
}
STATIC MP_DEFINE_CONST_FUN_OBJ_1(mod_trezorcrypto_falcon_zeroize_obj,
                                 mod_trezorcrypto_falcon_zeroize);

STATIC const mp_rom_map_elem_t mod_trezorcrypto_falcon_globals_table[] = {
    {MP_ROM_QSTR(MP_QSTR___name__), MP_ROM_QSTR(MP_QSTR_falcon)},
    {MP_ROM_QSTR(MP_QSTR_keygen),
     MP_ROM_PTR(&mod_trezorcrypto_falcon_keygen_obj)},
    {MP_ROM_QSTR(MP_QSTR_sign_compressed),
     MP_ROM_PTR(&mod_trezorcrypto_falcon_sign_compressed_obj)},
    {MP_ROM_QSTR(MP_QSTR_zeroize),
     MP_ROM_PTR(&mod_trezorcrypto_falcon_zeroize_obj)},
    {MP_ROM_QSTR(MP_QSTR_PRIVKEY_SIZE),
     MP_ROM_INT(FALCON_DET1024_PRIVKEY_SIZE)},
    {MP_ROM_QSTR(MP_QSTR_PUBKEY_SIZE), MP_ROM_INT(FALCON_DET1024_PUBKEY_SIZE)},
    {MP_ROM_QSTR(MP_QSTR_SIG_COMPRESSED_MAXSIZE),
     MP_ROM_INT(FALCON_DET1024_SIG_COMPRESSED_MAXSIZE)},
};
STATIC MP_DEFINE_CONST_DICT(mod_trezorcrypto_falcon_globals,
                            mod_trezorcrypto_falcon_globals_table);

STATIC const mp_obj_module_t mod_trezorcrypto_falcon_module = {
    .base = {&mp_type_module},
    .globals = (mp_obj_dict_t *)&mod_trezorcrypto_falcon_globals,
};
