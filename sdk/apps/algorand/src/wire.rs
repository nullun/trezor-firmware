//! Hand-rolled protobuf codec for the four Algorand wire messages.
//!
//! Request decoders replace prost-generated `Message::decode` so
//! `AlgorandSignTransactions.transactions` becomes a borrowed `&[u8]`
//! view into the IPC payload buffer instead of a heap-owned `Vec<u8>`.
//! For a 16-txn group of 16 KiB application txns that drops 256 KiB of
//! duplicated payload from the app's heap.
//!
//! Response encoders replace `prost::Message::encode_to_vec` to write
//! straight into a stack-local buffer. Each signature in
//! `AlgorandTransactionSignatures` is a fixed `[u8; 64]`; the old shape
//! collected them into a `Vec<Vec<u8>>` (one heap alloc per sig, plus
//! the outer Vec, plus the encode_to_vec output) — ~18 small heap ops
//! per signing call, replaced with one stack write loop.
//!
//! Wire shape is unchanged — `protob/algorand.proto` is the
//! spec. The host still encodes via the typed builders in
//! `scripts/algorand_messages.py`, exercised end-to-end by
//! `scripts/test_*.py`.

use tiny_algo::MAX_TXN_GROUP_SIZE;
use trezor_app_sdk::{Error, Result};

/// BIP-32 paths are short — Trezor's deepest standard derivation is
/// 6 levels — and the per-coin shape (Algorand requires exactly 5) is
/// enforced at the next layer by `check_path`. The cap here just keeps
/// the decoder from accepting an unbounded number of segments from a
/// malformed payload.
const MAX_PATH_LEN: usize = 8;

#[derive(Default)]
pub struct AddressN {
    items: [u32; MAX_PATH_LEN],
    len: u8,
}

impl AddressN {
    fn push(&mut self, v: u32) -> Result<()> {
        let i = self.len as usize;
        if i >= MAX_PATH_LEN {
            return Err(Error::DataError("BIP-32 path too long"));
        }
        self.items[i] = v;
        self.len += 1;
        Ok(())
    }

    pub fn as_slice(&self) -> &[u32] {
        &self.items[..self.len as usize]
    }
}

pub struct AlgorandGetPublicKey {
    pub address_n: AddressN,
    pub show_display: bool,
}

pub struct AlgorandSignTransactions<'a> {
    pub address_n: AddressN,
    /// First chunk of transaction data (borrowed from IPC payload).
    pub transactions: &'a [u8],
    /// When present and > len(transactions), the host will send more
    /// chunks via `ContinueSignTransactions` to reach this total.
    pub total_size: Option<u32>,
    /// Bitmask of the group indices the host wants signatures for: bit `i`
    /// set means "sign member `i`". `0` (no `sign_indices` field) means
    /// "sign every member" — the common single-signer case. Selecting a
    /// subset lets the device sign only the members whose sender is
    /// (rekeyed to) this account while still seeing the whole group to
    /// verify the group ID. Indices are range-checked against
    /// `MAX_TXN_GROUP_SIZE` here and against the actual member count when
    /// signing.
    pub sign_mask: u16,
}

pub struct AlgorandContinueSignTransactions<'a> {
    pub data: &'a [u8],
}

// --- protobuf wire helpers -----------------------------------------

fn read_varint(buf: &mut &[u8]) -> Result<u64> {
    let mut value: u64 = 0;
    let mut shift: u32 = 0;
    loop {
        let &b = buf.first().ok_or(Error::InvalidMessage)?;
        *buf = &buf[1..];
        value |= ((b & 0x7f) as u64) << shift;
        if b < 0x80 {
            return Ok(value);
        }
        shift += 7;
        if shift >= 64 {
            return Err(Error::InvalidMessage);
        }
    }
}

fn read_len_delim<'a>(buf: &mut &'a [u8]) -> Result<&'a [u8]> {
    let len = read_varint(buf)? as usize;
    if buf.len() < len {
        return Err(Error::InvalidMessage);
    }
    let (head, rest) = buf.split_at(len);
    *buf = rest;
    Ok(head)
}

fn read_u32(buf: &mut &[u8]) -> Result<u32> {
    let v = read_varint(buf)?;
    if v > u32::MAX as u64 {
        return Err(Error::InvalidMessage);
    }
    Ok(v as u32)
}

/// Skip an unknown field's value — used for forward compatibility with
/// fields the host adds that this device doesn't yet know about.
fn skip_field(buf: &mut &[u8], wire_type: u32) -> Result<()> {
    match wire_type {
        // varint
        0 => {
            read_varint(buf)?;
        }
        // 64-bit fixed
        1 => {
            if buf.len() < 8 {
                return Err(Error::InvalidMessage);
            }
            *buf = &buf[8..];
        }
        // length-delimited
        2 => {
            read_len_delim(buf)?;
        }
        // 32-bit fixed
        5 => {
            if buf.len() < 4 {
                return Err(Error::InvalidMessage);
            }
            *buf = &buf[4..];
        }
        // groups (3, 4) are proto2-deprecated and not used by any Trezor
        // message; anything else is malformed.
        _ => return Err(Error::InvalidMessage),
    }
    Ok(())
}

// --- decoders ------------------------------------------------------

pub fn decode_get_public_key(input: &[u8]) -> Result<AlgorandGetPublicKey> {
    let mut buf = input;
    let mut address_n = AddressN::default();
    let mut show_display = false;
    while !buf.is_empty() {
        let tag = read_varint(&mut buf)?;
        let field = (tag >> 3) as u32;
        let wire = (tag & 0x7) as u32;
        match (field, wire) {
            // address_n (repeated uint32) — unpacked
            (1, 0) => address_n.push(read_u32(&mut buf)?)?,
            // address_n — packed (any conformant encoder may emit either)
            (1, 2) => {
                let mut inner = read_len_delim(&mut buf)?;
                while !inner.is_empty() {
                    address_n.push(read_u32(&mut inner)?)?;
                }
            }
            // show_display (optional bool)
            (2, 0) => show_display = read_varint(&mut buf)? != 0,
            _ => skip_field(&mut buf, wire)?,
        }
    }
    Ok(AlgorandGetPublicKey {
        address_n,
        show_display,
    })
}

/// Set the bit for transaction index `idx` in a sign-selection mask,
/// rejecting indices that can't name a group member (a group is at most
/// `MAX_TXN_GROUP_SIZE` transactions).
fn set_sign_bit(mask: &mut u16, idx: u32) -> Result<()> {
    if idx as usize >= MAX_TXN_GROUP_SIZE {
        return Err(Error::DataError("Sign index out of range"));
    }
    *mask |= 1u16 << idx;
    Ok(())
}

pub fn decode_sign_transactions(input: &[u8]) -> Result<AlgorandSignTransactions<'_>> {
    let mut buf = input;
    let mut address_n = AddressN::default();
    let mut transactions: Option<&[u8]> = None;
    let mut total_size: Option<u32> = None;
    let mut sign_mask: u16 = 0;
    while !buf.is_empty() {
        let tag = read_varint(&mut buf)?;
        let field = (tag >> 3) as u32;
        let wire = (tag & 0x7) as u32;
        match (field, wire) {
            (1, 0) => address_n.push(read_u32(&mut buf)?)?,
            (1, 2) => {
                let mut inner = read_len_delim(&mut buf)?;
                while !inner.is_empty() {
                    address_n.push(read_u32(&mut inner)?)?;
                }
            }
            // transactions (required bytes) — first chunk
            (2, 2) => transactions = Some(read_len_delim(&mut buf)?),
            // total_size (optional uint32) — chunked mode indicator
            (3, 0) => total_size = Some(read_u32(&mut buf)?),
            // sign_indices (repeated uint32) — unpacked
            (4, 0) => set_sign_bit(&mut sign_mask, read_u32(&mut buf)?)?,
            // sign_indices — packed (any conformant encoder may emit either)
            (4, 2) => {
                let mut inner = read_len_delim(&mut buf)?;
                while !inner.is_empty() {
                    set_sign_bit(&mut sign_mask, read_u32(&mut inner)?)?;
                }
            }
            _ => skip_field(&mut buf, wire)?,
        }
    }
    Ok(AlgorandSignTransactions {
        address_n,
        transactions: transactions.ok_or(Error::InvalidMessage)?,
        total_size,
        sign_mask,
    })
}

pub fn decode_continue_sign_transactions(
    input: &[u8],
) -> Result<AlgorandContinueSignTransactions<'_>> {
    let mut buf = input;
    let mut data: Option<&[u8]> = None;
    while !buf.is_empty() {
        let tag = read_varint(&mut buf)?;
        let field = (tag >> 3) as u32;
        let wire = (tag & 0x7) as u32;
        match (field, wire) {
            (1, 2) => data = Some(read_len_delim(&mut buf)?),
            _ => skip_field(&mut buf, wire)?,
        }
    }
    Ok(AlgorandContinueSignTransactions {
        data: data.ok_or(Error::InvalidMessage)?,
    })
}

// --- encoders ------------------------------------------------------

/// Wire size of `AlgorandPublicKey` (94 bytes):
///   (tag=0x0A)(len=32)(public_key[32]) +
///   (tag=0x12)(len=58)(address[58])
/// Both lengths fit in a single varint byte (< 128).
pub const PUBLIC_KEY_RESPONSE_LEN: usize = 1 + 1 + 32 + 1 + 1 + 58;

/// Maximum wire size of one `AlgorandTransactionSignature` record,
/// including its enclosing field-1 tag/length in the parent
/// `AlgorandTransactionSignatures`:
///   outer:  (tag=0x0A)(len)                              = 2
///   nested: (tag=0x08)(index varint, <16 ⇒ 1 byte)       = 2
///           (tag=0x12)(len=64)(signature[64])            = 66
///           (tag=0x1A)(len=32)(auth_address[32])         = 34  (optional)
/// 2 + (2 + 66 + 34) = 104. The nested length (≤102) fits one varint byte.
pub const MAX_SIGNATURE_RECORD_LEN: usize = 2 + (2 + 66 + 34);

/// Maximum signing group size — the cap that `Transactions::parse`
/// enforces, reused so the response buffer is sized from the single
/// source of truth.
pub const MAX_SIGNATURE_RECORDS: usize = MAX_TXN_GROUP_SIZE;

/// Encode an `AlgorandPublicKey` response into the caller-provided
/// buffer and return the populated prefix. `address` is the 58-byte
/// canonical Algorand address (the ASCII bytes already written by
/// `Address::encode`).
pub fn encode_public_key<'a>(
    out: &'a mut [u8; PUBLIC_KEY_RESPONSE_LEN],
    public_key: &[u8; 32],
    address: &[u8; 58],
) -> &'a [u8] {
    out[0] = 0x0A; // field 1, length-delimited
    out[1] = 32;
    out[2..34].copy_from_slice(public_key);
    out[34] = 0x12; // field 2, length-delimited
    out[35] = 58;
    out[36..94].copy_from_slice(address);
    out.as_slice()
}

/// Append one `AlgorandTransactionSignature` record to an
/// `AlgorandTransactionSignatures` buffer at `offset` and return the new
/// offset.
///
/// `index` is the position of the signed transaction in the input group
/// (so the host can map a subset of signatures back to their members).
/// `auth` carries the signer's 32-byte public key and is emitted only
/// when the signer differs from the transaction's sender — i.e. the
/// sender account is rekeyed to this key; the host copies it into the
/// `SignedTxn` `sgnr` field. When the signer *is* the sender it is
/// omitted, matching Algorand's wire convention.
///
/// Caller ensures `out.len() >= offset + MAX_SIGNATURE_RECORD_LEN`; in
/// practice the buffer is sized `MAX_SIGNATURE_RECORDS *
/// MAX_SIGNATURE_RECORD_LEN` and the call count is bounded by
/// `Transactions::parse`.
pub fn write_signature_record(
    out: &mut [u8],
    offset: usize,
    index: u32,
    sig: &[u8; 64],
    auth: Option<&[u8; 32]>,
) -> usize {
    debug_assert!(index < 0x80, "group index must fit a single-byte varint");
    let nested_len = 2 + 66 + if auth.is_some() { 34 } else { 0 };
    let mut p = offset;
    out[p] = 0x0A; // outer field 1 (signatures), length-delimited
    out[p + 1] = nested_len as u8;
    p += 2;
    out[p] = 0x08; // nested field 1 (index), varint
    out[p + 1] = index as u8;
    p += 2;
    out[p] = 0x12; // nested field 2 (signature), length-delimited
    out[p + 1] = 64;
    out[p + 2..p + 66].copy_from_slice(sig);
    p += 66;
    if let Some(a) = auth {
        out[p] = 0x1A; // nested field 3 (auth_address), length-delimited
        out[p + 1] = 32;
        out[p + 2..p + 34].copy_from_slice(a);
        p += 34;
    }
    p
}
