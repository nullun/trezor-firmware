use ufmt::uWrite;
use trezor_app_sdk::ui::Property;

/// Max decimal digits in a `u64` (`18446744073709551615`).
pub const U64_LEN: usize = 20;

/// Buffer length for short screen labels and titles formatted at runtime
/// (e.g. "Asset config 16 of 16", "1024 bytes").
pub const LABEL_LEN: usize = 32;

/// `uWrite` sink that writes into a caller-supplied `&mut [u8]`. Pairs
/// with `uwrite!` for stack-buffered formatting — e.g. amount/fee
/// rendering during confirm screens, where a `String` allocation per
/// field adds up across a 16-txn group review.
///
/// Caller is responsible for sizing the buffer to the maximum possible
/// output of the format string; writes past `buf.len()` return
/// `BufFull`. The `as_str()` accessor consumes only the populated
/// prefix.
pub struct BufWriter<'a> {
    buf: &'a mut [u8],
    pos: usize,
}

#[derive(Debug)]
pub struct BufFull;

impl<'a> BufWriter<'a> {
    pub fn new(buf: &'a mut [u8]) -> Self {
        Self { buf, pos: 0 }
    }

    /// Consume the writer and return a `&str` over the populated prefix
    /// of the original buffer. Takes `self` so the borrow checker can
    /// downgrade the exclusive borrow we held during writing to a
    /// shared borrow that lives as long as the caller's buffer.
    pub fn into_str(self) -> &'a str {
        // uWrite only feeds us &str chunks, so the populated prefix is
        // always valid UTF-8.
        core::str::from_utf8(&self.buf[..self.pos]).expect("uWrite emits utf-8")
    }
}

impl<'a> uWrite for BufWriter<'a> {
    type Error = BufFull;

    fn write_str(&mut self, s: &str) -> Result<(), BufFull> {
        let bytes = s.as_bytes();
        let end = self.pos.checked_add(bytes.len()).ok_or(BufFull)?;
        if end > self.buf.len() {
            return Err(BufFull);
        }
        self.buf[self.pos..end].copy_from_slice(bytes);
        self.pos = end;
        Ok(())
    }
}

/// Fixed-capacity, stack-allocated stand-in for `Vec<Property>`.
///
/// Every confirm screen's property count is small and statically bounded
/// (the largest, an application call, tops out at 16), so a growable heap
/// vector is unnecessary. Callers size `N` to the maximum they can emit;
/// pushing past `N` panics rather than allocating.
pub struct PropVec<'a, const N: usize> {
    items: [Property<'a>; N],
    len: usize,
}

impl<'a, const N: usize> PropVec<'a, N> {
    pub fn new() -> Self {
        Self {
            items: core::array::from_fn(|_| Property::new("", "", false)),
            len: 0,
        }
    }

    /// Append a property. Panics if the fixed capacity `N` is exceeded —
    /// a programming error, since `N` is sized to the screen's maximum.
    pub fn push(&mut self, p: Property<'a>) {
        self.items[self.len] = p;
        self.len += 1;
    }

    pub fn as_slice(&self) -> &[Property<'a>] {
        &self.items[..self.len]
    }
}

impl<'a, const N: usize> Default for PropVec<'a, N> {
    fn default() -> Self {
        Self::new()
    }
}

/// Format into a caller-supplied stack buffer and return a `&str` view
/// over the written prefix — the no-alloc replacement for a formatting
/// macro that returns an owned `String`.
///
/// ```ignore
/// let mut buf = [0u8; strutil::LABEL_LEN];
/// let title = uformat!(&mut buf, "Payment {} of {}", i + 1, n);
/// ```
///
/// Panics if the output does not fit `buf`; size the buffer to the format
/// string's maximum output.
#[macro_export]
macro_rules! uformat {
    ($buf:expr, $($tt:tt)*) => {{
        use trezor_app_sdk::unwrap;
        let mut w = $crate::strutil::BufWriter::new($buf);
        unwrap!(ufmt::uwrite!(&mut w, $($tt)*));
        w.into_str()
    }};
}
