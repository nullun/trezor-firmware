//! ButtonRequest type codes.
//!
//! Mirrors the values of the firmware's `ButtonRequestType` protobuf enum
//! (`common.proto`). This app hand-rolls its wire codec and generates no
//! protobuf, so the handful of codes it needs are declared here.
//!
//! Passing a non-`None` `br_name` alongside one of these codes is what makes
//! the firmware emit a `ButtonRequest` to the host before a confirmation
//! screen, so host tooling (e.g. the device-test harness) can drive the
//! confirmation instead of waiting for a local button press.

/// Subset of `ButtonRequestType` (`common.proto`) used by this app.
#[derive(Copy, Clone)]
#[repr(i32)]
pub enum ButtonRequestType {
    /// Confirming a transaction prior to signing.
    SignTx = 8,
    /// Showing an address / public key.
    Address = 10,
}

impl From<ButtonRequestType> for i32 {
    fn from(value: ButtonRequestType) -> Self {
        value as i32
    }
}
