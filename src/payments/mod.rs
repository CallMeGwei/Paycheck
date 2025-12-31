mod stripe;
mod lemonsqueezy;

pub use stripe::*;
pub use lemonsqueezy::*;

use strum::{AsRefStr, EnumString};

#[derive(Debug, Clone, Copy, PartialEq, Eq, AsRefStr, EnumString)]
#[strum(ascii_case_insensitive)]
pub enum PaymentProvider {
    #[strum(serialize = "stripe")]
    Stripe,
    #[strum(serialize = "lemonsqueezy", serialize = "ls")]
    LemonSqueezy,
}
