mod lemonsqueezy;
mod stripe;

pub use lemonsqueezy::*;
pub use stripe::*;

use strum::{AsRefStr, EnumString};

#[derive(Debug, Clone, Copy, PartialEq, Eq, AsRefStr, EnumString)]
#[strum(ascii_case_insensitive)]
pub enum PaymentProvider {
    #[strum(serialize = "stripe")]
    Stripe,
    #[strum(serialize = "lemonsqueezy", serialize = "ls")]
    LemonSqueezy,
}
