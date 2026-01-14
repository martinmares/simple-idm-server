pub mod authorization_code;
pub mod client_credentials;
pub mod device_flow;

pub use authorization_code::{handle_authorize, handle_login, handle_token};
pub use client_credentials::{handle_client_credentials, OAuth2State};
pub use device_flow::{
    handle_device_authorization, handle_device_token, handle_device_verify,
};
