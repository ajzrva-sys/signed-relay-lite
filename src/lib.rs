//! signed-relay-lite library crate root.
//!
//! All public modules will be declared here.

pub mod config;
pub mod dkim;
pub mod message;
pub mod relay;
pub mod wire_normalizer;

#[cfg(test)]
mod tests {
    #[test]
    fn it_works() {
        assert_eq!(2 + 2, 4);
    }
}
