//! signed-relay-lite library crate root.
//!
//! All public modules will be declared here.

pub mod dkim;
pub mod relay;

#[cfg(test)]
mod tests {
    #[test]
    fn it_works() {
        assert_eq!(2 + 2, 4);
    }
}
