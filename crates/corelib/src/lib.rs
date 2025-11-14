pub mod types {
    //! Common types used across Provenix
}

pub mod utils {
    //! Utility functions
}

pub mod error {
    //! Error types and handling
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn it_works() {
        let result = add(2, 2);
        assert_eq!(result, 4);
    }
}
