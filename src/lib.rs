mod modules;

pub use modules::token;
pub use modules::algorithm;

#[cfg(test)]
mod tests {
    use crate::algorithm::ES256Private;
    use crate::modules::key::JwkPrivateParams;

    #[test]
    fn test_es256() {
        let key = ES256Private::rand();
        let params = key.get_private_params();

        dbg!(&params);
    }
}