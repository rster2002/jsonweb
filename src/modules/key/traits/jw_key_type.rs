pub trait JwKeyType {
    fn kty() -> impl AsRef<str>;
}
