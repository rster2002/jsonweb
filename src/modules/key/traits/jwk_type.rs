pub trait JwkType {
    fn kty() -> impl AsRef<str>;
}