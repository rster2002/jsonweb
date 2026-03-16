pub trait JwAlg {
    fn alg() -> impl AsRef<str>;
}