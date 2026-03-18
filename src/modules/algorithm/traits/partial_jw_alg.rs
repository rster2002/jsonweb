pub trait PartialJwAlg {
    fn partial_alg() -> Option<impl AsRef<str>>;
}