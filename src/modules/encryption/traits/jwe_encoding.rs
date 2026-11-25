pub trait JweEncoding {
    const ENC: &'static str;
    const CEK_LENGTH: usize;
}