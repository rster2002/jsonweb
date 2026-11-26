use rand::RngCore;

/// Helper function to generate a random CEK of a given length.
pub fn random_cek(length: usize) -> Vec<u8> {
    let mut rng = rand::thread_rng();
    let mut sec = vec![0u8; length];
    rng.fill_bytes(&mut sec);

    sec
}