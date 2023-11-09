pub trait Hasher<const N: usize> {
    fn new() -> Self;

    fn update(&mut self, data: &[u8]);

    fn finish(self) -> [u8; N];

    fn digest(data: &[u8]) -> [u8; N];
}

pub mod sha3;

#[cfg(feature = "openssl")]
pub mod openssl;
