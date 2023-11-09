use crate::Hasher;
use openssl::{md::Md, md_ctx::MdCtx};
use paste::paste;

macro_rules! hasher_bulk_impl {
    ($(($hasher:ident, $size:literal)),*$(,)?) => {
        $(
            paste! {
                pub struct $hasher {
                    ctx: MdCtx,
                }

                pub const [<$hasher:upper _MD_SIZE>]: usize = $size;

                impl Hasher<$size> for $hasher {
                    fn new() -> Self {
                        let mut ctx = MdCtx::new().unwrap();
                        ctx.digest_init(Md::[<$hasher:lower>]()).unwrap();
                        Self { ctx }
                    }

                    fn update(&mut self, data: &[u8]) {
                        self.ctx.digest_update(data).unwrap();
                    }

                    fn finish(mut self) -> [u8; $size] {
                        let mut digest = [0; $size];
                        self.ctx.digest_final(&mut digest).unwrap();
                        digest
                    }

                    fn digest(data: &[u8]) -> [u8; $size] {
                        let mut hasher = Self::new();
                        hasher.update(data);
                        hasher.finish()
                    }
                }
            }
        )*
    };
}

hasher_bulk_impl![
    (Sha224, 28),
    (Sha256, 32),
    (Sha384, 48),
    (Sha512, 64),
    (Sha3_224, 28),
    (Sha3_256, 32),
    (Sha3_384, 48),
    (Sha3_512, 64),
];

#[cfg(test)]
mod tests {
    #[cfg(feature = "openssl")]
    mod openssl {
        use crate::{openssl::*, Hasher};
        use paste::paste;

        macro_rules! hasher_test_bulk_impl {
            ($(($hasher:ident, $expected:literal)),*$(,)?) => {
                $(
                    paste! {
                        #[test]
                        fn [<$hasher:lower>]() {
                            assert_eq!(
                                hex::encode($hasher::digest(b"abcd")),
                                $expected
                            );
                        }
                    }
                )*
            };
        }

        hasher_test_bulk_impl![
            (
                Sha224,
                "a76654d8e3550e9a2d67a0eeb6c67b220e5885eddd3fde135806e601"
            ),
            (
                Sha256,
                "88d4266fd4e6338d13b845fcf289579d209c897823b9217da3e161936f031589"
            ),
            (
                Sha384,
                "1165b3406ff0b52a3d24721f785462ca2276c9f454a116c2b2ba20171a7905ea5a026682eb659c4d5f115c363aa3c79b"
            ),
            (
                Sha512,
                "d8022f2060ad6efd297ab73dcc5355c9b214054b0d1776a136a669d26a7d3b14f73aa0d0ebff19ee333368f0164b6419a96da49e3e481753e7e96b716bdccb6f"
            ),
            (
                Sha3_224,
                "dd886b5fd8421fb3871d24e39e53967ce4fc80dd348bedbea0109c0e"
            ),
            (
                Sha3_256,
                "6f6f129471590d2c91804c812b5750cd44cbdfb7238541c451e1ea2bc0193177"
            ),
            (
                Sha3_384,
                "5af1d89732d4d10cc6e92a36756f68ecfbf7ae4d14ed4523f68fc304cccfa5b0bba01c80d0d9b67f9163a5c211cfd65b"
            ),
            (
                Sha3_512,
                "6eb7b86765bf96a8467b72401231539cbb830f6c64120954c4567272f613f1364d6a80084234fa3400d306b9f5e10c341bbdc5894d9b484a8c7deea9cbe4e265"
            ),
        ];
    }
}
