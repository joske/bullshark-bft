use crate::Digest;

pub trait EncodeDecodeBase64: Sized {
    fn encode_base64(&self) -> String;
    fn decode_base64(value: &str) -> Result<Self, eyre::Report>;
}

pub trait Hash {
    type TypedDigest: Into<Digest> + Eq + std::hash::Hash + Copy + std::fmt::Debug;

    fn digest(&self) -> Self::TypedDigest;
}
