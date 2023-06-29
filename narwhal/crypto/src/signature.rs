use crate::{to_intent_message, CurrentNetwork, Digest, PrivateKey, PublicKey};

use eyre::eyre;
use rand::thread_rng;
use serde::{Deserialize, Serialize};
use shared_crypto::intent::IntentMessage;
use tokio::sync::{
    mpsc::{channel, Sender},
    oneshot,
};

pub type Signature = snarkvm_console::account::Signature<CurrentNetwork>;

/// Wraps a private key and provides on-demand signing through a channel.
// Note: this code is based on the fastcrypto implementation.
#[derive(Clone)]
pub struct SignatureService {
    channel: Sender<(Digest, oneshot::Sender<Signature>)>,
}

impl SignatureService {
    pub fn new(pk: PrivateKey) -> Self {
        let (tx, mut rx): (Sender<(Digest, oneshot::Sender<Signature>)>, _) = channel(100);
        tokio::spawn(async move {
            while let Some((msg, sender)) = rx.recv().await {
                let signature = Signature::new_secure(&to_intent_message(msg), &pk);
                let _ = sender.send(signature);
            }
        });

        Self { channel: tx }
    }

    pub async fn request_signature(&self, msg: Digest) -> Signature {
        let (tx, rx) = oneshot::channel();
        if let Err(e) = self.channel.send((msg, tx)).await {
            panic!("failed to send message to signature service: {e}");
        }

        rx.await
            .expect("failed to receive signature from signature service")
    }
}

// We just concatenate signatures for now. A true aggregate signature is possible with this scheme
// but this approach may be fast enough for our purposes.
#[derive(Clone, Serialize, Deserialize, Default)]
pub struct AggregateSignature(pub Vec<snarkvm_console::account::Signature<CurrentNetwork>>);

impl AggregateSignature {
    pub fn verify(&self, pks: &[PublicKey], digest: &[u8]) -> Result<(), eyre::Report> {
        if pks.len() != self.0.len() {
            return Err(eyre!(
                "number of signatures does not match number of public keys"
            ));
        }
        for (i, (pk, sig)) in pks.iter().zip(self.0.iter()).enumerate() {
            if !sig.verify_bytes(pk, digest) {
                return Err(eyre!("signature verification failed (#{i})"));
            }
        }
        Ok(())
    }
}

/// A trait for sign and verify over an intent message, instead of the message itself. See more at [struct IntentMessage].
pub trait NarwhalAuthoritySignature {
    /// Create a new signature over an intent message.
    fn new_secure<T>(value: &IntentMessage<T>, secret: &PrivateKey) -> Self
    where
        T: Serialize;

    /// Verify the signature on an intent message against the public key.
    fn verify_secure<T>(&self, value: &IntentMessage<T>, author: &PublicKey) -> bool
    where
        T: Serialize;
}

impl NarwhalAuthoritySignature for Signature {
    fn new_secure<T>(value: &IntentMessage<T>, secret: &PrivateKey) -> Self
    where
        T: Serialize,
    {
        let message = bcs::to_bytes(&value).expect("Message serialization should not fail");
        // TODO(nkls): can we do better with the rng here?
        // Note: fastcrypto also uses infallible signing in their impl of the signature
        // service.
        secret
            .sign_bytes(message.as_slice(), &mut rand::thread_rng())
            .expect("Signing failed")
    }

    fn verify_secure<T>(&self, value: &IntentMessage<T>, public_key: &PublicKey) -> bool
    where
        T: Serialize,
    {
        let message = bcs::to_bytes(&value).expect("Message serialization should not fail");
        self.verify_bytes(public_key, message.as_slice())
    }
}

pub trait NarwhalAuthorityAggregateSignature {
    fn verify_secure<T>(
        &self,
        value: &IntentMessage<T>,
        pks: &[PublicKey],
    ) -> Result<(), eyre::Report>
    where
        T: Serialize;
}

impl NarwhalAuthorityAggregateSignature for AggregateSignature {
    fn verify_secure<T>(
        &self,
        value: &IntentMessage<T>,
        pks: &[PublicKey],
    ) -> Result<(), eyre::Report>
    where
        T: Serialize,
    {
        let message = bcs::to_bytes(&value).expect("Message serialization should not fail");
        self.verify(pks, message.as_slice())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::KeyPair;
    use base64ct::{Base64, Encoding};
    use snarkvm_console::prelude::ToBytes;

    #[tokio::test]
    async fn test_signature_service() {
        let pk = PrivateKey::default();
        let signature_service = SignatureService::new(pk);
        let sig = signature_service
            .request_signature(Digest::new([0u8; 32]))
            .await;
        let _b64 = Base64::encode_string(&sig.to_bytes_le().unwrap());
    }

    #[tokio::test]
    async fn test_aggregate_signature() {
        let mut v = Vec::new();
        let mut pks = Vec::new();
        let digest = Digest::new([1u8; 32]);
        let rng = &mut thread_rng();
        for _ in 0..10 {
            let kp = KeyPair::new(rng).unwrap();
            let pk = kp.private();
            let signature_service = SignatureService::new(*pk);
            let sig = signature_service.request_signature(digest).await;
            v.push(sig);
            pks.push(kp.public().clone());
        }
        let agg_sig = AggregateSignature(v);
        let _ = agg_sig.verify_secure(&to_intent_message(digest), pks.as_slice());
    }
}
