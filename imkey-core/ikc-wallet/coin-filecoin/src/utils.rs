use blake2b_rs::Blake2bBuilder;
use cid::Cid;
use fvm_ipld_encoding::Error;
use multihash_codetable::{Code, MultihashDigest};

pub enum HashSize {
    Checksum = 4,
    Payload = 20,
    Default = 32,
}

pub fn digest(ingest: &[u8], hash_size: HashSize) -> Vec<u8> {
    //allocate max length byte
    let mut result = [0u8; 32];

    let size = hash_size as usize;
    let mut hasher = Blake2bBuilder::new(size).build();
    hasher.update(ingest);
    hasher.finalize(&mut result);
    result[0..size].to_vec()
}

/// Extension methods for constructing `dag-cbor` [Cid]
pub trait CidCborExt {
    /// Default CID builder for Filecoin
    ///
    /// - The default codec is [`fvm_ipld_encoding::DAG_CBOR`]
    /// - The default hash function is 256 bit BLAKE2b
    ///
    /// This matches [`abi.CidBuilder`](https://github.com/filecoin-project/go-state-types/blob/master/abi/cid.go#L49) in go
    fn from_cbor_blake2b256<S: serde::ser::Serialize>(obj: &S) -> Result<Cid, Error> {
        let bytes = fvm_ipld_encoding::to_vec(obj)?;
        Ok(Cid::new_v1(
            fvm_ipld_encoding::DAG_CBOR,
            Code::Blake2b256.digest(&bytes),
        ))
    }
}

impl CidCborExt for Cid {}
#[cfg(test)]
mod tests {
    use crate::utils::{digest, HashSize};

    #[test]
    fn test_digest() {
        let payload = [1u8, 2];

        assert_eq!(
            digest(&payload, HashSize::Checksum),
            vec![219, 55, 214, 157]
        );
    }
}
