// Copyright (c) 2022 Espresso Systems (espressosys.com)
// This file is part of the Commit library.

// You should have received a copy of the MIT License
// along with the Commit library. If not, see <https://mit-license.org/>.

use arbitrary::{Arbitrary, Unstructured};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize, Read, SerializationError, Write};
use bitvec::vec::BitVec;
use core::marker::PhantomData;
use derivative::Derivative;
use generic_array::{ArrayLength, GenericArray};
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use sha3::digest::Digest;
use sha3::Keccak256;
use std::convert::{TryFrom, TryInto};
use std::fmt::Debug;
use std::hash::Hash;

type Array = [u8; 32];

const INVALID_UTF8: [u8; 2] = [0xC0u8, 0x7Fu8];

#[cfg(test)]
mod tests {
    use super::INVALID_UTF8;
    use quickcheck_macros::quickcheck;

    #[quickcheck]
    fn invalid_utf8_is_invalid(pref: Vec<u8>, suff: Vec<u8>) {
        let s = pref
            .into_iter()
            .chain(INVALID_UTF8.iter().cloned())
            .chain(suff.into_iter())
            .collect::<Vec<_>>();
        assert!(std::str::from_utf8(&s).is_err());
    }

    #[quickcheck]
    fn invalid_utf8_is_invalid_strs_only(pref: String, suff: String) {
        let s = pref
            .as_bytes()
            .iter()
            .chain(INVALID_UTF8.iter())
            .chain(suff.as_bytes().iter())
            .cloned()
            .collect::<Vec<_>>();
        assert!(std::str::from_utf8(&s).is_err());
    }
}

pub trait Committable {
    type Commitment: Clone
        + Copy
        + Debug
        + Hash
        + PartialEq
        + Eq
        + AsRef<[u8]>
        + Serialize
        + DeserializeOwned
        + Send
        + Sync;
    fn commit(&self) -> Self::Commitment;
}

pub type Commitment<T> = <T as Committable>::Commitment;

#[derive(Derivative, Serialize, Deserialize)]
#[derivative(
    Debug(bound = ""),
    Clone(bound = ""),
    Copy(bound = ""),
    PartialEq(bound = ""),
    Eq(bound = ""),
    Hash(bound = "")
)]
#[serde(bound = "")]
pub struct HashCommitment<T: ?Sized + Committable>(Array, PhantomData<fn(T) -> ()>);

impl<T: ?Sized + Committable> AsRef<[u8]> for HashCommitment<T> {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl<T: ?Sized + Committable> HashCommitment<T> {
    pub fn into_bits(self) -> BitVec<bitvec::order::Lsb0, u8> {
        BitVec::try_from(self.0.to_vec()).unwrap()
    }
}

impl<T: ?Sized + Committable> CanonicalSerialize for HashCommitment<T> {
    fn serialize<W: Write>(&self, mut w: W) -> Result<(), SerializationError> {
        w.write_all(&self.0).map_err(SerializationError::from)
    }

    fn serialized_size(&self) -> usize {
        self.0.len()
    }
}

impl<T: ?Sized + Committable> CanonicalDeserialize for HashCommitment<T> {
    fn deserialize<R: Read>(mut r: R) -> Result<Self, SerializationError> {
        let mut buf = [0u8; 32];
        r.read_exact(&mut buf)?;
        Ok(HashCommitment(buf, Default::default()))
    }
}

impl<T: ?Sized + Committable> From<HashCommitment<T>> for [u8; 32] {
    fn from(v: HashCommitment<T>) -> Self {
        v.0
    }
}

impl<'a, T: ?Sized + Committable> Arbitrary<'a> for HashCommitment<T> {
    fn arbitrary(u: &mut Unstructured<'a>) -> arbitrary::Result<Self> {
        Ok(Self(u.arbitrary()?, PhantomData::default()))
    }
}

pub struct RawCommitmentBuilder<T: Committable> {
    hasher: Keccak256,
    _marker: PhantomData<T>,
}

impl<T: Committable> RawCommitmentBuilder<T> {
    pub fn new(tag: &str) -> Self {
        Self {
            hasher: Default::default(),
            _marker: Default::default(),
        }
        .constant_str(tag)
    }

    pub fn constant_str(mut self, s: &str) -> Self {
        self.hasher.update(s.as_bytes());
        self.fixed_size_bytes(&INVALID_UTF8)
    }

    pub fn fixed_size_bytes<const N: usize>(mut self, f: &[u8; N]) -> Self {
        self.hasher.update(f);
        self
    }

    #[allow(dead_code)]
    pub fn generic_byte_array<N: ArrayLength<u8>>(mut self, f: &GenericArray<u8, N>) -> Self {
        self.hasher.update(f);
        self
    }

    pub fn u64(self, val: u64) -> Self {
        self.fixed_size_bytes(&val.to_le_bytes())
    }

    pub fn var_size_bytes(self, f: &[u8]) -> Self {
        let mut ret = self.u64(f.len() as u64);
        ret.hasher.update(f);
        ret
    }

    #[allow(dead_code)]
    pub fn fixed_size_field<const N: usize>(self, name: &str, val: &[u8; N]) -> Self {
        self.constant_str(name).fixed_size_bytes(val)
    }

    pub fn var_size_field(self, name: &str, val: &[u8]) -> Self {
        self.constant_str(name).var_size_bytes(val)
    }

    pub fn field<C: AsRef<[u8]>>(self, name: &str, val: C) -> Self {
        self.constant_str(name).var_size_bytes(val.as_ref())
    }

    pub fn u64_field(self, name: &str, val: u64) -> Self {
        self.constant_str(name).u64(val)
    }

    pub fn array_field<C: AsRef<[u8]>>(self, name: &str, val: &[C]) -> Self {
        let mut ret = self.constant_str(name).u64(val.len() as u64);
        for v in val.iter() {
            ret = ret.var_size_bytes(v.as_ref());
        }
        ret
    }

    pub fn finalize(self) -> HashCommitment<T> {
        let ret = self.hasher.finalize();
        HashCommitment(ret.try_into().unwrap(), Default::default())
    }
}
