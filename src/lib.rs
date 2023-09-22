// Copyright (c) 2022 Espresso Systems (espressosys.com)
// This file is part of the Commit library.

// You should have received a copy of the MIT License
// along with the Commit library. If not, see <https://mit-license.org/>.

use arbitrary::{Arbitrary, Unstructured};
use bitvec::vec::BitVec;
use core::marker::PhantomData;
use derivative::Derivative;
use derive_more::{AsRef, Into};
use generic_array::{ArrayLength, GenericArray};
use sha3::digest::Digest;
use sha3::Keccak256;
use std::{
    convert::{TryFrom, TryInto},
    fmt::Debug,
    hash::Hash,
};

#[cfg(feature = "ark-serialize")]
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize, Read, SerializationError, Write};
#[cfg(feature = "ark-serialize")]
use core::fmt::{self, Display, Formatter};
#[cfg(feature = "ark-serialize")]
use core::str::FromStr;
#[cfg(feature = "ark-serialize")]
use tagged_base64::{Tagged, TaggedBase64, Tb64Error};

#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

type Array = [u8; 32];

const INVALID_UTF8: [u8; 2] = [0xC0u8, 0x7Fu8];

#[cfg(test)]
mod test_quickcheck {
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
    /// Create a binding commitment to `self`.
    fn commit(&self) -> Commitment<Self>;

    /// Tag that should be used when serializing commitments to this type.
    ///
    /// If not provided, a generic "COMMIT" tag will be used.
    fn tag() -> String {
        "COMMIT".to_string()
    }
}

#[derive(Derivative, AsRef, Into)]
#[derivative(
    Copy(bound = ""),
    Debug(bound = ""),
    PartialEq(bound = ""),
    Eq(bound = ""),
    PartialOrd(bound = ""),
    Ord(bound = ""),
    Hash(bound = "")
)]
#[cfg_attr(feature = "serde", derive(Deserialize, Serialize))]
#[cfg_attr(
    feature = "serde",
    serde(bound = "", try_from = "TaggedBase64", into = "TaggedBase64")
)]
pub struct Commitment<T: ?Sized + Committable>(Array, PhantomData<fn(&T)>);

/// Consolidate trait bounds for cryptographic commitments.
///
pub trait CommitmentBounds:
    AsRef<[u8]> + Clone + Copy + Debug + for<'a> Deserialize<'a> + Eq + PartialEq + Serialize + Hash
{
    /// Create a default commitment with no preimage.
    ///
    /// # Alternative to [`Default`]
    ///
    /// [`Commitment`] does not impl [`Default`] so as to prevent users from
    /// accidentally creating a commitment that has no preimage. Sometimes,
    /// however, such a commitment is needed so we provide this convenience
    /// method. Even without this method, we cannot stop users from creating
    /// such a commitment using [`Deserialize`] or `From<TaggedBase64>`.
    fn default_commitment_no_preimage() -> Self;
}

impl<T> CommitmentBounds for T
where
    T: AsRef<[u8]>
        + Clone
        + Copy
        + Debug
        + Default // additional bound beyond CommitmentBounds
        + for<'a> Deserialize<'a>
        + Eq
        + PartialEq
        + Serialize
        + Hash,
{
    fn default_commitment_no_preimage() -> Self {
        Self::default()
    }
}

// `Commitment<T>` needs its own impl because it's not `Default`
impl<T> CommitmentBounds for Commitment<T>
where
    T: Committable,
{
    fn default_commitment_no_preimage() -> Self {
        Commitment([0u8; 32], PhantomData)
    }
}

impl<T: ?Sized + Committable> Commitment<T> {
    pub fn into_bits(self) -> BitVec<u8, bitvec::order::Lsb0> {
        BitVec::try_from(self.0.to_vec()).unwrap()
    }
}

// clippy pacification: `non_canonical_clone_impl` aka `incorrect_clone_impl_on_copy_type`
impl<T: ?Sized + Committable> Clone for Commitment<T> {
    fn clone(&self) -> Self {
        *self
    }
}

impl<T: ?Sized + Committable> AsRef<[u8]> for Commitment<T> {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

#[cfg(feature = "ark-serialize")]
impl<T: ?Sized + Committable> CanonicalSerialize for Commitment<T> {
    fn serialize<W: Write>(&self, mut w: W) -> Result<(), SerializationError> {
        w.write_all(&self.0).map_err(SerializationError::from)
    }

    fn serialized_size(&self) -> usize {
        self.0.len()
    }
}

#[cfg(feature = "ark-serialize")]
impl<T: ?Sized + Committable> CanonicalDeserialize for Commitment<T> {
    fn deserialize<R: Read>(mut r: R) -> Result<Self, SerializationError> {
        let mut buf = [0u8; 32];
        r.read_exact(&mut buf)?;
        Ok(Commitment(buf, Default::default()))
    }
}

impl<T: ?Sized + Committable> From<Commitment<T>> for [u8; 32] {
    fn from(v: Commitment<T>) -> Self {
        v.0
    }
}

impl<'a, T: ?Sized + Committable> Arbitrary<'a> for Commitment<T> {
    fn arbitrary(u: &mut Unstructured<'a>) -> arbitrary::Result<Self> {
        Ok(Self(u.arbitrary()?, PhantomData))
    }
}

#[cfg(feature = "ark-serialize")]
impl<T: ?Sized + Committable> Tagged for Commitment<T> {
    fn tag() -> String {
        T::tag()
    }
}

#[cfg(feature = "ark-serialize")]
impl<T: ?Sized + Committable> TryFrom<TaggedBase64> for Commitment<T> {
    type Error = Tb64Error;
    fn try_from(v: TaggedBase64) -> Result<Self, Self::Error> {
        Self::try_from(&v)
    }
}

#[cfg(feature = "ark-serialize")]
impl<T: ?Sized + Committable> TryFrom<&TaggedBase64> for Commitment<T> {
    type Error = Tb64Error;
    fn try_from(v: &TaggedBase64) -> Result<Self, Self::Error> {
        if v.tag() == T::tag() {
            <Self as CanonicalDeserialize>::deserialize(v.as_ref())
                .map_err(|_| Tb64Error::InvalidData)
        } else {
            Err(Tb64Error::InvalidTag)
        }
    }
}

#[cfg(feature = "ark-serialize")]
impl<T: ?Sized + Committable> From<Commitment<T>> for TaggedBase64 {
    fn from(c: Commitment<T>) -> Self {
        Self::from(&c)
    }
}

#[cfg(feature = "ark-serialize")]
impl<T: ?Sized + Committable> From<&Commitment<T>> for TaggedBase64 {
    fn from(c: &Commitment<T>) -> Self {
        let mut bytes = std::vec![];
        CanonicalSerialize::serialize(c, &mut bytes).unwrap();
        Self::new(&T::tag(), &bytes).unwrap()
    }
}

#[cfg(feature = "ark-serialize")]
impl<T: ?Sized + Committable> Display for Commitment<T> {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "{}", TaggedBase64::from(self))
    }
}

#[cfg(feature = "ark-serialize")]
impl<T: ?Sized + Committable> FromStr for Commitment<T> {
    type Err = Tb64Error;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::try_from(TaggedBase64::from_str(s)?).map_err(|_| Tb64Error::InvalidData)
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

    pub fn field<S: Committable>(self, name: &str, val: Commitment<S>) -> Self {
        self.constant_str(name).fixed_size_bytes(&val.0)
    }

    pub fn u64_field(self, name: &str, val: u64) -> Self {
        self.constant_str(name).u64(val)
    }

    pub fn array_field<S: Committable>(self, name: &str, val: &[Commitment<S>]) -> Self {
        let mut ret = self.constant_str(name).u64(val.len() as u64);
        for v in val.iter() {
            ret = ret.fixed_size_bytes(&v.0);
        }
        ret
    }

    pub fn finalize(self) -> Commitment<T> {
        let ret = self.hasher.finalize();
        Commitment(ret.try_into().unwrap(), Default::default())
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use std::{fmt::Debug, hash::Hash};

    struct DummyCommittable;
    impl Committable for DummyCommittable {
        fn commit(&self) -> Commitment<Self> {
            Commitment([0u8; 32], PhantomData)
        }

        fn tag() -> String {
            "DUMMY_TAG".to_string()
        }
    }

    // For most `T`, `Commitment<T>` has many more traits beyond those
    // explicitly derived, such as `Send`, `Sync`, `'static`.
    // This function lists those traits.
    // A call to `trait_bounds_helper(c)` where `c` is a `Commitment<T>`
    // will compile only if `Commitment<T>` impls all the expected traits.
    fn trait_bounds_helper<T>(_t: T)
    where
        T: for<'a> Arbitrary<'a>
            + AsRef<[u8]>
            + Copy
            + Clone
            + Debug
            + Display
            + for<'a> Deserialize<'a>
            + Eq
            + FromStr
            + Hash
            + Ord
            + PartialEq
            + PartialOrd
            + Send
            + Serialize
            + Sized
            + Sync
            + Tagged
            + TryFrom<TaggedBase64>
            + for<'a> TryFrom<&'a TaggedBase64>
            + 'static,
    {
    }

    #[test]
    fn trait_bounds() {
        // this code compiles only when `Commitment` impls all the traits in `trait_bounds_helper`
        trait_bounds_helper(DummyCommittable.commit());
    }
}
