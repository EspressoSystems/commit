Keccak256-based structured commitments
======================================

This library provides utilities for defining hashes of structured
data, in a way that supports nested data structures and automatic
domain separation (ie, two structures with different fields will never
feed the same input into the hash function).

WARNING
=======

Implementing `Committable` using `RawCommitmentBuilder` is a manual
process that should be done carefully. In the future, we will provide
a macro to automatically implement `Committable` in a reasonable way,
but for now, use this library with caution.

