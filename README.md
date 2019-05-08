libsecp256k1
============

[![Build Status](https://travis-ci.org/bitcoin-core/secp256k1.svg?branch=master)](https://travis-ci.org/bitcoin-core/secp256k1)

Optimized C library for EC operations on curve secp256k1.

This library is a work in progress and is being used to research best practices. Use at your own risk.

Features:
* secp256k1 ECDSA signing/verification and key generation.
* Adding/multiplying private/public keys.
* Serialization/parsing of private keys, public keys, signatures.
* Constant time, constant memory access signing and pubkey generation.
* Derandomized DSA (via RFC6979 or with a caller provided function.)
* Very efficient implementation.

Implementation details
----------------------

* General
  * No runtime heap allocation.
  * Extensive testing infrastructure.
  * Structured to facilitate review and analysis.
  * Intended to be portable to any system with a C89 compiler and uint64_t support.
  * Expose only higher level interfaces to minimize the API surface and improve application security. ("Be difficult to use insecurely.")
* Field operations
  * Optimized implementation of arithmetic modulo the curve's field size (2^256 - 0x1000003D1).
    * Using 5 52-bit limbs (including hand-optimized assembly for x86_64, by Diederik Huys).
    * Using 10 26-bit limbs.
  * Field inverses and square roots using a sliding window over blocks of 1s (by Peter Dettman).
* Scalar operations
  * Optimized implementation without data-dependent branches of arithmetic modulo the curve's order.
    * Using 4 64-bit limbs (relying on __int128 support in the compiler).
    * Using 8 32-bit limbs.
* Group operations
  * Point addition formula specifically simplified for the curve equation (y^2 = x^3 + 7).
  * Use addition between points in Jacobian and affine coordinates where possible.
  * Use a unified addition/doubling formula where necessary to avoid data-dependent branches.
  * Point/x comparison without a field inversion by comparison in the Jacobian coordinate space.
* Point multiplication for verification (a*P + b*G).
  * Use wNAF notation for point multiplicands.
  * Use a much larger window for multiples of G, using precomputed multiples.
  * Use Shamir's trick to do the multiplication with the public key and the generator simultaneously.
  * Optionally (off by default) use secp256k1's efficiently-computable endomorphism to split the P multiplicand into 2 half-sized ones.
* Point multiplication for signing
  * Use a precomputed table of multiples of powers of 16 multiplied with the generator, so general multiplication becomes a series of additions.
  * Access the table with branch-free conditional moves so memory access is uniform.
  * No data-dependent branches
  * The precomputed tables add and eventually subtract points for which no known scalar (private key) is known, preventing even an attacker with control over the private key used to control the data internally.

Build steps
-----------

libsecp256k1 is built using autotools:

    $ ./autogen.sh
    $ ./configure
    $ make
    $ ./tests
    $ sudo make install  # optional

## secp256k1cmd
secp256k1cmd subcmd arg1 , arg2 ...

```
secp256k1cmd sign msg key

// msg - ascii string
// key - hex in ascii format

$ ./secp256k1cmd sign "abc" "da6feae3ca249c359200487934216f45dd1c2159116c3eecc348a74a3c7d16ba"

{"status":0,"data":{"signature":"85c8c74e85ae7c15c313a1b1532147ed8bbebf2e8898b31fbb0d7e3664aa22f115388c30ee37b7730711c0790cfc9aebef660937721d307560e90f28ab86613c","recid":1}}

// 错误返回 "status": -1

secp256k1cmd sha256 msg

// msg - ascii string

$./secp256k1cmd sha256 "abc"
{"status":0,"data":"ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"}



```


