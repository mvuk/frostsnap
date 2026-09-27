use crate::bip39_words::{word_to_index, BIP39_WORDS, BITS_PER_WORD};
use crate::error::ShareBackupError;
use alloc::{string::ToString, vec::Vec};
use core::{
    fmt,
    ops::{BitOrAssign, Shl},
    str::FromStr,
};
use schnorr_fun::{
    frost::{Fingerprint, SecretShare, ShareImage, ShareIndex, SharedKey},
    fun::{hash::HashAdd, poly, prelude::*},
};
use sha2::{Digest, Sha256};

/// Number of words in a share backup
pub const NUM_WORDS: usize = 25;

/// Number of bits used for the scalar/secret share (32 bytes)
pub const SCALAR_BITS: usize = 256;

/// Number of bits used for polynomial checksum
pub const POLY_CHECKSUM_BITS: u8 = 8;

/// Number of bits used for words checksum
pub const WORDS_CHECKSUM_BITS: u8 = 11;

/// Start bit position for polynomial checksum (after scalar)
const POLY_CHECKSUM_START: usize = SCALAR_BITS;

/// Start bit position for words checksum (after scalar and poly checksum)
const WORDS_CHECKSUM_START: usize = SCALAR_BITS + POLY_CHECKSUM_BITS as usize;

/// Total number of bits in the backup (must equal NUM_WORDS * BITS_PER_WORD)
const TOTAL_BITS: usize = SCALAR_BITS + POLY_CHECKSUM_BITS as usize + WORDS_CHECKSUM_BITS as usize;

/// A Shamir secret share with checksum for BIP39 word encoding
///
/// Contains a secret share and its polynomial checksum for FROST compatibility.
/// For safety, you can't access the secret share until you've provided the
/// correct polynomial (i.e. [`SharedKey`]). You can however access the *share
/// image* which can allow you to produce the `SharedKey`. See *polynomial
/// checksum* in the README.
///
/// A `ShareBackup` backs up a share of the secret, so its index is never `0`.
/// A [`SecretBackup`] backs up the secret itself under index `0`. Use
/// [`Backup`] to decode text that may be either.
///
/// [`SharedKey`]: schnorr_fun::frost::SharedKey
#[derive(Debug, Clone, PartialEq)]
#[cfg_attr(feature = "bincode", derive(bincode::Encode, bincode::Decode))]
pub struct ShareBackup {
    share: SecretShare,
    poly_checksum: u16,
}

/// A `#0` backup: the secret itself, with checksums, for BIP39 word encoding
///
/// A [`ShareBackup`] backs up a share of the secret; a `SecretBackup` backs up
/// the secret itself. Shamir's scheme defines the secret as `f(0)`, so index
/// `0` is reserved for it. The polynomial checksum binds the
/// backup to the degree-0 commitment `[secret·G]`, and
/// [`extract_secret`](Self::extract_secret) verifies it.
#[derive(Debug, Clone, PartialEq)]
pub struct SecretBackup {
    secret: Scalar<Secret, Zero>,
    poly_checksum: u16,
}

/// Either kind of backup: what parsing text produces
///
/// A `#0` backup is a [`SecretBackup`], the secret itself. Any other index is
/// a [`ShareBackup`], a share of the secret.
#[derive(Debug, Clone, PartialEq)]
pub enum Backup {
    /// A share of the secret (`#1`, `#2`, ...)
    Share(ShareBackup),
    /// The secret itself (`#0`)
    Secret(SecretBackup),
}

fn set_bit<T: BitOrAssign + Shl<u8, Output = T> + From<u8>>(target: &mut T, len: u8, index: u8) {
    *target |= T::from(1) << ((len - 1) - index)
}

impl ShareBackup {
    /// Returns the share index (x-coordinate in Shamir's scheme)
    pub fn index(&self) -> ShareIndex {
        self.share.index
    }

    /// Creates a ShareBackup with polynomial checksum for FROST compatibility
    pub fn from_secret_share_and_shared_key(
        secret_share: SecretShare,
        shared_key: &SharedKey,
    ) -> Self {
        let poly_checksum = compute_poly_checksum(
            secret_share.index.mark_zero(),
            secret_share.share,
            shared_key,
        );
        ShareBackup {
            share: secret_share,
            poly_checksum,
        }
    }

    /// Decodes a ShareBackup from index and 25 BIP39 words, validating checksums
    ///
    /// Index `0` is the secret itself, not a share, so it is rejected with
    /// [`ShareBackupError::InvalidShareIndex`]. Use [`Backup::from_words`] to
    /// accept both.
    pub fn from_words(index: u32, words: [&str; NUM_WORDS]) -> Result<Self, ShareBackupError> {
        let (scalar, poly_checksum) = decode_words(index, words)?;

        // Convert u32 to ShareIndex (Scalar<Public, NonZero>)
        let index_scalar = Scalar::<Secret, Zero>::from(index)
            .non_zero()
            .ok_or(ShareBackupError::InvalidShareIndex)?
            .public();

        let share = SecretShare {
            index: index_scalar,
            share: scalar,
        };

        Ok(ShareBackup {
            share,
            poly_checksum,
        })
    }

    /// Encodes share as 25 word indices (11-bit each) in constant time
    pub fn to_word_indices(&self) -> [u16; NUM_WORDS] {
        // Get index as u32
        let index_u32: u32 = self
            .index()
            .try_into()
            .expect("Share index should fit in u32");
        encode_word_indices(index_u32, self.share.share, self.poly_checksum)
    }

    /// Converts share to 25 BIP39 words for display/backup
    pub fn to_words(&self) -> [&'static str; NUM_WORDS] {
        indices_to_words(self.to_word_indices())
    }

    /// Extracts the secret share after validating polynomial checksum
    pub fn extract_secret<Z: ZeroChoice>(
        self,
        shared_key: &SharedKey<Normal, Z>,
    ) -> Result<SecretShare, ShareBackupError> {
        // Verify polynomial checksum against the shared key
        let poly_checksum =
            compute_poly_checksum(self.index().mark_zero(), self.share.share, shared_key);
        if poly_checksum != self.poly_checksum {
            return Err(ShareBackupError::PolyChecksumFailed);
        }

        Ok(self.share)
    }

    /// Returns the public share image (index and commitment)
    pub fn share_image(&self) -> ShareImage {
        self.share.share_image()
    }
}

impl SecretBackup {
    /// Creates a `#0` backup carrying the secret itself
    pub fn new(secret: Scalar<Secret, Zero>) -> Self {
        let shared_key = secret_shared_key(secret);
        let poly_checksum = compute_poly_checksum(Scalar::zero(), secret, &shared_key);
        SecretBackup {
            secret,
            poly_checksum,
        }
    }

    /// Decodes a `#0` backup from 25 BIP39 words, validating the words checksum
    pub fn from_words(words: [&str; NUM_WORDS]) -> Result<Self, ShareBackupError> {
        let (secret, poly_checksum) = decode_words(0, words)?;
        Ok(SecretBackup {
            secret,
            poly_checksum,
        })
    }

    /// Encodes the backup as 25 word indices (11-bit each) in constant time
    pub fn to_word_indices(&self) -> [u16; NUM_WORDS] {
        encode_word_indices(0, self.secret, self.poly_checksum)
    }

    /// Converts the backup to 25 BIP39 words for display/backup
    pub fn to_words(&self) -> [&'static str; NUM_WORDS] {
        indices_to_words(self.to_word_indices())
    }

    /// Extracts the secret after validating the polynomial checksum against
    /// its own degree-0 commitment `[secret·G]`
    pub fn extract_secret(self) -> Result<Scalar<Secret, Zero>, ShareBackupError> {
        let shared_key = secret_shared_key(self.secret);
        let poly_checksum = compute_poly_checksum(Scalar::zero(), self.secret, &shared_key);
        if poly_checksum != self.poly_checksum {
            return Err(ShareBackupError::PolyChecksumFailed);
        }
        Ok(self.secret)
    }
}

impl Backup {
    /// Returns the index: `0` for a secret backup, the share index otherwise
    pub fn index(&self) -> Scalar<Public, Zero> {
        match self {
            Backup::Share(share) => share.index().mark_zero(),
            Backup::Secret(_) => Scalar::zero(),
        }
    }

    /// Whether this is a `#0` backup carrying the secret itself
    pub fn is_secret(&self) -> bool {
        matches!(self, Backup::Secret(_))
    }

    /// Returns the public share image, or `None` for a `#0` backup, which has
    /// no image
    pub fn share_image(&self) -> Option<ShareImage> {
        match self {
            Backup::Share(share) => Some(share.share_image()),
            Backup::Secret(_) => None,
        }
    }

    /// Decodes a backup from index and 25 BIP39 words, validating checksums.
    /// Index `0` decodes as a [`SecretBackup`].
    pub fn from_words(index: u32, words: [&str; NUM_WORDS]) -> Result<Self, ShareBackupError> {
        if index == 0 {
            SecretBackup::from_words(words).map(Backup::Secret)
        } else {
            ShareBackup::from_words(index, words).map(Backup::Share)
        }
    }

    /// Converts the backup to 25 BIP39 words for display/backup
    pub fn to_words(&self) -> [&'static str; NUM_WORDS] {
        match self {
            Backup::Share(share) => share.to_words(),
            Backup::Secret(secret_backup) => secret_backup.to_words(),
        }
    }

    /// Generates threshold shares with fingerprint grinding for FROST.
    ///
    /// With `threshold == 1` every share equals the secret, so each backup is
    /// emitted as a `#0` secret backup.
    pub fn generate_shares<R: rand_core::RngCore>(
        secret: Scalar<Secret, NonZero>,
        threshold: usize,
        n_shares: usize,
        fingerprint: Fingerprint,
        rng: &mut R,
    ) -> (Vec<Backup>, SharedKey) {
        let poly = poly::scalar::generate_shamir_sharing_poly(secret, threshold, rng);
        let point_poly = poly::scalar::to_point_poly(&poly);
        let mut shared_key =
            SharedKey::from_non_zero_poly(point_poly[0], point_poly[1..].iter().copied());
        let tweak_poly = shared_key.grind_fingerprint::<sha2::Sha256>(fingerprint);
        let poly = poly::scalar::add(poly, tweak_poly).collect::<Vec<_>>();

        let shares: Vec<Backup> = if threshold == 1 {
            (0..n_shares)
                .map(|_| Backup::Secret(SecretBackup::new(secret.mark_zero())))
                .collect()
        } else {
            // Generate shares by evaluating the polynomial at indices 1..=n_shares
            (1u32..=n_shares as _)
                .map(|i| {
                    let index = Scalar::<Public, _>::from(i)
                        .non_zero()
                        .expect("starts at 1");
                    let share_scalar = poly::scalar::eval(&poly, index);
                    let poly_checksum =
                        compute_poly_checksum(index.mark_zero(), share_scalar, &shared_key);

                    let share = SecretShare {
                        index,
                        share: share_scalar,
                    };

                    Backup::Share(ShareBackup {
                        share,
                        poly_checksum,
                    })
                })
                .collect()
        };

        (shares, shared_key)
    }
}

impl From<ShareBackup> for Backup {
    fn from(share: ShareBackup) -> Self {
        Backup::Share(share)
    }
}

impl From<SecretBackup> for Backup {
    fn from(secret_backup: SecretBackup) -> Self {
        Backup::Secret(secret_backup)
    }
}

/// The degree-0 shared key a `#0` backup is checksummed against
pub(crate) fn secret_shared_key(secret: Scalar<Secret, Zero>) -> SharedKey<Normal, Zero> {
    SharedKey::from_poly(vec![g!(secret * G).normalize()])
}

/// Decodes the 25 words into the scalar and polynomial checksum, verifying the
/// words checksum under `index`
fn decode_words(
    index: u32,
    words: [&str; NUM_WORDS],
) -> Result<(Scalar<Secret, Zero>, u16), ShareBackupError> {
    // First, convert each word to its BITS_PER_WORD-bit index
    let mut word_indices = [0u16; NUM_WORDS];
    for (i, word) in words.iter().enumerate() {
        word_indices[i] = word_to_index(word).ok_or_else(|| ShareBackupError::InvalidBip39Word {
            word_index: i,
            word: word.to_string(),
        })? as u16;
    }

    let mut scalar_bytes = [0u8; 32];
    let mut poly_checksum = 0u16;
    let mut words_checksum = 0u16;

    let mut total_bits_processed = 0;

    for &word_idx in &word_indices {
        for bit_offset in (0..BITS_PER_WORD).rev() {
            let bit = (word_idx >> bit_offset) & 1;

            if bit != 0 {
                if total_bits_processed < SCALAR_BITS {
                    // Scalar bytes
                    let byte_index = total_bits_processed / 8;
                    let bit_in_byte = total_bits_processed % 8;
                    set_bit(&mut scalar_bytes[byte_index], 8, bit_in_byte as _);
                } else if total_bits_processed < WORDS_CHECKSUM_START {
                    let checksum_bit = total_bits_processed - POLY_CHECKSUM_START;
                    set_bit(&mut poly_checksum, POLY_CHECKSUM_BITS, checksum_bit as _);
                } else if total_bits_processed < TOTAL_BITS {
                    let checksum_bit = total_bits_processed - WORDS_CHECKSUM_START;
                    set_bit(&mut words_checksum, WORDS_CHECKSUM_BITS, checksum_bit as _);
                }
            }

            total_bits_processed += 1;
        }
    }

    // The scalar must be less than the group order; it is never reduced.
    let scalar =
        Scalar::<Secret, Zero>::from_bytes(scalar_bytes).ok_or(ShareBackupError::InvalidScalar)?;

    // Verify words checksum before creating the share
    let expected_words_checksum = compute_words_checksum(index, scalar, poly_checksum);
    if expected_words_checksum != words_checksum {
        return Err(ShareBackupError::WordsChecksumFailed);
    }

    Ok((scalar, poly_checksum))
}

/// Encodes the scalar and polynomial checksum as 25 word indices (11-bit
/// each) in constant time, with the words checksum computed under `index`
fn encode_word_indices(
    index: u32,
    scalar: Scalar<Secret, Zero>,
    poly_checksum: u16,
) -> [u16; NUM_WORDS] {
    let scalar_bytes = scalar.to_bytes();

    // Calculate words checksum for encoding
    let words_checksum = compute_words_checksum(index, scalar, poly_checksum);

    let mut word_indices = [0u16; NUM_WORDS];
    let mut word_idx = 0;
    let mut accumulator: u32 = 0;
    let mut bits_in_acc = 0;

    // Process the 32 scalar bytes
    for &byte in &scalar_bytes {
        accumulator = (accumulator << 8) | (byte as u32);
        bits_in_acc += 8;

        // Extract 11-bit words while we have enough bits
        while bits_in_acc >= BITS_PER_WORD as u32 && word_idx < NUM_WORDS {
            let shift = bits_in_acc - BITS_PER_WORD as u32;
            word_indices[word_idx] = (accumulator >> shift) as u16;
            accumulator &= (1u32 << shift) - 1;
            bits_in_acc = shift;
            word_idx += 1;
        }
    }

    // After scalar bytes, we have some bits left in accumulator
    // Add poly_checksum (8 bits) to complete the current word
    accumulator = (accumulator << 8) | (poly_checksum as u32);
    word_indices[23] = accumulator as u16;
    word_indices[24] = words_checksum;

    word_indices
}

fn indices_to_words(word_indices: [u16; NUM_WORDS]) -> [&'static str; NUM_WORDS] {
    let mut words = [""; NUM_WORDS];

    for (i, &word_idx) in word_indices.iter().enumerate() {
        words[i] = BIP39_WORDS[word_idx as usize];
    }

    words
}

fn compute_poly_checksum<Z: ZeroChoice>(
    index: Scalar<Public, Zero>,
    scalar: Scalar<Secret, Zero>,
    shared_key: &SharedKey<Normal, Z>,
) -> u16 {
    let hash = Sha256::new()
        .add(index.to_bytes())
        .add(scalar)
        .add(shared_key.point_polynomial())
        .finalize();
    u16::from_be_bytes([hash[0], hash[1]]) >> (16 - POLY_CHECKSUM_BITS)
}

fn compute_words_checksum(index: u32, scalar: Scalar<Secret, Zero>, poly_checksum: u16) -> u16 {
    let hash = Sha256::new()
        .add(index.to_be_bytes())
        .add(scalar)
        .add(poly_checksum.to_be_bytes())
        .finalize();
    u16::from_be_bytes([hash[0], hash[1]]) >> (16 - WORDS_CHECKSUM_BITS)
}

fn fmt_backup(
    f: &mut fmt::Formatter<'_>,
    index: u32,
    words: [&'static str; NUM_WORDS],
) -> fmt::Result {
    write!(f, "#{} ", index)?;
    for (i, word) in words.iter().enumerate() {
        if i > 0 {
            write!(f, " ")?;
        }
        write!(f, "{}", word)?;
    }
    Ok(())
}

impl fmt::Display for ShareBackup {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let index_u32: u32 = self
            .index()
            .try_into()
            .expect("Share index should fit in u32");
        fmt_backup(f, index_u32, self.to_words())
    }
}

impl fmt::Display for SecretBackup {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt_backup(f, 0, self.to_words())
    }
}

impl fmt::Display for Backup {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Backup::Share(share) => share.fmt(f),
            Backup::Secret(secret_backup) => secret_backup.fmt(f),
        }
    }
}

/// Splits `#<index> <25 words>` into the index and the words
fn parse_index_and_words(s: &str) -> Result<(u32, [&str; NUM_WORDS]), ShareBackupError> {
    let mut parts = s.split_whitespace();

    // Get the index
    let index_str = parts
        .next()
        .ok_or(ShareBackupError::ShareIndexParseError)?
        .trim_start_matches('#');
    let index = index_str
        .parse::<u32>()
        .map_err(|_| ShareBackupError::ShareIndexParseError)?;

    // Get the NUM_WORDS words
    let mut words = [""; NUM_WORDS];
    for word in &mut words {
        *word = parts.next().ok_or(ShareBackupError::NotEnoughWords)?;
    }

    // Check there are no extra words
    if parts.next().is_some() {
        return Err(ShareBackupError::TooManyWords);
    }

    Ok((index, words))
}

impl FromStr for ShareBackup {
    type Err = ShareBackupError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let (index, words) = parse_index_and_words(s)?;
        ShareBackup::from_words(index, words)
    }
}

impl FromStr for Backup {
    type Err = ShareBackupError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let (index, words) = parse_index_and_words(s)?;
        Backup::from_words(index, words)
    }
}
