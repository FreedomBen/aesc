//! Container-format detection and dispatch (PLAN_05 §3.1, §5.4).
//!
//! After the optional ASCII-armor layer is stripped, the core peeks the leading
//! magic to choose between the native aesc path and the AES Crypt read path.
//! The peeked bytes are re-chained ahead of the rest of the stream so the chosen
//! parser sees the whole input from byte 0.

use std::io::{self, Read};

use crate::error::{AescError, Result};

/// Native aesc magic (DESIGN §5.2): ASCII "aesc" plus a NUL pad (8 bytes).
const NATIVE_MAGIC: &[u8] = b"aesc\0\0\0\0";
/// Native magic written by pre-rename builds (DESIGN §5.2, §14); accepted on
/// read forever. Same length as the aesc magic, so one 8-byte peek decides.
const LEGACY_NATIVE_MAGIC: &[u8] = b"PALADIN\0";
/// AES Crypt magic (PLAN_05 §2.1). Uppercase, so it shares no prefix with the
/// lowercase native magic.
const AESCRYPT_MAGIC: &[u8] = b"AES";

/// Which container the input is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Format {
    /// A native container — either dialect's magic (`header::parse` records
    /// which one as `Header.dialect`) — read by `stream::*`.
    Aesc,
    /// An AES Crypt container (`aescrypt::*`).
    AesCrypt,
}

/// Peek the leading magic and return the [`Format`] plus a reader that still
/// yields the peeked bytes (PLAN_05 §3.1). A fully-read prefix matching neither
/// magic is [`AescError::BadMagic`]; a short input that is a proper prefix of a
/// supported magic is [`AescError::MalformedHeader`] (a truncated header). The
/// AES Crypt magic is only 3 bytes, so an `"AES"` prefix dispatches to the AES
/// parser regardless of the following bytes (it reports any unsupported version
/// itself).
pub(crate) fn detect<R: Read>(mut input: R) -> Result<(Format, impl Read)> {
    let peek = read_up_to(&mut input, NATIVE_MAGIC.len())?;

    let format = if peek.starts_with(AESCRYPT_MAGIC) {
        Format::AesCrypt
    } else if peek == NATIVE_MAGIC || peek == LEGACY_NATIVE_MAGIC {
        Format::Aesc
    } else if is_proper_prefix_of_magic(&peek) {
        return Err(AescError::MalformedHeader(
            "input ends before the file magic is complete",
        ));
    } else {
        return Err(AescError::BadMagic);
    };

    Ok((format, io::Cursor::new(peek).chain(input)))
}

/// Whether `peek` is a proper (shorter-than-magic) prefix of any supported
/// magic — i.e. the input may be a truncated header rather than a foreign file.
fn is_proper_prefix_of_magic(peek: &[u8]) -> bool {
    [NATIVE_MAGIC, LEGACY_NATIVE_MAGIC, AESCRYPT_MAGIC]
        .iter()
        .any(|magic| peek.len() < magic.len() && magic.starts_with(peek))
}

/// Read up to `max` bytes, returning fewer only at end of input. Mirrors
/// `stream::read_up_to`: retries `Interrupted` and recovers a framing error the
/// armor layer wrapped in an `io::Error`.
fn read_up_to<R: Read>(reader: &mut R, max: usize) -> Result<Vec<u8>> {
    let mut buf = vec![0u8; max];
    let mut filled = 0;
    while filled < max {
        match reader.read(&mut buf[filled..]) {
            Ok(0) => break,
            Ok(n) => filled += n,
            Err(ref e) if e.kind() == io::ErrorKind::Interrupted => continue,
            Err(e) => {
                return Err(match crate::error::recover_aesc_error(e) {
                    Ok(sym) => sym,
                    Err(e) => AescError::Io(e),
                })
            }
        }
    }
    buf.truncate(filled);
    Ok(buf)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Run detection over `bytes` and return the format plus everything the
    /// re-chained reader yields, proving no peeked byte is lost.
    fn detect_and_drain(bytes: &[u8]) -> Result<(Format, Vec<u8>)> {
        let (format, mut reader) = detect(io::Cursor::new(bytes.to_vec()))?;
        let mut out = Vec::new();
        reader.read_to_end(&mut out).map_err(AescError::Io)?;
        Ok((format, out))
    }

    #[test]
    fn aesc_magic_is_detected_and_rechained() {
        let input = b"aesc\x00\x00\x00\x00\x01the rest of the container";
        let (format, drained) = detect_and_drain(input).unwrap();
        assert_eq!(format, Format::Aesc);
        assert_eq!(drained, input, "re-chained reader reproduces the input");
    }

    /// The legacy PALADIN magic routes to the same native path forever
    /// (DESIGN §5.2, §14).
    #[test]
    fn legacy_paladin_magic_is_detected_and_rechained() {
        let input = b"PALADIN\x00\x01the rest of the container";
        let (format, drained) = detect_and_drain(input).unwrap();
        assert_eq!(format, Format::Aesc);
        assert_eq!(drained, input, "re-chained reader reproduces the input");
    }

    #[test]
    fn aescrypt_magic_is_detected_and_rechained() {
        // Both a v2 and an (unsupported) version byte route to the AES parser;
        // detection does not look at the version.
        for version in [0x01u8, 0x02, 0x03, 0x7f] {
            let input = [b"AES".as_slice(), &[version, 0x00], b"more bytes"].concat();
            let (format, drained) = detect_and_drain(&input).unwrap();
            assert_eq!(format, Format::AesCrypt, "version {version:#04x}");
            assert_eq!(drained, input, "re-chained reader reproduces the input");
        }
    }

    #[test]
    fn foreign_magic_is_bad_magic() {
        // A full 8-byte prefix matching neither magic.
        assert!(matches!(
            detect_and_drain(b"GARBAGE!and more"),
            Err(AescError::BadMagic)
        ));
        // Eight bytes that share a native-magic prefix but differ in the 8th
        // byte (both dialects).
        assert!(matches!(
            detect_and_drain(b"PALADINxtail"),
            Err(AescError::BadMagic)
        ));
        assert!(matches!(
            detect_and_drain(b"aesc\x00\x00\x00xtail"),
            Err(AescError::BadMagic)
        ));
    }

    #[test]
    fn short_prefix_of_a_magic_is_malformed_not_bad() {
        // Proper prefixes of aesc, PALADIN, and AES are truncated headers.
        for short in [
            b"".as_slice(),
            b"P",
            b"PAL",
            b"PALADIN",
            b"A",
            b"AE",
            b"aesc",
            b"aesc\x00\x00",
        ] {
            assert!(
                matches!(detect_and_drain(short), Err(AescError::MalformedHeader(_))),
                "prefix {short:?} should be MalformedHeader"
            );
        }
    }

    #[test]
    fn exactly_aes_magic_routes_to_aescrypt() {
        // The 3-byte magic alone is enough to dispatch; the AES parser then
        // reports the truncation itself.
        let (format, drained) = detect_and_drain(b"AES").unwrap();
        assert_eq!(format, Format::AesCrypt);
        assert_eq!(drained, b"AES");
    }
}
