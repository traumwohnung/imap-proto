//!
//! https://tools.ietf.org/html/rfc4466
//!
//! Collected Extensions to IMAP4 ABNF
//!

use nom::Parser;
use nom::{
    branch::alt,
    bytes::streaming::take_while1,
    character::streaming::char,
    combinator::{opt, recognize},
    multi::separated_list1,
    IResult,
};

use crate::parser::core::{astring, paren_delimited};

// tagged-ext-label    = tagged-label-fchar *tagged-label-char
//                       ;; Is a valid RFC 3501 "atom".
// tagged-label-fchar  = ALPHA / "-" / "_" / "."
// tagged-label-char   = tagged-label-fchar / DIGIT / ":"
pub(crate) fn tagged_ext_label(i: &[u8]) -> IResult<&[u8], &str> {
    let (rest, label) = recognize((
        take_while1(is_tagged_label_fchar),
        opt(take_while1(|c| {
            is_tagged_label_fchar(c) || c.is_ascii_digit() || c == b':'
        })),
    ))
    .parse(i)?;
    // Only ASCII bytes were accepted above.
    Ok((rest, std::str::from_utf8(label).unwrap()))
}

fn is_tagged_label_fchar(c: u8) -> bool {
    c.is_ascii_alphabetic() || c == b'-' || c == b'_' || c == b'.'
}

// tagged-ext-val      = tagged-ext-simple /
//                       "(" [tagged-ext-comp] ")"
//
// Returns the raw bytes of the value, so that callers can keep values of
// extensions this crate does not model instead of dropping them.
pub(crate) fn tagged_ext_val(i: &[u8]) -> IResult<&[u8], &[u8]> {
    alt((
        recognize(paren_delimited(opt(tagged_ext_comp))),
        tagged_ext_simple,
    ))
    .parse(i)
}

// tagged-ext-simple   = sequence-set / number / number64
fn tagged_ext_simple(i: &[u8]) -> IResult<&[u8], &[u8]> {
    take_while1(|c: u8| c.is_ascii_digit() || c == b':' || c == b',' || c == b'*')(i)
}

// tagged-ext-comp     = astring /
//                       tagged-ext-comp *(SP tagged-ext-comp) /
//                       "(" tagged-ext-comp ")"
//                       ;; Extensions that follow this general
//                       ;; syntax should use nstring instead of
//                       ;; astring when appropriate in the context
//                       ;; of the extension.
//                       ;; Note that a message set or a "number"
//                       ;; can always be represented as an "atom".
//                       ;; A URL should be represented as
//                       ;; a "quoted" string.
fn tagged_ext_comp(i: &[u8]) -> IResult<&[u8], &[u8]> {
    recognize(separated_list1(
        char(' '),
        alt((astring, recognize(paren_delimited(tagged_ext_comp)))),
    ))
    .parse(i)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_tagged_ext_val() {
        for (input, value) in [
            (&b"1:3,5\r\n"[..], &b"1:3,5"[..]),
            (b"42\r\n", b"42"),
            (b"()\r\n", b"()"),
            (
                b"(\"a\" b (c (d)) {1}\r\nx)\r\n",
                b"(\"a\" b (c (d)) {1}\r\nx)",
            ),
        ] {
            assert_eq!(tagged_ext_val(input), Ok((&b"\r\n"[..], value)));
        }
        assert!(tagged_ext_val(b"(unbalanced\r\n").is_err());
        assert!(tagged_ext_val(b"\"quoted\"\r\n").is_err());
    }

    #[test]
    fn test_tagged_ext_label() {
        assert_eq!(
            tagged_ext_label(b"X-VENDOR.item:2 "),
            Ok((&b" "[..], "X-VENDOR.item:2"))
        );
        assert!(tagged_ext_label(b"2BAD ").is_err());
    }
}
