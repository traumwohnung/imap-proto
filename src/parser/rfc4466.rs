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
    combinator::{map, map_res, opt, recognize},
    multi::separated_list1,
    IResult,
};

use std::str::from_utf8;

use crate::parser::core::{astring, paren_delimited};

// tagged-ext-label    = tagged-label-fchar *tagged-label-char
//                       ;; Is a valid RFC 3501 "atom".
// tagged-label-fchar  = ALPHA / "-" / "_" / "."
// tagged-label-char   = tagged-label-fchar / DIGIT / ":"
pub(crate) fn tagged_ext_label(i: &[u8]) -> IResult<&[u8], &str> {
    map_res(
        recognize((
            take_while1(is_tagged_label_fchar),
            opt(take_while1(|c| {
                is_tagged_label_fchar(c) || c.is_ascii_digit() || c == b':'
            })),
        )),
        from_utf8,
    )
    .parse(i)
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
//
// Only recognized, not interpreted: unlike `core::sequence_set`, this accepts
// the `*` seq-number, and a number64 never needs a separate branch because
// its digits are also a sequence-set's.
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
//
// The grammar nests without limit, so the nesting depth is bounded to keep a
// hostile server from overflowing the stack of the parsing thread.
fn tagged_ext_comp(i: &[u8]) -> IResult<&[u8], &[u8]> {
    nested_tagged_ext_comp(i, MAX_TAGGED_EXT_COMP_DEPTH)
}

/// Parenthesis levels allowed inside a `tagged-ext-val` beyond its own.
const MAX_TAGGED_EXT_COMP_DEPTH: usize = 32;

fn nested_tagged_ext_comp(i: &[u8], depth: usize) -> IResult<&[u8], &[u8]> {
    recognize(separated_list1(
        char(' '),
        alt((astring, |i| {
            if depth == 0 {
                return Err(nom::Err::Error(nom::error::make_error(
                    i,
                    nom::error::ErrorKind::TooLarge,
                )));
            }
            recognize(paren_delimited(|i| nested_tagged_ext_comp(i, depth - 1))).parse(i)
        })),
    ))
    .parse(i)
}

/// Parses the `tagged-ext-val` of an extension item whose label was already
/// consumed.
///
/// `known` is the result of parsing the value with the item's modelled syntax,
/// or `None` when the label names no modelled item. An unknown item, or a
/// known one whose value does not follow the modelled syntax, is kept
/// verbatim through `raw` rather than rejected or dropped; other errors,
/// such as `Incomplete`, propagate.
pub(crate) fn known_or_raw_tagged_ext_val<'a, O>(
    i: &'a [u8],
    known: Option<IResult<&'a [u8], O>>,
    raw: impl FnMut(&'a [u8]) -> O,
) -> IResult<&'a [u8], O> {
    match known {
        None | Some(Err(nom::Err::Error(_))) => map(tagged_ext_val, raw).parse(i),
        Some(result) => result,
    }
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

        // Nesting is bounded rather than recursing without limit.
        let nested = |depth: usize| {
            let mut input = "(".repeat(depth + 1).into_bytes();
            input.push(b'a');
            input.extend(")".repeat(depth + 1).bytes());
            input.extend(b"\r\n");
            input
        };
        let input = nested(MAX_TAGGED_EXT_COMP_DEPTH);
        assert_eq!(
            tagged_ext_val(&input),
            Ok((&b"\r\n"[..], &input[..input.len() - 2]))
        );
        assert!(matches!(
            tagged_ext_val(&nested(MAX_TAGGED_EXT_COMP_DEPTH + 1)),
            Err(nom::Err::Error(_))
        ));
        assert!(matches!(
            tagged_ext_val(&nested(1_000_000)),
            Err(nom::Err::Error(_))
        ));
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
