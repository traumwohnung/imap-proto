//!
//! https://tools.ietf.org/html/rfc4731
//!
//! IMAP4 Extension to SEARCH Command for Controlling What Kind of
//! Information Is Returned
//!
//! IMAP4rev2 ([RFC 9051](https://tools.ietf.org/html/rfc9051)) makes
//! `ESEARCH` the only response to `SEARCH` and `UID SEARCH`.
//!

use nom::Parser;
use nom::{
    bytes::streaming::{tag, tag_no_case},
    character::streaming::satisfy,
    combinator::{map, not, opt},
    multi::many0,
    sequence::{delimited, preceded, terminated},
    IResult,
};
use std::borrow::Cow;

use crate::{
    parser::{
        core::{astring_utf8, is_atom_char, number, number_64, sequence_set},
        rfc4466::{known_or_raw_tagged_ext_val, tagged_ext_label},
    },
    types::{MailboxDatum, SearchReturnData},
};

// esearch-response  = "ESEARCH" [search-correlator] [SP "UID"]
//                     *(SP search-return-data)
//                     ; ESEARCH response replaces SEARCH response
//                     ; from IMAP4rev1.
//
// A response without any search-return-data means that nothing matched:
//
//     S: * ESEARCH (TAG "A0006") UID
pub(crate) fn mailbox_data_esearch(i: &[u8]) -> IResult<&[u8], MailboxDatum<'_>> {
    map(
        (
            tag_no_case("ESEARCH"),
            opt(search_correlator),
            opt(terminated(
                tag_no_case(" UID"),
                not(satisfy(|c| is_atom_char(c as u8))),
            )),
            many0(preceded(tag(" "), search_return_data)),
        ),
        |(_, correlator, uid, data)| MailboxDatum::ESearch {
            correlator,
            uid: uid.is_some(),
            data,
        },
    )
    .parse(i)
}

// search-correlator = SP "(" "TAG" SP tag-string ")"
// tag-string        = astring
//                     ; <tag> represented as a string
fn search_correlator(i: &[u8]) -> IResult<&[u8], Cow<'_, str>> {
    delimited(tag_no_case(" (TAG "), astring_utf8, tag(")")).parse(i)
}

// search-return-data = "MIN" SP nz-number /
//                      "MAX" SP nz-number /
//                      "ALL" SP sequence-set /
//                      "COUNT" SP number /
//                      search-ret-data-ext
//                      ; All return data items conform to
//                      ; search-ret-data-ext syntax.
// search-ret-data-ext = search-modifier-name SP search-return-value
// search-modifier-name = tagged-ext-label
// search-return-value = tagged-ext-val
//
// RFC 7162 section 7 adds:
// search-return-data =/ "MODSEQ" SP mod-sequence-value
fn search_return_data(i: &[u8]) -> IResult<&[u8], SearchReturnData<'_>> {
    let (rest, name) = terminated(tagged_ext_label, tag(" ")).parse(i)?;

    // A known item's value must end where the item ends: `ALL 1:*` is not
    // a valid sequence-set here, so it must not parse as `ALL 1`.
    let item_end = || not(satisfy(|c| c != ' ' && c != '\r'));
    let known = if name.eq_ignore_ascii_case("MIN") {
        Some(terminated(map(number, SearchReturnData::Min), item_end()).parse(rest))
    } else if name.eq_ignore_ascii_case("MAX") {
        Some(terminated(map(number, SearchReturnData::Max), item_end()).parse(rest))
    } else if name.eq_ignore_ascii_case("ALL") {
        Some(terminated(map(sequence_set, SearchReturnData::All), item_end()).parse(rest))
    } else if name.eq_ignore_ascii_case("COUNT") {
        Some(terminated(map(number, SearchReturnData::Count), item_end()).parse(rest))
    } else if name.eq_ignore_ascii_case("MODSEQ") {
        Some(terminated(map(number_64, SearchReturnData::ModSeq), item_end()).parse(rest))
    } else {
        None
    };

    known_or_raw_tagged_ext_val(rest, known, |value| SearchReturnData::Other {
        name: Cow::Borrowed(name),
        value: Cow::Borrowed(value),
    })
}
