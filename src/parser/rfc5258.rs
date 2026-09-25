//!
//! https://tools.ietf.org/html/rfc5258
//!
//! IMAP4 LIST Command Extensions
//!

use nom::Parser;
use nom::{
    bytes::streaming::tag,
    combinator::{map, opt},
    multi::separated_list1,
    sequence::preceded,
    IResult,
};
use std::borrow::Cow;

use crate::{
    parser::{
        core::{astring_utf8, paren_delimited, parenthesized_list},
        rfc3501::mailbox,
        rfc4466::tagged_ext_val,
    },
    types::MailboxListExtendedItem,
};

// mbox-list-extended  = "(" [mbox-list-extended-item
//                       *(SP mbox-list-extended-item)] ")"
pub(crate) fn mbox_list_extended(i: &[u8]) -> IResult<&[u8], Vec<MailboxListExtendedItem<'_>>> {
    parenthesized_list(mbox_list_extended_item).parse(i)
}

// mbox-list-extended-item = mbox-list-extended-item-tag SP tagged-ext-val
//
// mbox-list-extended-item-tag = astring
//                       ; The content MUST conform to either "eitem-vendor-tag"
//                       ; or "eitem-standard-tag" ABNF productions.
fn mbox_list_extended_item(i: &[u8]) -> IResult<&[u8], MailboxListExtendedItem<'_>> {
    let (rest, item_tag) = astring_utf8(i)?;
    let (rest, _) = tag(" ")(rest)?;

    let known = if item_tag.eq_ignore_ascii_case("CHILDINFO") {
        // childinfo-extended-item = "CHILDINFO" SP "("
        //                           list-select-base-opt-quoted
        //                           *(SP list-select-base-opt-quoted) ")"
        paren_delimited(separated_list1(tag(" "), astring_utf8))
            .map(MailboxListExtendedItem::ChildInfo)
            .parse(rest)
    } else if item_tag.eq_ignore_ascii_case("OLDNAME") {
        // oldname-extended-item = "OLDNAME" SP "(" mailbox ")"
        paren_delimited(mailbox)
            .map(MailboxListExtendedItem::OldName)
            .parse(rest)
    } else {
        Err(nom::Err::Error(nom::error::make_error(
            rest,
            nom::error::ErrorKind::Tag,
        )))
    };

    match known {
        Err(nom::Err::Error(_)) => map(tagged_ext_val, |value| MailboxListExtendedItem::Other {
            tag: item_tag.clone(),
            value: Cow::Borrowed(value),
        })
        .parse(rest),
        result => result,
    }
}

// mailbox-list        = "(" [mbx-list-flags] ")" SP
//                       (DQUOTE QUOTED-CHAR DQUOTE / nil) SP mailbox
//                       [SP mbox-list-extended]
pub(crate) fn opt_mbox_list_extended(i: &[u8]) -> IResult<&[u8], Vec<MailboxListExtendedItem<'_>>> {
    map(
        opt(preceded(tag(" "), mbox_list_extended)),
        Option::unwrap_or_default,
    )
    .parse(i)
}
