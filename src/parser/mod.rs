use crate::types::Response;
use nom::Parser;
use nom::{branch::alt, IResult};

pub mod core;

pub mod bodystructure;
pub mod gmail;
pub mod rfc2087;
pub mod rfc2971;
pub mod rfc3501;
pub mod rfc4314;
pub mod rfc4315;
pub mod rfc4466;
pub mod rfc4551;
pub mod rfc4731;
pub mod rfc5161;
pub mod rfc5256;
pub mod rfc5258;
pub mod rfc5464;
pub mod rfc7162;

#[cfg(test)]
mod tests;

pub fn parse_response(msg: &[u8]) -> ParseResult<'_> {
    alt((
        rfc3501::continue_req,
        rfc3501::response_data,
        rfc3501::response_tagged,
    ))
    .parse(msg)
}

pub type ParseResult<'a> = IResult<&'a [u8], Response<'a>>;
