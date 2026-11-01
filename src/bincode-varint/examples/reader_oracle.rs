//! Text bridge for the independently frozen Reader corpus; executes Rust only.

use hl_bincode_varint::{ReaderError, decode_u32_reader, decode_u64_reader};
use std::io::{self, BufRead, Write};

fn invalid_input(message: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, message.into())
}

fn parse_hex(text: &str) -> io::Result<Vec<u8>> {
    if !text.len().is_multiple_of(2) {
        return Err(invalid_input("hex input has odd length"));
    }
    text.as_bytes()
        .chunks_exact(2)
        .map(|pair| {
            let digit = |byte: u8| match byte {
                b'0'..=b'9' => Some(byte - b'0'),
                b'a'..=b'f' => Some(byte - b'a' + 10),
                b'A'..=b'F' => Some(byte - b'A' + 10),
                _ => None,
            };
            match (digit(pair[0]), digit(pair[1])) {
                (Some(high), Some(low)) => Ok(high * 16 + low),
                _ => Err(invalid_input("hex input contains a non-hex byte")),
            }
        })
        .collect()
}

fn write_case(line: &str, output: &mut impl Write) -> io::Result<()> {
    let mut fields = line.split('\t');
    let width = fields
        .next()
        .ok_or_else(|| invalid_input("missing width"))?;
    let flag: u8 = fields
        .next()
        .ok_or_else(|| invalid_input("missing byte-order flag"))?
        .parse()
        .map_err(|_| invalid_input("byte-order flag must be a decimal byte"))?;
    let bytes = parse_hex(
        fields
            .next()
            .ok_or_else(|| invalid_input("missing hex input"))?,
    )?;
    if fields.next().is_some() {
        return Err(invalid_input("extra input field"));
    }

    let mut remaining = bytes.as_slice();
    let result = match width {
        "32" => decode_u32_reader(&mut remaining, flag).map(u64::from),
        "64" => decode_u64_reader(&mut remaining, flag),
        _ => return Err(invalid_input("width must be 32 or 64")),
    };
    match result {
        Ok(value) => write!(output, "ok\t{value}"),
        Err(ReaderError::UnexpectedEnd { additional }) => write!(output, "end\t{additional}"),
        Err(ReaderError::RejectedMarker {
            expected_code,
            found_code,
        }) => write!(output, "type\t{expected_code}\t{found_code}"),
    }?;
    write!(
        output,
        "\t{}\t{}\t",
        bytes.len() - remaining.len(),
        remaining.len()
    )?;
    for byte in remaining {
        write!(output, "{byte:02x}")?;
    }
    writeln!(output)
}

fn main() -> io::Result<()> {
    let stdin = io::stdin();
    let mut output = io::BufWriter::new(io::stdout().lock());
    for (index, line) in stdin.lock().lines().enumerate() {
        write_case(&line?, &mut output)
            .map_err(|error| invalid_input(format!("line {}: {error}", index + 1)))?;
    }
    output.flush()
}
