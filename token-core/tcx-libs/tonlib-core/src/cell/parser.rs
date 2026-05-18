use std::io::Cursor;

use bitstream_io::{BigEndian, BitRead, BitReader, Numeric};

use super::ArcCell;
use crate::cell::{MapTonCellError, TonCellError};

pub struct CellParser<'a> {
    pub(crate) bit_len: usize,
    pub(crate) bit_reader: BitReader<Cursor<&'a [u8]>, BigEndian>,
    pub(crate) references: &'a [ArcCell],
    next_ref: usize,
}

impl<'a> CellParser<'a> {
    pub fn new(bit_len: usize, data: &'a [u8], references: &'a [ArcCell]) -> Self {
        let cursor = Cursor::new(data);
        let bit_reader = BitReader::endian(cursor, BigEndian);
        CellParser {
            bit_len,
            bit_reader,
            references,
            next_ref: 0,
        }
    }

    pub fn remaining_bits(&mut self) -> usize {
        let pos = self.bit_reader.position_in_bits().unwrap_or_default() as usize;
        if self.bit_len > pos {
            self.bit_len - pos
        } else {
            0
        }
    }

    pub fn load_bit(&mut self) -> Result<bool, TonCellError> {
        self.ensure_enough_bits(1)?;
        self.bit_reader.read_bit().map_cell_parser_error()
    }

    pub fn load_u8(&mut self, bit_len: usize) -> Result<u8, TonCellError> {
        self.load_number(bit_len)
    }

    pub fn load_u32(&mut self, bit_len: usize) -> Result<u32, TonCellError> {
        self.load_number(bit_len)
    }

    pub fn load_i32(&mut self, bit_len: usize) -> Result<i32, TonCellError> {
        self.load_number(bit_len)
    }

    pub fn load_u64(&mut self, bit_len: usize) -> Result<u64, TonCellError> {
        self.load_number(bit_len)
    }

    pub fn load_slice(&mut self, slice: &mut [u8]) -> Result<(), TonCellError> {
        self.ensure_enough_bits(slice.len() * 8)?;
        self.bit_reader.read_bytes(slice).map_cell_parser_error()
    }

    pub fn ensure_empty(&mut self) -> Result<(), TonCellError> {
        let remaining_bits = self.remaining_bits();
        let remaining_refs = self.references.len() - self.next_ref;
        // if remaining_bits == 0 && remaining_refs == 0 { // todo: We will restore reference checking in in 0.18
        if remaining_bits == 0 {
            Ok(())
        } else {
            Err(TonCellError::NonEmptyReader {
                remaining_bits,
                remaining_refs,
            })
        }
    }

    pub fn skip_bits(&mut self, num_bits: usize) -> Result<(), TonCellError> {
        self.ensure_enough_bits(num_bits)?;
        self.bit_reader
            .skip(num_bits as u32)
            .map_cell_parser_error()
    }

    fn load_number<N: Numeric>(&mut self, bit_len: usize) -> Result<N, TonCellError> {
        self.ensure_enough_bits(bit_len)?;

        self.bit_reader
            .read::<N>(bit_len as u32)
            .map_cell_parser_error()
    }

    fn ensure_enough_bits(&mut self, bit_len: usize) -> Result<(), TonCellError> {
        if self.remaining_bits() < bit_len {
            return Err(TonCellError::CellParserError(
                "Not enough bits to read".to_owned(),
            ));
        }
        Ok(())
    }
}
