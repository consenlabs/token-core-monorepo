use bitstream_io::{BigEndian, BitWrite, BitWriter};
use num_bigint::BigUint;
use num_traits::Zero;

use crate::cell::error::{MapTonCellError, TonCellError};
use crate::cell::{ArcCell, Cell};

pub(crate) const MAX_CELL_BITS: usize = 1023;
pub(crate) const MAX_CELL_REFERENCES: usize = 4;
pub(crate) const MAX_LEVEL_MASK: u32 = 3;

pub struct CellBuilder {
    bit_writer: BitWriter<Vec<u8>, BigEndian>,
    bits_to_write: usize,
    references: Vec<ArcCell>,
    is_cell_exotic: bool,
}

#[derive(Clone, Debug, PartialEq, Copy)]
pub enum EitherCellLayout {
    Native,
    ToRef,
    ToCell,
}

impl CellBuilder {
    pub fn new() -> CellBuilder {
        //==
        let bit_writer = BitWriter::endian(Vec::new(), BigEndian);
        CellBuilder {
            bit_writer,
            bits_to_write: 0,
            references: Vec::new(),
            is_cell_exotic: false,
        }
    }

    pub fn store_bit(&mut self, val: bool) -> Result<&mut Self, TonCellError> {
        self.bit_writer.write_bit(val).map_cell_builder_error()?;
        self.bits_to_write += 1;
        Ok(self)
    }

    pub fn store_u8(&mut self, bit_len: usize, val: u8) -> Result<&mut Self, TonCellError> {
        self.bit_writer
            .write(bit_len as u32, val)
            .map_cell_builder_error()?;
        self.bits_to_write += bit_len;
        Ok(self)
    }

    pub fn store_u32(&mut self, bit_len: usize, val: u32) -> Result<&mut Self, TonCellError> {
        self.bit_writer
            .write(bit_len as u32, val)
            .map_cell_builder_error()?;
        self.bits_to_write += bit_len;
        Ok(self)
    }

    pub fn store_i32(&mut self, bit_len: usize, val: i32) -> Result<&mut Self, TonCellError> {
        self.bit_writer
            .write(bit_len as u32, val)
            .map_cell_builder_error()?;
        self.bits_to_write += bit_len;
        Ok(self)
    }

    pub fn store_u64(&mut self, bit_len: usize, val: u64) -> Result<&mut Self, TonCellError> {
        self.bit_writer
            .write(bit_len as u32, val)
            .map_cell_builder_error()?;
        self.bits_to_write += bit_len;
        Ok(self)
    }

    pub fn store_i64(&mut self, bit_len: usize, val: i64) -> Result<&mut Self, TonCellError> {
        self.bit_writer
            .write(bit_len as u32, val)
            .map_cell_builder_error()?;
        self.bits_to_write += bit_len;
        Ok(self)
    }

    pub fn store_uint(&mut self, bit_len: usize, val: &BigUint) -> Result<&mut Self, TonCellError> {
        let minimum_bits_needed = if val.is_zero() { 1 } else { val.bits() } as usize;
        if minimum_bits_needed > bit_len {
            return Err(TonCellError::cell_builder_error(format!(
                "Value {} doesn't fit in {} bits (takes {} bits)",
                val, bit_len, minimum_bits_needed
            )));
        }

        let value_bytes = val.to_bytes_be();
        let first_byte_bit_size = bit_len - (value_bytes.len() - 1) * 8;

        for _ in 0..(first_byte_bit_size - 1) / 32 {
            // fill full-bytes padding
            self.store_u32(32, 0u32)?;
        }

        // fill first byte with required size
        if first_byte_bit_size % 32 == 0 {
            self.store_u32(32, value_bytes[0] as u32)?;
        } else {
            self.store_u32(first_byte_bit_size % 32, value_bytes[0] as u32)
                .map_cell_builder_error()?;
        }

        // fill remaining bytes
        for byte in value_bytes.iter().skip(1) {
            self.store_u8(8, *byte).map_cell_builder_error()?;
        }
        Ok(self)
    }

    pub fn store_byte(&mut self, val: u8) -> Result<&mut Self, TonCellError> {
        self.store_u8(8, val)
    }

    pub fn store_slice(&mut self, slice: &[u8]) -> Result<&mut Self, TonCellError> {
        for val in slice {
            self.store_byte(*val)?;
        }
        Ok(self)
    }

    /// Adds reference to an existing `Cell`.
    ///
    /// The reference is passed as `ArcCell` so it might be references from other cells.
    pub fn store_reference(&mut self, cell: &ArcCell) -> Result<&mut Self, TonCellError> {
        let ref_count = self.references.len() + 1;
        if ref_count > 4 {
            return Err(TonCellError::cell_builder_error(format!(
                "Cell must contain at most 4 references, got {}",
                ref_count
            )));
        }
        self.references.push(cell.clone());
        Ok(self)
    }

    pub fn remaining_bits(&self) -> usize {
        MAX_CELL_BITS - self.bits_to_write
    }

    pub fn build(&mut self) -> Result<Cell, TonCellError> {
        let mut trailing_zeros = 0;
        while !self.bit_writer.byte_aligned() {
            self.bit_writer.write_bit(false).map_cell_builder_error()?;
            trailing_zeros += 1;
        }

        if let Some(vec) = self.bit_writer.writer() {
            let bit_len = vec.len() * 8 - trailing_zeros;
            if bit_len > MAX_CELL_BITS {
                return Err(TonCellError::cell_builder_error(format!(
                    "Cell must contain at most {} bits, got {}",
                    MAX_CELL_BITS, bit_len
                )));
            }
            let ref_count = self.references.len();
            if ref_count > MAX_CELL_REFERENCES {
                return Err(TonCellError::cell_builder_error(format!(
                    "Cell must contain at most 4 references, got {}",
                    ref_count
                )));
            }

            Cell::new(
                vec.clone(),
                bit_len,
                self.references.clone(),
                self.is_cell_exotic,
            )
        } else {
            Err(TonCellError::CellBuilderError(
                "Stream is not byte-aligned".to_string(),
            ))
        }
    }
}

impl Default for CellBuilder {
    fn default() -> Self {
        Self::new()
    }
}
