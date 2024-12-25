use std::io::Cursor;

use crate::cell::level_mask::LevelMask;
use crate::cell::{MapTonCellError, TonCellError};
use bitstream_io::{BigEndian, ByteRead, ByteReader};

/// Raw representation of Cell.
///
/// References are stored as indices in BagOfCells.
#[derive(PartialEq, Eq, Debug, Clone, Hash)]
pub(crate) struct RawCell {
    pub(crate) data: Vec<u8>,
    pub(crate) bit_len: usize,
    pub(crate) references: Vec<usize>,
    pub(crate) is_exotic: bool,
    level_mask: u32,
}

impl RawCell {
    pub(crate) fn new(
        data: Vec<u8>,
        bit_len: usize,
        references: Vec<usize>,
        level_mask: u32,
        is_exotic: bool,
    ) -> Self {
        Self {
            data,
            bit_len,
            references,
            level_mask: level_mask & 7,
            is_exotic,
        }
    }
}

/// Raw representation of BagOfCells.
///
/// `cells` must be topologically sorted.
#[derive(PartialEq, Eq, Debug, Clone, Hash)]
pub(crate) struct RawBagOfCells {
    pub(crate) cells: Vec<RawCell>,
    pub(crate) roots: Vec<usize>,
}

const GENERIC_BOC_MAGIC: u32 = 0xb5ee9c72;
const _INDEXED_BOC_MAGIC: u32 = 0x68ff65f3;
const _INDEXED_CRC32_MAGIC: u32 = 0xacc3a728;

impl RawBagOfCells {
    pub(crate) fn parse(serial: &[u8]) -> Result<RawBagOfCells, TonCellError> {
        let cursor = Cursor::new(serial);

        let mut reader: ByteReader<Cursor<&[u8]>, BigEndian> =
            ByteReader::endian(cursor, BigEndian);
        // serialized_boc#b5ee9c72
        let magic = reader.read::<u32>().map_boc_deserialization_error()?;

        let (has_idx, has_crc32c, _has_cache_bits, size) = match magic {
            GENERIC_BOC_MAGIC => {
                // has_idx:(## 1) has_crc32c:(## 1) has_cache_bits:(## 1) flags:(## 2) { flags = 0 }
                let header = reader.read::<u8>().map_boc_deserialization_error()?;
                let has_idx = (header >> 7) & 1 == 1;
                let has_crc32c = (header >> 6) & 1 == 1;
                let has_cache_bits = (header >> 5) & 1 == 1;
                // size:(## 3) { size <= 4 }
                let size = header & 0b0000_0111;

                (has_idx, has_crc32c, has_cache_bits, size)
            }
            magic => {
                return Err(TonCellError::boc_deserialization_error(format!(
                    "Unsupported cell magic number: {:#}",
                    magic
                )));
            }
        };
        //   off_bytes:(## 8) { off_bytes <= 8 }
        let off_bytes = reader.read::<u8>().map_boc_deserialization_error()?;
        //cells:(##(size * 8))
        let cells = read_var_size(&mut reader, size)?;
        //   roots:(##(size * 8)) { roots >= 1 }
        let roots = read_var_size(&mut reader, size)?;
        //   absent:(##(size * 8)) { roots + absent <= cells }
        let _absent = read_var_size(&mut reader, size)?;
        //   tot_cells_size:(##(off_bytes * 8))
        let _tot_cells_size = read_var_size(&mut reader, off_bytes)?;
        //   root_list:(roots * ##(size * 8))
        let mut root_list = vec![];
        for _ in 0..roots {
            root_list.push(read_var_size(&mut reader, size)?)
        }
        //   index:has_idx?(cells * ##(off_bytes * 8))
        let mut index = vec![];
        if has_idx {
            for _ in 0..cells {
                index.push(read_var_size(&mut reader, off_bytes)?)
            }
        }
        //   cell_data:(tot_cells_size * [ uint8 ])
        let mut cell_vec = Vec::with_capacity(cells);

        for _ in 0..cells {
            let cell = read_cell(&mut reader, size)?;
            cell_vec.push(cell);
        }
        //   crc32c:has_crc32c?uint32
        let _crc32c = if has_crc32c {
            reader.read::<u32>().map_boc_deserialization_error()?
        } else {
            0
        };
        // TODO: Check crc32

        Ok(RawBagOfCells {
            cells: cell_vec,
            roots: root_list,
        })
    }
}

fn read_cell(
    reader: &mut ByteReader<Cursor<&[u8]>, BigEndian>,
    size: u8,
) -> Result<RawCell, TonCellError> {
    let d1 = reader.read::<u8>().map_boc_deserialization_error()?;
    let d2 = reader.read::<u8>().map_boc_deserialization_error()?;

    let ref_num = d1 & 0b111;
    let is_exotic = (d1 & 0b1000) != 0;
    let has_hashes = (d1 & 0b10000) != 0;
    let level_mask = (d1 >> 5) as u32;
    let data_size = ((d2 >> 1) + (d2 & 1)).into();
    let full_bytes = (d2 & 0x01) == 0;

    if has_hashes {
        let hash_count = LevelMask::new(level_mask).hash_count();
        let skip_size = hash_count * (32 + 2);

        // TODO: check depth and hashes
        reader
            .skip(skip_size as u32)
            .map_boc_deserialization_error()?;
    }

    let mut data = reader
        .read_to_vec(data_size)
        .map_boc_deserialization_error()?;

    let data_len = data.len();
    let padding_len = if data_len > 0 && !full_bytes {
        // Fix last byte,
        // see https://github.com/toncenter/tonweb/blob/c2d5d0fc23d2aec55a0412940ce6e580344a288c/src/boc/BitString.js#L302
        let num_zeros = data[data_len - 1].trailing_zeros();
        if num_zeros >= 8 {
            return Err(TonCellError::boc_deserialization_error(
                "Last byte of binary must not be zero if full_byte flag is not set",
            ));
        }
        data[data_len - 1] &= !(1 << num_zeros);
        num_zeros + 1
    } else {
        0
    };
    let bit_len = data.len() * 8 - padding_len as usize;
    let mut references: Vec<usize> = Vec::new();
    for _ in 0..ref_num {
        references.push(read_var_size(reader, size)?);
    }
    let cell = RawCell::new(data, bit_len, references, level_mask, is_exotic);
    Ok(cell)
}

fn read_var_size(
    reader: &mut ByteReader<Cursor<&[u8]>, BigEndian>,
    n: u8,
) -> Result<usize, TonCellError> {
    let bytes = reader
        .read_to_vec(n.into())
        .map_boc_deserialization_error()?;

    let mut result = 0;
    for &byte in &bytes {
        result <<= 8;
        result |= usize::from(byte);
    }
    Ok(result)
}
