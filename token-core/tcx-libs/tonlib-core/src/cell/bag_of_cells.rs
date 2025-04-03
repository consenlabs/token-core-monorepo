use std::sync::Arc;

use base64::engine::general_purpose::STANDARD;

use crate::cell::*;

#[derive(PartialEq, Eq, Debug, Clone, Hash)]
pub struct BagOfCells {
    pub roots: Vec<ArcCell>,
}

impl BagOfCells {
    pub fn new(roots: &[ArcCell]) -> BagOfCells {
        BagOfCells {
            roots: roots.to_vec(),
        }
    }

    pub fn single_root(&self) -> Result<&ArcCell, TonCellError> {
        let root_count = self.roots.len();
        if root_count == 1 {
            Ok(&self.roots[0])
        } else {
            Err(TonCellError::CellParserError(format!(
                "Single root expected, got {}",
                root_count
            )))
        }
    }

    pub fn parse(serial: &[u8]) -> Result<BagOfCells, TonCellError> {
        let raw = RawBagOfCells::parse(serial)?;
        let num_cells = raw.cells.len();
        let mut cells: Vec<ArcCell> = Vec::with_capacity(num_cells);

        for (cell_index, raw_cell) in raw.cells.into_iter().enumerate().rev() {
            let mut references = Vec::with_capacity(raw_cell.references.len());
            for ref_index in &raw_cell.references {
                if *ref_index <= cell_index {
                    return Err(TonCellError::boc_deserialization_error(
                        "References to previous cells are not supported",
                    ));
                }
                references.push(cells[num_cells - 1 - ref_index].clone());
            }

            let cell = Cell::new(
                raw_cell.data,
                raw_cell.bit_len,
                references,
                raw_cell.is_exotic,
            )
            .map_boc_deserialization_error()?;
            cells.push(cell.to_arc());
        }

        let roots = raw
            .roots
            .into_iter()
            .map(|r| &cells[num_cells - 1 - r])
            .map(Arc::clone)
            .collect();

        Ok(BagOfCells { roots })
    }

    pub fn parse_base64(base64: &str) -> Result<BagOfCells, TonCellError> {
        let bin = STANDARD.decode(base64).map_boc_deserialization_error()?;
        Self::parse(&bin)
    }
}
