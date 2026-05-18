use super::ArcCell;
use crate::cell::{Cell, CellBuilder, TonCellError};
use crate::TonHash;

pub struct StateInitBuilder {
    code: Option<ArcCell>,
    data: Option<ArcCell>,
    split_depth: bool,
    tick_tock: bool,
    library: bool,
}
pub struct StateInit {
    pub code: Option<ArcCell>,
    pub data: Option<ArcCell>,
}

impl StateInitBuilder {
    pub fn new(code: &ArcCell, data: &ArcCell) -> StateInitBuilder {
        StateInitBuilder {
            code: Some(code.clone()),
            data: Some(data.clone()),
            split_depth: false,
            tick_tock: false,
            library: false,
        }
    }

    pub fn with_library(&mut self, library: bool) -> &mut Self {
        self.library = library;
        self
    }

    pub fn build(&self) -> Result<Cell, TonCellError> {
        let mut builder = CellBuilder::new();
        builder
            .store_bit(self.split_depth)? //Split depth
            .store_bit(self.tick_tock)? //Tick tock
            .store_bit(self.code.is_some())? //Code
            .store_bit(self.data.is_some())? //Data
            .store_bit(self.library)?; //Library
        if let Some(code) = &self.code {
            builder.store_reference(code)?;
        }
        if let Some(data) = &self.data {
            builder.store_reference(data)?;
        }
        builder.build()
    }
}

impl StateInit {
    pub fn create_account_id(code: &ArcCell, data: &ArcCell) -> Result<TonHash, TonCellError> {
        Ok(StateInitBuilder::new(code, data)
            .with_library(false)
            .build()?
            .cell_hash())
    }
}
