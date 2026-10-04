//! Bastion V1 terminal wire contract. Binary frames contain terminal bytes;
//! these JSON text messages carry control information only.
use serde::{Deserialize, Serialize};

#[derive(Debug, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum Control {
    Ready { version: u8, session_id: String },
    Error { message: String },
    Exit { status: Option<i32> },
}

#[derive(Debug, Serialize)]
pub struct Resize {
    #[serde(rename = "type")]
    kind: &'static str,
    version: u8,
    cols: u16,
    rows: u16,
}

impl Resize {
    pub fn new(cols: u16, rows: u16) -> Self {
        Self {
            kind: "resize",
            version: 1,
            cols,
            rows,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn resize_wire_format() {
        assert_eq!(
            serde_json::to_value(Resize::new(120, 40)).unwrap(),
            serde_json::json!({"type": "resize", "version": 1, "cols": 120, "rows": 40})
        );
    }
}
