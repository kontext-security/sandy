use serde::{Deserialize, Serialize};

use crate::OsValue;

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct CommandSpec {
    pub program: OsValue,
    pub arguments: Vec<OsValue>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct EnvironmentEntry {
    pub key: OsValue,
    pub value: OsValue,
}
