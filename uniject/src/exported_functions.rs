pub struct ExportedFunction {
    pub name: String,
    pub address: usize,
}

impl ExportedFunction {
    pub fn new(name: &str, address: usize) -> Self {
        ExportedFunction {
            name: name.to_string(),
            address,
        }
    }
}