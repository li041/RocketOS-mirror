use alloc::{format, string::{String, ToString}, vec::Vec};
use lazy_static::lazy_static;

// 符号数据
const SYMBOL_DATA: &str = include_str!("symbol.txt");

lazy_static! {
    static ref SYMBOL_TABLE: SymbolTable = init_symbol_table();
}

pub fn lookup_symbol(addr: usize) -> Option<String> {
    SYMBOL_TABLE.lookup_symbol(addr)
        .map(|sym| format!("{}", sym.name))
}


#[derive(Debug, Clone)]
pub struct Symbol {
    pub addr: usize,
    pub name: String,
}

pub struct SymbolTable {
    symbols: Vec<Symbol>,
}

pub fn init_symbol_table() -> SymbolTable {
    let mut table = SymbolTable::new();
    
    for line in SYMBOL_DATA.lines() {
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() >= 2 {
            if let Ok(addr) = usize::from_str_radix(parts[0], 16) {
                table.add_symbol(addr, parts[1].to_string());
            }
        }
    }
    
    table.sort_symbols();
    table
}

impl SymbolTable {
    pub fn new() -> Self {
        Self {
            symbols: Vec::new(),
        }
    }
    
    pub fn lookup_symbol(&self, addr: usize) -> Option<&Symbol> {
        // 使用二分查找找到最接近的符号
        match self.symbols.binary_search_by(|s| s.addr.cmp(&addr)) {
            Ok(idx) => Some(&self.symbols[idx]),
            Err(idx) => {
                if idx > 0 {
                    Some(&self.symbols[idx - 1])
                } else {
                    None
                }
            }
        }
    }
    
    pub fn add_symbol(&mut self, addr: usize, name: String) {
        self.symbols.push(Symbol { addr, name });
    }
    
    pub fn sort_symbols(&mut self) {
        self.symbols.sort_by(|a, b| a.addr.cmp(&b.addr));
    }
}
