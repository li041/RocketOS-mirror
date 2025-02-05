use alloc::{
    ffi::CString,
    string::{String, ToString},
    vec::Vec,
};
use user_lib::{execve, exit};

pub struct Command {
    tokens: Vec<CString>,
}

impl From<&str> for Command {
    fn from(line: &str) -> Self {
        let tokens: Vec<String> = line.split(' ').map(|s| s.to_string()).collect();
        let tokens: Vec<CString> = tokens
            .iter()
            .map(|s| CString::new(s.as_str()).unwrap())
            .collect();
        Command { tokens }
    }
}

impl Command {
    pub fn get_name(&self) -> &str {
        self.tokens[0].to_str().unwrap()
    }

    /// excluding the command name
    pub fn get_args(&self) -> Vec<&str> {
        if self.tokens.len() < 2 {
            return Vec::new();
        }
        self.tokens[1..]
            .iter()
            .map(|s| s.to_str().unwrap())
            .collect()
    }

    /// including the command name
    pub fn get_argv(&self) -> Vec<&str> {
        self.tokens.iter().map(|s| s.to_str().unwrap()).collect()
    }

    pub fn exec(&self) {
        execve(self.get_name(), &self.get_argv(), &[]);
        exit(-1);
    }
}
