use core::fmt::Display;

use alloc::{
    string::{String, ToString},
    vec::Vec,
};

#[derive(Debug, Clone)]
pub struct PathOld {
    inner: Vec<String>,
    is_relative: bool,
}

impl From<&str> for PathOld {
    fn from(v: &str) -> Self {
        let is_relative = !v.starts_with("/");
        Self {
            inner: v
                .split("/")
                .filter(|s| s.len() > 0)
                .map(|s| s.to_string())
                .collect(),
            is_relative,
        }
    }
}

impl From<String> for PathOld {
    fn from(v: String) -> Self {
        Self::from(v.as_str())
    }
}

// you can call to_string() or println!("{}", path) to get path concated by "/"
impl Display for PathOld {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        if self.is_relative {
            write!(f, "{}", &self.inner.join("/"))
        } else {
            write!(f, "{}", "/".to_string() + &self.inner.join("/"))
        }
    }
}

impl PathOld {
    fn push(&mut self, s: &str) {
        self.inner.push(s.to_string());
    }

    #[allow(unused)]
    fn pop(&mut self) -> Option<String> {
        self.inner.pop() /* .unwrap_or(String::new()) */
    }

    pub fn new_absolute() -> Self {
        Self {
            inner: Vec::new(),
            is_relative: false,
        }
    }

    // 返回最后一级的名字
    pub fn get_name(&self) -> String {
        self.inner.last().unwrap_or(&String::new()).to_string()
    }

    pub fn len(&self) -> usize {
        self.inner.len()
    }

    pub fn is_relative(&self) -> bool {
        self.is_relative
    }

    pub fn get_inner(&self) -> &Vec<String> {
        &self.inner
    }

    pub fn clone_and_append(&self, s: &str) -> Self {
        let mut ret = self.clone();
        ret.push(s);
        ret
    }
}
