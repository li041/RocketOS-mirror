extern crate alloc;
use alloc::collections::BTreeMap;
use alloc::string::String;
use alloc::vec::Vec;

pub struct Environment {
    vars: BTreeMap<String, String>,
}

impl Environment {
    pub fn new() -> Self {
        let mut env = Environment {
            vars: BTreeMap::new(),
        };

        // 初始化一些默认环境变量
        env.vars
            .insert(String::from("PATH"), String::from("/bin:/usr/bin"));
        env.vars.insert(String::from("HOME"), String::from("/"));
        env.vars
            .insert(String::from("SHELL"), String::from("/bin/shell"));
        env.vars.insert(String::from("USER"), String::from("root"));
        env.vars.insert(
            String::from("PATH"),
            String::from("/bin:/usr/bin:/glibc/ltp/testcases/bin"),
        );

        env
    }

    pub fn set(&mut self, key: String, value: String) {
        self.vars.insert(key, value);
    }

    pub fn get(&self, key: &str) -> Option<&String> {
        self.vars.get(key)
    }

    pub fn unset(&mut self, key: &str) {
        self.vars.remove(key);
    }

    pub fn list_all(&self) -> Vec<(String, String)> {
        self.vars
            .iter()
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect()
    }

    // 变量替换，支持 $VAR 和 ${VAR} 格式
    pub fn expand_variables(&self, input: &str) -> String {
        let mut result = String::new();
        let mut chars = input.chars().peekable();

        while let Some(ch) = chars.next() {
            if ch == '$' {
                if let Some(&'{') = chars.peek() {
                    // ${VAR} 格式
                    chars.next(); // 消费 '{'
                    let mut var_name = String::new();
                    while let Some(&ch) = chars.peek() {
                        if ch == '}' {
                            chars.next(); // 消费 '}'
                            break;
                        }
                        var_name.push(chars.next().unwrap());
                    }
                    if let Some(value) = self.get(&var_name) {
                        result.push_str(value);
                    }
                } else {
                    // $VAR 格式
                    let mut var_name = String::new();
                    while let Some(&ch) = chars.peek() {
                        if ch.is_alphanumeric() || ch == '_' {
                            var_name.push(chars.next().unwrap());
                        } else {
                            break;
                        }
                    }
                    if !var_name.is_empty() {
                        if let Some(value) = self.get(&var_name) {
                            result.push_str(value);
                        }
                    } else {
                        result.push('$');
                    }
                }
            } else {
                result.push(ch);
            }
        }

        result
    }
}
