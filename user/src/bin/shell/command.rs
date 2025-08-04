extern crate alloc;
use alloc::{
    ffi::CString,
    string::{String, ToString},
    vec,
    vec::Vec,
};
use user_lib::{chdir, execve, exit};

use super::environment::Environment;

pub struct Pipeline {
    commands: Vec<Command>,
}

impl From<&str> for Pipeline {
    fn from(line: &str) -> Self {
        let mut commands = Vec::new();
        for segment in line.split('|') {
            let cmd = Command::from(segment.trim());
            commands.push(cmd);
        }
        Pipeline { commands }
    }
}

pub struct Command {
    tokens: Vec<CString>,
    stdin_redirect: Option<CString>,
    stdout_redirect: Option<CString>,
    append: bool,
}

// pub fn parse_pipeline(line: &str) -> Vec<Command> {
//     line.split('|').map(str::trim).map(Command::from).collect()
// }
/// 忽略引号中的|
pub fn parse_pipeline(line: &str) -> Vec<Command> {
    let mut commands = Vec::new();
    let mut current = String::new();
    let mut in_quotes = false;

    for c in line.chars() {
        match c {
            '|' if !in_quotes => {
                commands.push(Command::from(current.trim()));
                current.clear();
            }
            '"' => {
                in_quotes = !in_quotes;
                current.push(c);
            }
            _ => current.push(c),
        }
    }
    if !current.is_empty() {
        commands.push(Command::from(current.trim()));
    }
    commands
}

/// 辅助函数：从字符迭代器中读取下一个 token（跳过空格）
fn parse_next_token(chars: &mut core::iter::Peekable<core::str::Chars>) -> Option<CString> {
    let mut token = String::new();
    while let Some(&c) = chars.peek() {
        if c == ' ' {
            chars.next(); // 跳过空格
            if !token.is_empty() {
                break;
            }
        } else {
            token.push(chars.next().unwrap());
        }
    }
    if token.is_empty() {
        None
    } else {
        Some(CString::new(token).unwrap())
    }
}

impl From<&str> for Command {
    fn from(line: &str) -> Self {
        let mut tokens = Vec::new();
        let mut current_token = String::new();
        let mut in_quote = None; // None = not in quote, Some('"') or Some('\'') = in quote
        let mut chars = line.chars().peekable();

        // 重定向相关字段
        let mut stdin_redirect = None;
        let mut stdout_redirect = None;
        let mut append = false;

        while let Some(c) = chars.next() {
            match c {
                // Entering a quote
                '"' | '\'' if in_quote.is_none() => {
                    in_quote = Some(c);
                }
                // Exiting a quote
                '"' | '\'' if in_quote == Some(c) => {
                    in_quote = None;
                }
                // 空格分割(仅在非引号中)
                ' ' if in_quote.is_none() => {
                    if !current_token.is_empty() {
                        // 检查是否是重定向符号（>、<、>>）
                        match current_token.as_str() {
                            ">" => {
                                if let Some(next_token) = parse_next_token(&mut chars) {
                                    stdout_redirect = Some(next_token);
                                }
                            }
                            ">>" => {
                                if let Some(next_token) = parse_next_token(&mut chars) {
                                    stdout_redirect = Some(next_token);
                                    append = true;
                                }
                            }
                            "<" => {
                                if let Some(next_token) = parse_next_token(&mut chars) {
                                    stdin_redirect = Some(next_token);
                                }
                            }
                            _ => tokens.push(current_token),
                        }
                        current_token = String::new();
                    }
                }
                // Handle escape sequences (e.g., \n, \t, \", \\)
                '\\' if in_quote.is_some() => {
                    if let Some(next_c) = chars.next() {
                        match next_c {
                            'n' => current_token.push('\n'),
                            't' => current_token.push('\t'),
                            'r' => current_token.push('\r'),
                            '"' => current_token.push('"'),
                            '\'' => current_token.push('\''),
                            '\\' => current_token.push('\\'),
                            _ => {
                                // Unknown escape sequence, treat as literal (e.g., `\x` -> `x`)
                                current_token.push(next_c);
                            }
                        }
                    }
                }
                // Default: add character to current token
                _ => {
                    current_token.push(c);
                }
            }
        }

        // Add the last token if it exists
        if !current_token.is_empty() {
            tokens.push(current_token);
        }

        // Convert Vec<String> to Vec<CString>
        let tokens = tokens
            .into_iter()
            .map(|s| CString::new(s).unwrap())
            .collect();
        Command {
            tokens,
            stdin_redirect,
            stdout_redirect,
            append,
        }
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

    // 将环境变量转换为 C 格式的字符串数组
    fn get_env(&self, env: &Environment) -> Vec<CString> {
        let mut env_strings = Vec::new();

        // 遍历所有环境变量，转换为 "KEY=VALUE" 格式
        for (key, value) in env.list_all() {
            let env_str = key + "=" + &value;
            if let Ok(c_str) = CString::new(env_str) {
                env_strings.push(c_str);
            }
        }
        env_strings
    }
    // pub fn exec(&self) {
    //     execve(self.get_name(), &self.get_argv(), &[]);
    //     exit(-1);
    // }
    pub fn exec(&self, env: &Environment) {
        use user_lib::OpenFlags;
        use user_lib::{close, dup3, open};

        // 输入重定向
        if let Some(file) = &self.stdin_redirect {
            let fd = open(file, OpenFlags::RDONLY);
            if fd >= 0 {
                dup3(fd as usize, 0, 0); // 将 stdin 重定向到文件
                close(fd as usize);
            }
        }

        // 输出重定向
        if let Some(file) = &self.stdout_redirect {
            let flags = if self.append {
                OpenFlags::WRONLY | OpenFlags::CREATE | OpenFlags::APPEND
            } else {
                OpenFlags::WRONLY | OpenFlags::CREATE | OpenFlags::TRUNC
            };
            let fd = open(file, flags);
            if fd >= 0 {
                dup3(fd as usize, 1, 0); // 将stdout重定向到文件
                close(fd as usize);
            }
        }
        let env_array = self.get_env(env);
        let envp: Vec<&str> = env_array.iter().map(|s| s.to_str().unwrap()).collect();

        // 执行命令
        execve(self.get_name(), &self.get_argv(), &envp);
        exit(-1);
    }
}
