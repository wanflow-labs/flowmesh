// SPDX-License-Identifier: Apache-2.0
//! 从 Rust/Go 源码中抽取注释和字符串字面量，供相似度比对使用。

use std::path::Path;

/// 抽取出的一段文本及其起始行号（从 1 开始）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Fragment {
    pub line: usize,
    pub text: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Lang {
    Rust,
    Go,
}

impl Lang {
    pub fn from_path(path: &Path) -> Option<Lang> {
        match path.extension()?.to_str()? {
            "rs" => Some(Lang::Rust),
            "go" => Some(Lang::Go),
            _ => None,
        }
    }
}

pub fn extract(src: &str, lang: Lang) -> Vec<Fragment> {
    let mut lx = Lexer {
        chars: src.chars().collect(),
        i: 0,
        line: 1,
        out: Vec::new(),
    };
    lx.run(lang);
    lx.out
}

struct Lexer {
    chars: Vec<char>,
    i: usize,
    line: usize,
    out: Vec<Fragment>,
}

impl Lexer {
    fn peek(&self, k: usize) -> Option<char> {
        self.chars.get(self.i + k).copied()
    }

    fn bump(&mut self) -> Option<char> {
        let c = self.chars.get(self.i).copied()?;
        self.i += 1;
        if c == '\n' {
            self.line += 1;
        }
        Some(c)
    }

    fn bump_n(&mut self, n: usize) {
        for _ in 0..n {
            self.bump();
        }
    }

    fn push(&mut self, line: usize, text: String) {
        self.out.push(Fragment { line, text });
    }

    fn prev(&self) -> Option<char> {
        self.i
            .checked_sub(1)
            .and_then(|p| self.chars.get(p))
            .copied()
    }

    fn run(&mut self, lang: Lang) {
        while let Some(c) = self.peek(0) {
            match (c, self.peek(1)) {
                ('/', Some('/')) => self.line_comment(),
                ('/', Some('*')) => self.block_comment(lang == Lang::Rust),
                ('"', _) => self.quoted_string(),
                ('`', _) if lang == Lang::Go => self.go_raw_string(),
                ('\'', _) => self.char_literal(lang),
                ('r', Some('"' | '#')) if lang == Lang::Rust && self.raw_string_ahead() => {
                    self.rust_raw_string()
                }
                _ => {
                    self.bump();
                }
            }
        }
    }

    fn line_comment(&mut self) {
        let line = self.line;
        self.bump_n(2);
        let mut text = String::new();
        while let Some(c) = self.peek(0) {
            if c == '\n' {
                break;
            }
            text.push(c);
            self.bump();
        }
        self.push(line, text);
    }

    fn block_comment(&mut self, nests: bool) {
        let line = self.line;
        self.bump_n(2);
        let mut depth = 1usize;
        let mut text = String::new();
        while let Some(c) = self.peek(0) {
            if c == '*' && self.peek(1) == Some('/') {
                depth -= 1;
                self.bump_n(2);
                if depth == 0 {
                    break;
                }
                text.push_str("*/");
                continue;
            }
            if nests && c == '/' && self.peek(1) == Some('*') {
                depth += 1;
                text.push_str("/*");
                self.bump_n(2);
                continue;
            }
            text.push(c);
            self.bump();
        }
        self.push(line, text);
    }

    fn quoted_string(&mut self) {
        let line = self.line;
        self.bump();
        let mut text = String::new();
        while let Some(c) = self.bump() {
            match c {
                '\\' => {
                    text.push(c);
                    if let Some(n) = self.bump() {
                        text.push(n);
                    }
                }
                '"' => break,
                _ => text.push(c),
            }
        }
        self.push(line, text);
    }

    fn go_raw_string(&mut self) {
        let line = self.line;
        self.bump();
        let mut text = String::new();
        while let Some(c) = self.bump() {
            if c == '`' {
                break;
            }
            text.push(c);
        }
        self.push(line, text);
    }

    /// 字符字面量直接跳过；Rust 的生命周期标记（`'a`）只前进一个字符。
    fn char_literal(&mut self, lang: Lang) {
        if self.peek(1) == Some('\\') {
            self.bump_n(2);
            while let Some(c) = self.bump() {
                if c == '\'' {
                    break;
                }
            }
            return;
        }
        if self.peek(2) == Some('\'') || lang == Lang::Go {
            self.bump_n(3);
            return;
        }
        self.bump();
    }

    /// `r"`、`r#"`、`br#"` 开头的原始字符串；`for"` 这类标识符结尾的 r 不算。
    fn raw_string_ahead(&self) -> bool {
        if let Some(p) = self.prev() {
            if (p.is_alphanumeric() || p == '_') && p != 'b' {
                return false;
            }
        }
        let mut k = 1;
        while self.peek(k) == Some('#') {
            k += 1;
        }
        self.peek(k) == Some('"')
    }

    fn rust_raw_string(&mut self) {
        let line = self.line;
        self.bump();
        let mut hashes = 0usize;
        while self.peek(0) == Some('#') {
            hashes += 1;
            self.bump();
        }
        self.bump();
        let mut text = String::new();
        while let Some(c) = self.peek(0) {
            if c == '"' && (1..=hashes).all(|k| self.peek(k) == Some('#')) {
                self.bump_n(1 + hashes);
                break;
            }
            text.push(c);
            self.bump();
        }
        self.push(line, text);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn texts(src: &str, lang: Lang) -> Vec<(usize, String)> {
        extract(src, lang)
            .into_iter()
            .map(|f| (f.line, f.text))
            .collect()
    }

    #[test]
    fn rust_line_comment_and_string() {
        let src = "fn a() {}\n// hello world\nlet s = \"text here\";\n";
        assert_eq!(
            texts(src, Lang::Rust),
            vec![(2, " hello world".into()), (3, "text here".into())]
        );
    }

    #[test]
    fn rust_nested_block_comment() {
        let src = "/* outer /* inner */ still */ x";
        assert_eq!(
            texts(src, Lang::Rust),
            vec![(1, " outer /* inner */ still ".into())]
        );
    }

    #[test]
    fn rust_raw_string_keeps_quotes() {
        let src = r####"let s = r#"a "quoted" b"#;"####;
        assert_eq!(texts(src, Lang::Rust), vec![(1, "a \"quoted\" b".into())]);
    }

    #[test]
    fn rust_lifetimes_are_not_char_literals() {
        let src = "fn f<'a>(x: &'a str) -> &'a str { \"s\" }";
        assert_eq!(texts(src, Lang::Rust), vec![(1, "s".into())]);
    }

    #[test]
    fn rust_quote_char_literal_does_not_open_string() {
        let src = "let c = '\"'; let d = '\\''; let s = \"ok\";";
        assert_eq!(texts(src, Lang::Rust), vec![(1, "ok".into())]);
    }

    #[test]
    fn rust_escaped_quote_inside_string() {
        let src = "let s = \"say \\\"hi\\\" now\";";
        assert_eq!(
            texts(src, Lang::Rust),
            vec![(1, "say \\\"hi\\\" now".into())]
        );
    }

    #[test]
    fn go_raw_string_block_comment_and_rune() {
        let src = "r := '\"'\n/* block\ncomment */\nx := `raw \"s\"`\n";
        assert_eq!(
            texts(src, Lang::Go),
            vec![(2, " block\ncomment ".into()), (4, "raw \"s\"".into())]
        );
    }

    #[test]
    fn go_block_comment_does_not_nest() {
        let src = "/* a /* b */ c := \"x\"";
        assert_eq!(
            texts(src, Lang::Go),
            vec![(1, " a /* b ".into()), (1, "x".into())]
        );
    }

    #[test]
    fn lang_from_path() {
        assert_eq!(Lang::from_path(Path::new("a/b.rs")), Some(Lang::Rust));
        assert_eq!(Lang::from_path(Path::new("a/b.go")), Some(Lang::Go));
        assert_eq!(Lang::from_path(Path::new("a/b.txt")), None);
    }
}
