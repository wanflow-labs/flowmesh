// SPDX-License-Identifier: Apache-2.0
//! Similarity detection on comments and strings: any run of `min_tokens` consecutive tokens that matches the reference corpus counts as similar.

use crate::extract::{Lang, extract};
use std::collections::HashMap;
use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};
use std::path::{Path, PathBuf};
use std::process::ExitCode;

pub struct SourceFile {
    pub path: PathBuf,
    pub lang: Lang,
    pub content: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Match {
    pub file: PathBuf,
    pub line: usize,
    pub reference_file: PathBuf,
    pub reference_line: usize,
    pub excerpt: String,
}

pub fn tokens(text: &str) -> Vec<String> {
    text.split(|c: char| !(c.is_alphanumeric() || c == '_'))
        .filter(|t| !t.is_empty())
        .map(str::to_lowercase)
        .collect()
}

fn window_hash(window: &[String]) -> u64 {
    let mut h = DefaultHasher::new();
    window.hash(&mut h);
    h.finish()
}

fn normalized(text: &str) -> String {
    tokens(text).join(" ")
}

pub fn find_matches(
    reference: &[SourceFile],
    scan: &[SourceFile],
    min_tokens: usize,
    allow: &[String],
) -> Vec<Match> {
    let mut index: HashMap<u64, (PathBuf, usize)> = HashMap::new();
    for file in reference {
        for frag in extract(&file.content, file.lang) {
            for window in tokens(&frag.text).windows(min_tokens) {
                index
                    .entry(window_hash(window))
                    .or_insert_with(|| (file.path.clone(), frag.line));
            }
        }
    }
    let allow: Vec<String> = allow.iter().map(|a| normalized(a)).collect();
    let mut found = Vec::new();
    for file in scan {
        for frag in extract(&file.content, file.lang) {
            for window in tokens(&frag.text).windows(min_tokens) {
                let Some((ref_file, ref_line)) = index.get(&window_hash(window)) else {
                    continue;
                };
                let excerpt = window.join(" ");
                if allow.iter().any(|a| a.contains(&excerpt)) {
                    continue;
                }
                found.push(Match {
                    file: file.path.clone(),
                    line: frag.line,
                    reference_file: ref_file.clone(),
                    reference_line: *ref_line,
                    excerpt,
                });
                break;
            }
        }
    }
    found
}

const SKIP_DIRS: &[&str] = &["target", ".git", "node_modules"];

fn collect(root: &Path, out: &mut Vec<SourceFile>) -> std::io::Result<()> {
    let meta = std::fs::metadata(root)?;
    if meta.is_file() {
        if let Some(lang) = Lang::from_path(root) {
            let content = String::from_utf8_lossy(&std::fs::read(root)?).into_owned();
            out.push(SourceFile {
                path: root.to_path_buf(),
                lang,
                content,
            });
        }
        return Ok(());
    }
    for entry in std::fs::read_dir(root)? {
        let path = entry?.path();
        let skip = path
            .file_name()
            .and_then(|n| n.to_str())
            .is_some_and(|n| SKIP_DIRS.contains(&n));
        if !skip && !path.is_symlink() {
            collect(&path, out)?;
        }
    }
    Ok(())
}

struct Args {
    references: Vec<PathBuf>,
    scans: Vec<PathBuf>,
    allowlist: Option<PathBuf>,
    min_tokens: usize,
}

fn parse_args(args: &[String]) -> Result<Args, String> {
    let mut parsed = Args {
        references: Vec::new(),
        scans: Vec::new(),
        allowlist: None,
        min_tokens: 12,
    };
    let mut it = args.iter();
    while let Some(arg) = it.next() {
        match arg.as_str() {
            "--reference" => parsed
                .references
                .push(it.next().ok_or("--reference needs a value")?.into()),
            "--allowlist" => {
                parsed.allowlist = Some(it.next().ok_or("--allowlist needs a value")?.into())
            }
            "--min-tokens" => {
                let v = it.next().ok_or("--min-tokens needs a value")?;
                parsed.min_tokens = v.parse().map_err(|_| format!("bad --min-tokens: {v}"))?;
            }
            other => parsed.scans.push(other.into()),
        }
    }
    if parsed.references.is_empty() || parsed.scans.is_empty() || parsed.min_tokens == 0 {
        return Err("need at least one --reference and one scan dir".into());
    }
    Ok(parsed)
}

fn load_allowlist(path: &Path) -> std::io::Result<Vec<String>> {
    Ok(std::fs::read_to_string(path)?
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .map(String::from)
        .collect())
}

fn load_all(roots: &[PathBuf]) -> Result<Vec<SourceFile>, String> {
    let mut out = Vec::new();
    for root in roots {
        collect(root, &mut out).map_err(|e| format!("reading {}: {e}", root.display()))?;
    }
    Ok(out)
}

pub fn run(args: &[String]) -> ExitCode {
    let result = parse_args(args).and_then(|args| {
        let reference = load_all(&args.references)?;
        let scan = load_all(&args.scans)?;
        let allow = match &args.allowlist {
            Some(p) => load_allowlist(p).map_err(|e| format!("reading {}: {e}", p.display()))?,
            None => Vec::new(),
        };
        let found = find_matches(&reference, &scan, args.min_tokens, &allow);
        println!(
            "similarity: {} reference files, {} scanned files, {} matches (min {} tokens)",
            reference.len(),
            scan.len(),
            found.len(),
            args.min_tokens
        );
        for m in &found {
            println!(
                "{}:{} ~ {}:{}\n    {}",
                m.file.display(),
                m.line,
                m.reference_file.display(),
                m.reference_line,
                m.excerpt
            );
        }
        Ok(found.is_empty())
    });
    match result {
        Ok(true) => ExitCode::SUCCESS,
        Ok(false) => ExitCode::from(1),
        Err(e) => {
            eprintln!("similarity: {e}");
            ExitCode::from(2)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const COPIED: &str = "the quick brown fox jumps over the lazy dog while seven \
                          silent owls watch from the old oak tree";

    fn rs(path: &str, content: &str) -> SourceFile {
        SourceFile {
            path: path.into(),
            lang: Lang::Rust,
            content: content.into(),
        }
    }

    fn go(path: &str, content: &str) -> SourceFile {
        SourceFile {
            path: path.into(),
            lang: Lang::Go,
            content: content.into(),
        }
    }

    #[test]
    fn tokens_lowercase_alnum() {
        assert_eq!(
            tokens("Hello, World_2 x-y"),
            vec!["hello", "world_2", "x", "y"]
        );
    }

    #[test]
    fn detects_copied_comment_across_languages() {
        let reference = vec![go("ref/a.go", &format!("package a\n\n// {COPIED}\n"))];
        let scan = vec![rs("src/b.rs", &format!("fn x() {{}}\n/* {COPIED} */\n"))];
        let found = find_matches(&reference, &scan, 12, &[]);
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].file, PathBuf::from("src/b.rs"));
        assert_eq!(found[0].line, 2);
        assert_eq!(found[0].reference_file, PathBuf::from("ref/a.go"));
        assert_eq!(found[0].reference_line, 3);
    }

    #[test]
    fn detects_copied_string_literal() {
        let reference = vec![go("ref/a.go", &format!("x := \"{COPIED}\""))];
        let scan = vec![rs("src/b.rs", &format!("let e = \"{COPIED}\";"))];
        assert_eq!(find_matches(&reference, &scan, 12, &[]).len(), 1);
    }

    #[test]
    fn ignores_code_outside_comments_and_strings() {
        let reference = vec![go("ref/a.go", &format!("// {COPIED}"))];
        let scan = vec![rs("src/b.rs", "fn the_quick_brown() {}")];
        assert!(find_matches(&reference, &scan, 12, &[]).is_empty());
    }

    #[test]
    fn below_threshold_is_not_reported() {
        let eleven = "// one two three four five six seven eight nine ten eleven";
        let reference = vec![go("ref/a.go", eleven)];
        let scan = vec![rs("src/b.rs", eleven)];
        assert!(find_matches(&reference, &scan, 12, &[]).is_empty());
    }

    #[test]
    fn allowlist_suppresses_match() {
        let reference = vec![go("ref/a.go", &format!("// {COPIED}"))];
        let scan = vec![rs("src/b.rs", &format!("// {COPIED}"))];
        let allow = vec![COPIED.to_string()];
        assert!(find_matches(&reference, &scan, 12, &allow).is_empty());
    }

    #[test]
    fn one_report_per_fragment() {
        let twice = format!("{COPIED} {COPIED}");
        let reference = vec![go("ref/a.go", &format!("// {twice}"))];
        let scan = vec![rs("src/b.rs", &format!("// {twice}"))];
        assert_eq!(find_matches(&reference, &scan, 12, &[]).len(), 1);
    }
}
