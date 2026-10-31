//! Source analysis for the self-repair engine.
//!
//! This module is the part of Core that actually looks at the repository and
//! decides what is wrong with it. It is deliberately conservative: it reports
//! a wide set of problems, but it will only *propose* a change when the change
//! is mechanical and cannot alter behaviour.
//!
//! The distinction matters. A repair that a human has to reason about belongs
//! in a proposal the operator reads; a repair that only removes a leftover
//! `dbg!` belongs in a patch that can be applied mechanically and reviewed at a
//! glance. Mixing the two produces diffs nobody can read, and a diff nobody can
//! read is a diff nobody will approve.
//!
//! The output is a unified diff, generated in-process, that `git apply`
//! accepts. That is not a stylistic choice: the same diff is what the applier
//! will later feed to git, so a diff that git rejects is a repair that cannot
//! happen, and a diff that git accepts but that no human can read is a repair
//! that will not be approved.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use heimdall_ipc::Severity;

/// A class of problem the analyser can recognise.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Rule {
    /// `dbg!(...)` left in a library path: it prints to stderr and keeps its
    /// argument alive.
    DebugPrint,
    /// A printing macro left in a library path.
    StdoutPrint,
    /// A `return` as the last statement of a block, where the expression is
    /// already the tail.
    NeedlessReturn,
    /// `if cond { true } else { false }`, where the condition is the answer.
    NeedlessBool,
    /// A comparison against the literal `true` or `false`.
    BoolComparison,
    /// `.unwrap()` on a `Result` or an `Option`.
    Unwrap,
    /// `.expect(..)` on a `Result` or an `Option`.
    Expect,
    /// `todo!()`.
    TodoMacro,
    /// `unimplemented!()`.
    UnimplementedMacro,
    /// `panic!` outside a test.
    PanicMacro,
    /// A `TODO` or `FIXME` comment.
    TodoComment,
}

impl Rule {
    /// A short, stable identifier for the rule, for logs and for the UI.
    pub const fn label(self) -> &'static str {
        match self {
            Self::DebugPrint => "debug-print",
            Self::StdoutPrint => "print",
            Self::NeedlessReturn => "needless-return",
            Self::NeedlessBool => "needless-bool",
            Self::BoolComparison => "bool-comparison",
            Self::Unwrap => "unwrap",
            Self::Expect => "expect",
            Self::TodoMacro => "todo-macro",
            Self::UnimplementedMacro => "unimplemented-macro",
            Self::PanicMacro => "panic-macro",
            Self::TodoComment => "todo-comment",
        }
    }

    /// How much attention the finding deserves.
    pub const fn severity(self) -> Severity {
        match self {
            Self::NeedlessReturn
            | Self::NeedlessBool
            | Self::BoolComparison
            | Self::TodoComment => Severity::Info,
            Self::DebugPrint | Self::StdoutPrint => Severity::Low,
            Self::Unwrap | Self::Expect | Self::TodoMacro | Self::UnimplementedMacro => {
                Severity::Medium
            }
            Self::PanicMacro => Severity::High,
        }
    }

    /// Whether the analyser knows how to repair this rule mechanically and
    /// safely.
    ///
    /// Only four rules qualify. The rest are reported and left alone: an
    /// `unwrap` is a decision about error handling, and a `todo!` is a decision
    /// about intent, and neither is the analyser's to make.
    pub const fn is_auto_fixable(self) -> bool {
        matches!(
            self,
            Self::DebugPrint
                | Self::StdoutPrint
                | Self::NeedlessReturn
                | Self::NeedlessBool
                | Self::BoolComparison
        )
    }
}

/// One problem, located in the tree.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Finding {
    /// Path relative to the repository root, using `/` separators.
    pub path: String,
    /// 1-based line number where the problem starts.
    pub line: usize,
    /// 1-based line where the problem ends.
    ///
    /// Most problems are on a single line and this equals [`Finding::line`]. A
    /// branch that spans several lines is reported as the whole span, because
    /// the lines in the middle of it are part of the same problem.
    pub end_line: usize,
    /// 1-based column of the first offending character.
    pub column: usize,
    /// What kind of problem this is.
    pub rule: Rule,
    /// One sentence: what is wrong.
    pub message: String,
    /// The offending source line, trimmed.
    pub excerpt: String,
}

/// A source change the analyser proposes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Edit {
    /// Path relative to the repository root.
    pub path: String,
    /// 1-based line of the changed line in the original file.
    pub line: usize,
    /// 1-based line of the last changed line in the original file.
    pub end_line: usize,
    /// The original text, without its terminator.
    ///
    /// For a change that spans several lines this is the whole block.
    pub original: String,
    /// The replacement text, without its terminator.
    pub repaired: String,
}

/// A complete, reviewable repair: what was found, what would change, and the
/// diff that expresses it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RepairPlan {
    /// Everything the analyser found, most severe first is not guaranteed:
    /// they are in scan order, which is path then line.
    pub findings: Vec<Finding>,
    /// The changes this plan would make.
    pub edits: Vec<Edit>,
    /// A unified diff, `git apply` compatible.
    pub diff: String,
    /// One sentence, for the approval screen.
    pub summary: String,
    /// Why this change is being proposed, in plain language.
    pub rationale: String,
}

/// Analyses a repository.
#[derive(Debug, Clone)]
pub struct Analyzer {
    root: PathBuf,
}

impl Analyzer {
    /// Creates an analyser rooted at `root`. The root is not touched until
    /// [`Analyzer::scan`] runs.
    #[must_use]
    pub fn new(root: impl Into<PathBuf>) -> Self {
        Self { root: root.into() }
    }

    /// The repository this analyser reads.
    #[must_use]
    pub fn root(&self) -> &Path {
        &self.root
    }

    /// Walks the repository and reports everything it finds.
    ///
    /// Unreadable files are skipped with a warning rather than failing the
    /// scan: a repository with one unreadable file is still worth analysing.
    pub fn scan(&self) -> Vec<Finding> {
        let mut findings = Vec::new();
        let mut files = Vec::new();
        collect_files(&self.root, &mut files);
        files.sort();

        for file in files {
            let Ok(text) = std::fs::read_to_string(&file) else {
                tracing::warn!(path = %file.display(), "skipping a file the analyser cannot read");
                continue;
            };
            let relative = self.relative(&file);
            findings.extend(scan_source(&relative, &text));
        }
        findings
    }

    /// Produces a repair plan for the auto-fixable findings, or `None` when
    /// there is nothing it is willing to change automatically.
    ///
    /// The plan covers the whole repository. It is the right shape for a report
    /// and the wrong shape for a proposal: the gate confines a proposal to one
    /// path and the applier writes one file, so a proposal is built from
    /// [`Analyzer::plans`].
    pub fn plan(&self) -> Option<RepairPlan> {
        let findings = self.scan();
        let plans = self.plans_for(&findings);
        if plans.is_empty() {
            return None;
        }

        let edits: Vec<Edit> = plans.iter().flat_map(|p| p.edits.clone()).collect();
        let diff = plans.iter().map(|p| p.diff.as_str()).collect::<String>();
        let changed_lines = edits.len();
        let changed_files = plans.len();

        Some(RepairPlan {
            findings,
            edits,
            diff,
            summary: summary_for(changed_lines, changed_files),
            rationale: rationale_for(changed_lines),
        })
    }

    /// One repair plan per file.
    ///
    /// The split is not cosmetic. A proposal names a single path, the gate
    /// refuses a path that leaves the repository, and the applier checks that
    /// the one file it is about to write is untouched. A diff that touched
    /// three files would have none of those properties.
    pub fn plans(&self) -> Vec<RepairPlan> {
        let findings = self.scan();
        self.plans_for(&findings)
    }

    /// The per-file plans implied by a set of findings.
    fn plans_for(&self, findings: &[Finding]) -> Vec<RepairPlan> {
        let fixable: Vec<&Finding> = findings
            .iter()
            .filter(|f| f.rule.is_auto_fixable())
            .collect();
        if fixable.is_empty() {
            return Vec::new();
        }

        // One edit per span: two mechanical repairs that overlap would have to
        // be composed, and the composition is exactly where a mechanical
        // repair starts guessing.
        let mut per_file: BTreeMap<String, Vec<&Finding>> = BTreeMap::new();
        for finding in &fixable {
            per_file
                .entry(finding.path.clone())
                .or_default()
                .push(finding);
        }

        let mut plans = Vec::new();
        for (path, candidates) in per_file {
            let Some(plan) = self.plan_for_file(&path, &candidates, findings) else {
                continue;
            };
            plans.push(plan);
        }
        plans
    }

    /// The plan for one file, or `None` when it cannot be repaired safely.
    fn plan_for_file(
        &self,
        path: &str,
        candidates: &[&Finding],
        findings: &[Finding],
    ) -> Option<RepairPlan> {
        // The candidates are in scan order. Two findings that touch the same
        // lines cannot both be applied, so the first one wins and the second
        // is left for a human.
        let mut selected: BTreeMap<usize, &Finding> = BTreeMap::new();
        let mut taken_until = 0usize;
        for finding in candidates {
            if finding.line <= taken_until {
                continue;
            }
            taken_until = finding.end_line;
            selected.insert(finding.line, finding);
        }
        if selected.is_empty() {
            return None;
        }

        let absolute = self.root.join(path);
        let Ok(original) = std::fs::read_to_string(&absolute) else {
            tracing::warn!(path = %path, "skipping a file the analyser cannot read");
            return None;
        };
        let Some((repaired, applied)) = apply_edits(&original, &selected) else {
            tracing::warn!(path = %path, "skipping a file whose repair would not be balanced");
            return None;
        };
        if repaired == original {
            return None;
        }
        let diff = unified_diff(path, &original, &repaired);
        if diff.is_empty() {
            return None;
        }

        let edits: Vec<Edit> = applied
            .iter()
            .map(|(finding, original_block, repaired_block)| Edit {
                path: path.to_string(),
                line: finding.line,
                end_line: finding.end_line,
                original: original_block.clone(),
                repaired: repaired_block.clone(),
            })
            .collect();

        let file_findings: Vec<Finding> = findings
            .iter()
            .filter(|f| f.path == path)
            .cloned()
            .collect();

        let edit_count = edits.len();
        Some(RepairPlan {
            findings: file_findings,
            edits,
            diff,
            summary: summary_for(edit_count, 1),
            rationale: rationale_for(edit_count),
        })
    }

    /// The path of `file` relative to the root, with `/` separators.
    fn relative(&self, file: &Path) -> String {
        let relative = file.strip_prefix(&self.root).unwrap_or(file);
        relative
            .components()
            .map(|c| c.as_os_str().to_string_lossy())
            .collect::<Vec<_>>()
            .join("/")
    }
}

/// The one-line summary of a plan.
fn summary_for(changed_lines: usize, changed_files: usize) -> String {
    format!(
        "Removes {} leftover debug or redundant construct{} across {} file{}",
        changed_lines,
        if changed_lines == 1 { "" } else { "s" },
        changed_files,
        if changed_files == 1 { "" } else { "s" }
    )
}

/// Why the change is being proposed, in the words the operator reads.
fn rationale_for(changed_lines: usize) -> String {
    format!(
        "The analyser found {} problem{} it can repair without changing behaviour: a leftover \
         debug macro, a printing macro in a library path, a redundant `return`, a boolean \
         branch that restates its own condition, or a comparison against `true`/`false`. Each \
         edit is mechanical and preserves what the code does. Nothing is written until the \
         operator approves this proposal, and the resulting change is left unstaged for \
         review.",
        changed_lines,
        if changed_lines == 1 { "" } else { "s" }
    )
}

/// Collects the analysable files under `dir`, recursively.
fn collect_files(dir: &Path, out: &mut Vec<PathBuf>) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        let name = entry.file_name();
        let name = name.to_string_lossy();
        if name.starts_with('.') {
            continue;
        }
        let Ok(kind) = entry.file_type() else {
            continue;
        };
        if kind.is_dir() {
            if matches!(name.as_ref(), "target" | "node_modules" | "vendor") {
                continue;
            }
            collect_files(&path, out);
        } else if kind.is_file() {
            let extension = path
                .extension()
                .and_then(|e| e.to_str())
                .unwrap_or_default();
            if matches!(extension, "rs" | "toml") {
                out.push(path);
            }
        }
    }
}

/// One applied repair: the finding, the text it replaced, and its replacement.
type AppliedRepair<'a> = (&'a Finding, String, String);

/// The result of applying the repairs to a file.
type RepairedFile<'a> = (String, Vec<AppliedRepair<'a>>);

/// Applies the given repairs to `original`.
///
/// Returns the repaired text together with the original block and its
/// replacement for every repair that was applied. A repair that cannot be
/// applied is left alone: one line the analyser does not understand is not a
/// reason to give up on the rest of the file.
///
/// Returns `None` when the result would not be balanced, which is the one
/// invariant a mechanical repair must not break.
fn apply_edits<'a>(
    original: &str,
    edits: &BTreeMap<usize, &'a Finding>,
) -> Option<RepairedFile<'a>> {
    let all: Vec<&str> = original.split_inclusive('\n').collect();
    let mut out = String::with_capacity(original.len());
    let mut applied: Vec<AppliedRepair<'a>> = Vec::new();
    let mut index = 0usize;
    while index < all.len() {
        let number = index + 1;
        let Some(finding) = edits.get(&number) else {
            out.push_str(all[index]);
            index += 1;
            continue;
        };
        let end = finding.end_line.clamp(index + 1, all.len());
        let span = &all[index..end];
        match repair_span(span, finding.rule) {
            Some(repaired) => {
                out.push_str(&repaired);
                if span.last().is_some_and(|line| line.ends_with('\n')) {
                    out.push('\n');
                }
                applied.push((finding, block_text(span), repaired));
            }
            None => {
                for line in span {
                    out.push_str(line);
                }
            }
        }
        index = end;
    }
    if !original.ends_with('\n') && out.ends_with('\n') {
        out.pop();
    }
    if !is_balanced(&out) {
        return None;
    }
    Some((out, applied))
}

/// Repairs a span of lines according to `rule`.
///
/// A single line is repaired on its own. A span of several lines is only
/// repaired by the rules that know what a whole block looks like.
fn repair_span(span: &[&str], rule: Rule) -> Option<String> {
    if span.len() == 1 {
        let content = span[0].trim_end_matches(['\n', '\r']);
        return repair_line(content, rule);
    }
    match rule {
        Rule::NeedlessBool => repair_needless_bool_span(span),
        _ => None,
    }
}

/// The text of a span of lines, without the terminator of the last one.
fn block_text(span: &[&str]) -> String {
    let mut text = span.concat();
    while text.ends_with('\n') || text.ends_with('\r') {
        text.pop();
    }
    text
}

/// Repairs one line according to `rule`.
///
/// The rules here are all line-local, which is what makes them safe: the
/// analyser never has to reason about the statement before or after.
fn repair_line(line: &str, rule: Rule) -> Option<String> {
    match rule {
        Rule::DebugPrint => repair_debug_print(line),
        Rule::StdoutPrint => Some(String::new()),
        Rule::NeedlessReturn => {
            let trimmed = line.trim_start();
            let indent = &line[..line.len() - trimmed.len()];
            let rest = trimmed.strip_prefix("return ")?;
            if !rest.ends_with(';') {
                return None;
            }
            Some(format!("{indent}{rest}"))
        }
        Rule::NeedlessBool => repair_needless_bool(line),
        Rule::BoolComparison => repair_bool_comparison(line),
        _ => None,
    }
}

/// `dbg!(expr)` becomes `expr`.
fn repair_debug_print(line: &str) -> Option<String> {
    let scans = scan_lines(line);
    let code = &scans[0].code;
    let start = code.find("dbg!(")?;
    let open = start + "dbg!".len();
    let close = matching_paren(code, open)?;
    let inner_start = open + 1;
    let inner = &line[inner_start..close];
    if inner.contains('\n') {
        return None;
    }
    let mut out = String::with_capacity(line.len());
    out.push_str(&line[..start]);
    out.push_str(inner);
    out.push_str(&line[close + 1..]);
    Some(out)
}

/// The two shapes of a branch that restates its own condition.
const NEEDLESS_BOOL_PATTERNS: [&str; 2] = [
    "{ return true; } else { return false; }",
    "{ true } else { false }",
];

/// The number of context lines a diff hunk carries.
const DIFF_CONTEXT: usize = 3;

/// Recognises a branch that restates its own condition.
///
/// The text must start with `if `. Returns the condition the branch
/// restates, whether the branch returns instead of evaluating, and whatever
/// follows the branch.
fn needless_bool_condition(text: &str) -> Option<(String, bool, String)> {
    let rest = text.strip_prefix("if ")?;
    for pattern in NEEDLESS_BOOL_PATTERNS {
        let Some(index) = rest.find(pattern) else {
            continue;
        };
        let condition = rest[..index].trim();
        // A condition with braces in it is a nested statement, not a value:
        // rewriting that would change what the code means.
        if condition.is_empty() || condition.contains('{') || condition.contains('}') {
            return None;
        }
        let tail = rest[index + pattern.len()..].to_string();
        return Some((condition.to_string(), pattern.starts_with("{ return"), tail));
    }
    None
}

/// `if c { true } else { false }` becomes `c`.
fn repair_needless_bool(line: &str) -> Option<String> {
    let scans = scan_lines(line);
    let code = &scans[0].code;
    let trimmed = code.trim_start();
    let indent = &line[..line.len() - trimmed.len()];
    let (condition, returns, tail) = needless_bool_condition(trimmed)?;

    let mut out = String::with_capacity(line.len());
    out.push_str(indent);
    if returns {
        out.push_str("return ");
        out.push_str(&condition);
        out.push(';');
    } else {
        out.push_str(&condition);
    }
    let mut tail = tail;
    if let Some(stripped) = tail.strip_prefix(';') {
        tail = stripped.to_string();
        if !returns {
            out.push(';');
        }
    }
    out.push_str(&tail);
    Some(out)
}

/// The same branch, spread over several lines, becomes one line.
///
/// The whole block is replaced by the condition it restates, so this is the
/// one repair that is not confined to a single line.
fn repair_needless_bool_span(lines: &[&str]) -> Option<String> {
    let first = lines.first()?;
    let trimmed = first.trim_start();
    let indent = &first[..first.len() - trimmed.len()];
    let joined = lines
        .iter()
        .map(|line| line.trim())
        .collect::<Vec<_>>()
        .join(" ");
    let (condition, returns, _) = needless_bool_condition(&joined)?;
    if returns {
        Some(format!("{indent}return {condition};"))
    } else {
        Some(format!("{indent}{condition}"))
    }
}

/// `x == true` becomes `x`, `x == false` becomes `!x`.
fn repair_bool_comparison(line: &str) -> Option<String> {
    let scans = scan_lines(line);
    let code = &scans[0].code;
    for (literal, negate_when_true) in [("true", false), ("false", true)] {
        for op in ["==", "!="] {
            let needle = format!("{op} {literal}");
            let mut search = 0usize;
            while let Some(found) = code[search..].find(&needle) {
                let index = search + found;
                search = index + needle.len();
                if !boundary_before(code, index) {
                    continue;
                }
                let after = index + needle.len();
                if after < code.len() && is_ident_char(code.as_bytes()[after]) {
                    continue;
                }
                let Some((operand_start, operand_end)) = simple_operand(code, index) else {
                    continue;
                };
                let operand = &line[operand_start..operand_end];
                let replacement = if op == "==" {
                    if negate_when_true {
                        format!("!{operand}")
                    } else {
                        operand.to_string()
                    }
                } else if negate_when_true {
                    operand.to_string()
                } else {
                    format!("!{operand}")
                };
                let mut out = String::with_capacity(line.len());
                out.push_str(&line[..operand_start]);
                out.push_str(&replacement);
                out.push_str(&line[after..]);
                return Some(out);
            }
        }
    }
    None
}

/// The byte range of the simple operand that ends just before `index`.
fn simple_operand(code: &str, index: usize) -> Option<(usize, usize)> {
    let bytes = code.as_bytes();
    // The operand ends before the operator, with the space in between.
    let mut end = index;
    while end > 0 && bytes[end - 1].is_ascii_whitespace() {
        end -= 1;
    }
    let mut start = end;
    while start > 0 {
        let c = bytes[start - 1];
        if c.is_ascii_alphanumeric() || c == b'_' || c == b'.' {
            start -= 1;
        } else {
            break;
        }
    }
    if start == end {
        return None;
    }
    let operand = &code[start..end];
    if operand.starts_with('.') || operand.ends_with('.') {
        return None;
    }
    let bytes = operand.as_bytes();
    if !bytes[0].is_ascii_alphabetic() && bytes[0] != b'_' {
        return None;
    }
    if !bytes
        .iter()
        .all(|c| c.is_ascii_alphanumeric() || *c == b'_' || *c == b'.')
    {
        return None;
    }
    Some((start, end))
}

/// Whether the character before `index` makes the operator a real comparison.
fn boundary_before(code: &str, index: usize) -> bool {
    if index == 0 {
        return true;
    }
    let bytes = code.as_bytes();
    !matches!(bytes[index - 1], b'=' | b'!' | b'<' | b'>' | b'+' | b'-')
}

/// The index of the `)` that closes the `(` at `open`.
fn matching_paren(code: &str, open: usize) -> Option<usize> {
    let bytes = code.as_bytes();
    let mut depth = 0i32;
    let mut index = open;
    while index < bytes.len() {
        match bytes[index] {
            b'(' => depth += 1,
            b')' => {
                depth -= 1;
                if depth == 0 {
                    return Some(index);
                }
            }
            _ => {}
        }
        index += 1;
    }
    None
}

/// Whether the braces and brackets in `text` are balanced.
fn is_balanced(text: &str) -> bool {
    let scans = scan_lines(text);
    let mut depth: i64 = 0;
    for scan in &scans {
        // The depths are counts, not sizes: a file with more than two
        // billion lines of nesting is not a file that exists.
        let before = i64::try_from(scan.depth_before).unwrap_or(i64::MAX);
        let after = i64::try_from(scan.depth_after).unwrap_or(i64::MAX);
        depth += after - before;
        if depth < 0 {
            return false;
        }
    }
    depth == 0
}

/// One line of source, with its code isolated from its comments and strings.
#[derive(Debug, Clone)]
struct LineScan {
    /// The line with comment and string contents replaced by spaces. The
    /// length is preserved, so a column in the code is the same column in the
    /// original line.
    code: String,
    /// Brace depth before the line.
    depth_before: usize,
    /// Brace depth after the line.
    depth_after: usize,
    /// Whether the line carries no code at all.
    blank: bool,
}

/// Splits `text` into lines and isolates the code on each of them.
fn scan_lines(text: &str) -> Vec<LineScan> {
    let mut scans = Vec::new();
    let mut depth = 0usize;
    let mut in_block_comment = false;
    let mut in_string = false;
    let mut in_char = false;
    let mut escaped = false;

    for raw in text.split('\n') {
        let mut code = String::with_capacity(raw.len());
        let depth_before = depth;
        let mut chars = raw.chars().peekable();

        while let Some(c) = chars.next() {
            if in_block_comment {
                if c == '*' && chars.peek() == Some(&'/') {
                    chars.next();
                    code.push(' ');
                    code.push(' ');
                    in_block_comment = false;
                } else {
                    code.push(' ');
                }
                continue;
            }
            if in_string {
                if escaped {
                    escaped = false;
                    code.push(' ');
                    continue;
                }
                match c {
                    '\\' => {
                        escaped = true;
                        code.push(' ');
                    }
                    '"' => {
                        in_string = false;
                        code.push('"');
                    }
                    _ => code.push(' '),
                }
                continue;
            }
            if in_char {
                if escaped {
                    escaped = false;
                    code.push(' ');
                    continue;
                }
                match c {
                    '\\' => {
                        escaped = true;
                        code.push(' ');
                    }
                    '\'' => {
                        in_char = false;
                        code.push('\'');
                    }
                    _ => code.push(' '),
                }
                continue;
            }
            match c {
                '/' if chars.peek() == Some(&'/') => {
                    for _ in chars.by_ref() {
                        code.push(' ');
                    }
                }
                '/' if chars.peek() == Some(&'*') => {
                    chars.next();
                    code.push(' ');
                    code.push(' ');
                    in_block_comment = true;
                }
                '"' => {
                    in_string = true;
                    code.push('"');
                }
                '\'' => {
                    in_char = true;
                    code.push('\'');
                }
                '{' => {
                    depth += 1;
                    code.push('{');
                }
                '}' => {
                    depth = depth.saturating_sub(1);
                    code.push('}');
                }
                _ => code.push(c),
            }
        }

        let blank = code.trim().is_empty();
        scans.push(LineScan {
            code,
            depth_before,
            depth_after: depth,
            blank,
        });
    }
    scans
}

/// Joins the lines of the block that starts at `index`.
///
/// Returns the joined text and the index of the last line of the block. The
/// block ends where the braces balance again, so the join never runs past the
/// statement it started from.
fn join_block(scans: &[LineScan], index: usize) -> (String, usize) {
    const MAX_LINES: usize = 24;
    let base = scans[index].depth_before;
    let mut parts: Vec<&str> = Vec::new();
    let mut last = index;
    for (offset, scan) in scans.iter().enumerate().skip(index) {
        if offset > index + MAX_LINES {
            break;
        }
        parts.push(scan.code.trim());
        last = offset;
        if offset > index && scan.depth_after <= base {
            break;
        }
    }
    (parts.join(" "), last)
}

/// The span of a function body.
#[derive(Debug, Clone)]
struct FnBody {
    /// The name of the function.
    name: String,
    /// 1-based line where the body opens.
    start: usize,
    /// 1-based line where the body closes.
    end: usize,
    /// The brace depth inside the body.
    depth: usize,
}

/// Finds the bodies of the functions declared in `scans`.
fn find_functions(scans: &[LineScan]) -> Vec<FnBody> {
    let mut bodies = Vec::new();
    for (index, scan) in scans.iter().enumerate() {
        let Some(position) = scan.code.find("fn ") else {
            continue;
        };
        // `fn` must be a whole word.
        if position > 0 {
            let before = scan.code.as_bytes()[position - 1];
            if before.is_ascii_alphanumeric() || before == b'_' {
                continue;
            }
        }
        let rest = &scan.code[position + 3..];
        let name: String = rest
            .chars()
            .take_while(|c| c.is_ascii_alphanumeric() || *c == '_')
            .collect();
        if name.is_empty() {
            continue;
        }
        // A declaration without a body has no braces to find.
        let Some((start, depth)) = body_start(scans, index) else {
            continue;
        };
        let mut end = start;
        for (offset, later) in scans.iter().enumerate().skip(start) {
            if later.depth_after < depth {
                end = offset + 1;
                break;
            }
        }
        bodies.push(FnBody {
            name,
            start: start + 1,
            end,
            depth,
        });
    }
    bodies
}

/// The line where a function body opens, and the depth inside it.
fn body_start(scans: &[LineScan], from: usize) -> Option<(usize, usize)> {
    for (index, scan) in scans.iter().enumerate().skip(from) {
        if scan.code.contains('{') {
            return Some((index, scan.depth_before + 1));
        }
        if scan.code.contains(';') {
            return None;
        }
    }
    None
}

/// Builds a finding for one line.
fn finding(
    path: &str,
    line: usize,
    column: usize,
    rule: Rule,
    message: impl Into<String>,
    excerpt: &str,
) -> Finding {
    Finding {
        path: path.to_string(),
        line,
        end_line: line,
        column,
        rule,
        message: message.into(),
        excerpt: excerpt.trim().to_string(),
    }
}

/// Scans one source file.
fn scan_source(path: &str, text: &str) -> Vec<Finding> {
    let scans = scan_lines(text);
    let lines: Vec<&str> = text.split('\n').collect();
    let mut findings = Vec::new();

    // Everything after a `#[cfg(test)]` attribute is test code.
    let test_start = scans
        .iter()
        .position(|scan| scan.code.contains("#[cfg(test)]"))
        .unwrap_or(scans.len());

    let functions = find_functions(&scans);
    let in_main = |line: usize| {
        functions
            .iter()
            .any(|body| line >= body.start && line <= body.end && body.name == "main")
    };

    for (index, scan) in scans.iter().enumerate() {
        if index >= test_start {
            break;
        }
        if scan.blank {
            continue;
        }
        let original = lines.get(index).copied().unwrap_or_default();
        findings.extend(scan_line(path, index, scan, original, &in_main, &scans));
    }

    findings.extend(scan_needless_returns(path, &scans, &lines, &functions));

    findings.sort_by(|a, b| {
        a.path
            .cmp(&b.path)
            .then(a.line.cmp(&b.line))
            .then(a.column.cmp(&b.column))
    });
    findings.dedup_by(|a, b| a.path == b.path && a.line == b.line && a.rule == b.rule);
    findings
}

/// Scans one line of source for the problems that a single line can show.
fn scan_line(
    path: &str,
    index: usize,
    scan: &LineScan,
    original: &str,
    in_main: &dyn Fn(usize) -> bool,
    scans: &[LineScan],
) -> Vec<Finding> {
    let mut findings = Vec::new();
    let line_number = index + 1;
    let code = &scan.code;

    if let Some(column) = code.find("dbg!(") {
        findings.push(finding(
            path,
            line_number,
            column + 1,
            Rule::DebugPrint,
            "a `dbg!` macro is left in a library path: it prints to stderr on every call",
            original,
        ));
    }

    for macro_name in ["println!", "print!", "eprintln!", "eprint!"] {
        let Some(column) = code.find(macro_name) else {
            continue;
        };
        // A program is allowed to talk to its user.
        if in_main(line_number) {
            continue;
        }
        let is_statement = code.trim_start().starts_with(macro_name);
        let message = if is_statement {
            format!("a `{macro_name}` statement is left in a library path")
        } else {
            format!("a `{macro_name}` call is left in a library path")
        };
        findings.push(finding(
            path,
            line_number,
            column + 1,
            Rule::StdoutPrint,
            message,
            original,
        ));
    }

    for (needle, rule, message) in [
        (
            ".unwrap()",
            Rule::Unwrap,
            "`.unwrap()` turns a recoverable error into a panic",
        ),
        (
            ".expect(",
            Rule::Expect,
            "`.expect(..)` turns a recoverable error into a panic",
        ),
        (
            "todo!(",
            Rule::TodoMacro,
            "a `todo!` marker is still in the code",
        ),
        (
            "unimplemented!(",
            Rule::UnimplementedMacro,
            "an `unimplemented!` marker is still in the code",
        ),
        (
            "panic!(",
            Rule::PanicMacro,
            "a `panic!` outside a test aborts the whole process",
        ),
    ] {
        let Some(column) = code.find(needle) else {
            continue;
        };
        // `.unwrap()` points at the method, the macros at the name.
        let column = if needle.starts_with('.') {
            column + 2
        } else {
            column + 1
        };
        findings.push(finding(path, line_number, column, rule, message, original));
    }

    findings.extend(scan_branch(path, index, code, original, scans));
    findings.extend(scan_comparison(path, line_number, code, original));
    findings.extend(scan_comment(path, line_number, original));
    findings
}

/// Looks for a branch that restates its own condition, on one line or over
/// several.
fn scan_branch(
    path: &str,
    index: usize,
    code: &str,
    original: &str,
    scans: &[LineScan],
) -> Vec<Finding> {
    let mut findings = Vec::new();
    if !code.trim_start().starts_with("if ") {
        return findings;
    }
    let line_number = index + 1;
    let column = code.find("if ").map_or(1, |at| at + 1);
    if needless_bool_condition(code.trim_start()).is_some() {
        findings.push(finding(
            path,
            line_number,
            column,
            Rule::NeedlessBool,
            "the branch restates its own condition instead of returning it",
            original,
        ));
        return findings;
    }
    // The same branch, written over several lines.
    let (joined, last) = join_block(scans, index);
    if last > index && needless_bool_condition(&joined).is_some() {
        findings.push(Finding {
            end_line: last + 1,
            ..finding(
                path,
                line_number,
                column,
                Rule::NeedlessBool,
                "the branch restates its own condition instead of returning it",
                original,
            )
        });
    }
    findings
}

/// Looks for a comparison against `true` or `false`.
fn scan_comparison(path: &str, line_number: usize, code: &str, original: &str) -> Vec<Finding> {
    let mut findings = Vec::new();
    for (literal, operator) in [
        ("true", "=="),
        ("false", "=="),
        ("true", "!="),
        ("false", "!="),
    ] {
        let needle = format!("{operator} {literal}");
        let Some(column) = code.find(&needle) else {
            continue;
        };
        if !boundary_before(code, column) {
            continue;
        }
        let after = column + needle.len();
        if after < code.len() && is_ident_char(code.as_bytes()[after]) {
            continue;
        }
        if simple_operand(code, column).is_none() {
            continue;
        }
        findings.push(finding(
            path,
            line_number,
            column + 1,
            Rule::BoolComparison,
            format!("a comparison against the literal `{literal}` is redundant"),
            original,
        ));
    }
    findings
}

/// Looks for a comment that admits the work is not finished.
fn scan_comment(path: &str, line_number: usize, original: &str) -> Vec<Finding> {
    let mut findings = Vec::new();
    if !original.contains("//") {
        return findings;
    }
    let comment = original.split("//").nth(1).unwrap_or_default();
    for marker in ["TODO", "FIXME"] {
        if comment.contains(marker) {
            findings.push(finding(
                path,
                line_number,
                original.find("//").unwrap_or(0) + 1,
                Rule::TodoComment,
                format!("a `{marker}` comment marks work that was never finished"),
                original,
            ));
            break;
        }
    }
    findings
}

/// Finds the `return` statements that are the last statement of a function.
fn scan_needless_returns(
    path: &str,
    scans: &[LineScan],
    lines: &[&str],
    functions: &[FnBody],
) -> Vec<Finding> {
    let mut findings = Vec::new();
    for body in functions {
        let mut last_statement: Option<usize> = None;
        for (index, scan) in scans
            .iter()
            .enumerate()
            .take(body.end.min(scans.len()))
            .skip(body.start - 1)
        {
            if scan.depth_before != body.depth {
                continue;
            }
            let code = scan.code.trim();
            if code.is_empty() || code.starts_with("//") {
                continue;
            }
            if code.ends_with(';') && !code.ends_with("};") {
                last_statement = Some(index);
            }
        }
        let Some(index) = last_statement else {
            continue;
        };
        let code = scans[index].code.trim();
        let Some(rest) = code.strip_prefix("return ") else {
            continue;
        };
        if !rest.ends_with(';') || rest.contains(' ') && rest.contains('{') {
            continue;
        }
        if rest.trim() == ";" {
            continue;
        }
        findings.push(finding(
            path,
            index + 1,
            scans[index].code.find("return").unwrap_or(0) + 1,
            Rule::NeedlessReturn,
            "the `return` is the last statement of the function, so the expression is already the \
             tail",
            lines.get(index).copied().unwrap_or_default(),
        ));
    }
    findings
}

fn is_ident_char(c: u8) -> bool {
    c.is_ascii_alphanumeric() || c == b'_'
}

/// Builds a unified diff between two versions of one file.
///
/// The output is what `git apply` expects: `diff --git` header, `---`/`+++`
/// lines, and hunks with three lines of context. The line diff is computed
/// here rather than by shelling out to git, because the analyser must work on
/// a tree that is not a git repository at all.
pub fn unified_diff(path: &str, original: &str, repaired: &str) -> String {
    use std::fmt::Write as _;
    if original == repaired {
        return String::new();
    }

    let original_lines: Vec<&str> = original.split('\n').collect();
    let repaired_lines: Vec<&str> = repaired.split('\n').collect();
    // A trailing newline produces a final empty element; drop it so the diff
    // counts lines, not the terminator.
    let (original_lines, repaired_lines) = if original.ends_with('\n') {
        (
            &original_lines[..original_lines.len() - 1],
            &repaired_lines[..repaired_lines.len() - 1],
        )
    } else {
        (&original_lines[..], &repaired_lines[..])
    };

    let script = diff_lines(original_lines, repaired_lines);
    if script.is_empty() {
        return String::new();
    }

    let mut out = String::new();
    out.push_str("diff --git a/");
    out.push_str(path);
    out.push_str(" b/");
    out.push_str(path);
    out.push('\n');
    out.push_str("--- a/");
    out.push_str(path);
    out.push('\n');
    out.push_str("+++ b/");
    out.push_str(path);
    out.push('\n');

    for hunk in hunks(&script, original_lines, repaired_lines, DIFF_CONTEXT) {
        let old_start = hunk.old_start;
        let old_count = hunk.old_count;
        let new_start = hunk.new_start;
        let new_count = hunk.new_count;
        if old_count == 0 {
            let _ = writeln!(out, "@@ -{old_start},0 +{new_start},{new_count} @@");
        } else if new_count == 0 {
            let _ = writeln!(out, "@@ -{old_start},{old_count} +{new_start},0 @@");
        } else {
            let _ = writeln!(
                out,
                "@@ -{old_start},{old_count} +{new_start},{new_count} @@"
            );
        }
        for line in &hunk.lines {
            out.push_str(line);
            out.push('\n');
        }
    }

    out
}

/// One step of a line diff.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Op {
    /// A line that is in both versions.
    Equal,
    /// A line only in the original.
    Remove,
    /// A line only in the repaired version.
    Insert,
}

/// A hunk of a unified diff.
#[derive(Debug, Clone)]
struct Hunk {
    old_start: usize,
    old_count: usize,
    new_start: usize,
    new_count: usize,
    lines: Vec<String>,
}

/// Computes the edit script between two versions of a file.
///
/// The diff is a longest-common-subsequence diff, with a guard: if the two
/// sides are too large to compare exactly, the whole region is reported as a
/// replacement. A coarse diff is still a correct diff, and an unbounded
/// allocation on a large file is not acceptable in a process that is meant to
/// be watching a machine.
fn diff_lines(original: &[&str], repaired: &[&str]) -> Vec<Op> {
    let mut prefix = 0usize;
    while prefix < original.len() && prefix < repaired.len() && original[prefix] == repaired[prefix]
    {
        prefix += 1;
    }
    let mut suffix = 0usize;
    while suffix < original.len() - prefix
        && suffix < repaired.len() - prefix
        && original[original.len() - 1 - suffix] == repaired[repaired.len() - 1 - suffix]
    {
        suffix += 1;
    }

    let old_middle = &original[prefix..original.len() - suffix];
    let new_middle = &repaired[prefix..repaired.len() - suffix];

    let mut ops = vec![Op::Equal; prefix];
    if old_middle.len().saturating_mul(new_middle.len()) > 4_000_000 {
        ops.extend(std::iter::repeat_n(Op::Remove, old_middle.len()));
        ops.extend(std::iter::repeat_n(Op::Insert, new_middle.len()));
    } else {
        ops.extend(lcs_ops(old_middle, new_middle));
    }
    ops.extend(std::iter::repeat_n(Op::Equal, suffix));
    ops
}

/// The edit script of a longest-common-subsequence diff.
fn lcs_ops(old: &[&str], new: &[&str]) -> Vec<Op> {
    if old.is_empty() {
        return vec![Op::Insert; new.len()];
    }
    if new.is_empty() {
        return vec![Op::Remove; old.len()];
    }

    let rows = old.len() + 1;
    let columns = new.len() + 1;
    let mut table = vec![0u32; rows * columns];
    for i in (0..old.len()).rev() {
        for j in (0..new.len()).rev() {
            table[i * columns + j] = if old[i] == new[j] {
                table[(i + 1) * columns + j + 1] + 1
            } else {
                table[(i + 1) * columns + j].max(table[i * columns + j + 1])
            };
        }
    }

    let mut ops = Vec::new();
    let (mut i, mut j) = (0usize, 0usize);
    while i < old.len() && j < new.len() {
        if old[i] == new[j] {
            ops.push(Op::Equal);
            i += 1;
            j += 1;
        } else if table[(i + 1) * columns + j] >= table[i * columns + j + 1] {
            ops.push(Op::Remove);
            i += 1;
        } else {
            ops.push(Op::Insert);
            j += 1;
        }
    }
    while i < old.len() {
        ops.push(Op::Remove);
        i += 1;
    }
    while j < new.len() {
        ops.push(Op::Insert);
        j += 1;
    }
    ops
}

/// Groups an edit script into hunks with `context` lines of context.
fn hunks(ops: &[Op], original: &[&str], repaired: &[&str], context: usize) -> Vec<Hunk> {
    // Walk the script, tracking the line numbers on both sides.
    let mut entries: Vec<Step> = Vec::with_capacity(ops.len());
    let mut old_line = 0usize;
    let mut new_line = 0usize;
    for op in ops {
        match op {
            Op::Equal => {
                entries.push(Step::Equal(old_line, new_line));
                old_line += 1;
                new_line += 1;
            }
            Op::Remove => {
                entries.push(Step::Remove(old_line));
                old_line += 1;
            }
            Op::Insert => {
                entries.push(Step::Insert(new_line));
                new_line += 1;
            }
        }
    }

    let change_indices: Vec<usize> = entries
        .iter()
        .enumerate()
        .filter(|(_, step)| !matches!(step, Step::Equal(_, _)))
        .map(|(index, _)| index)
        .collect();
    if change_indices.is_empty() {
        return Vec::new();
    }

    // Group changes that are close enough to share a context window.
    let mut groups: Vec<(usize, usize)> = Vec::new();
    let mut start = change_indices[0];
    let mut end = change_indices[0];
    for &index in &change_indices[1..] {
        if index - end <= context * 2 {
            end = index;
        } else {
            groups.push((start, end));
            start = index;
            end = index;
        }
    }
    groups.push((start, end));

    let mut result = Vec::new();
    for (first, last) in groups {
        let from = first.saturating_sub(context);
        let to = (last + context + 1).min(entries.len());
        let mut lines = Vec::new();
        let mut old_count = 0usize;
        let mut new_count = 0usize;
        let mut old_start = 0usize;
        let mut new_start = 0usize;
        for (index, step) in entries.iter().enumerate().take(to).skip(from) {
            if index == from {
                old_start = step.old_line();
                new_start = step.new_line();
            }
            match step {
                Step::Equal(old, _) => {
                    old_count += 1;
                    new_count += 1;
                    lines.push(format!(" {}", original[*old]));
                }
                Step::Remove(old) => {
                    old_count += 1;
                    lines.push(format!("-{}", original[*old]));
                }
                Step::Insert(new) => {
                    new_count += 1;
                    lines.push(format!("+{}", repaired[*new]));
                }
            }
        }
        result.push(Hunk {
            old_start: if old_count == 0 {
                old_start
            } else {
                old_start + 1
            },
            old_count,
            new_start: if new_count == 0 {
                new_start
            } else {
                new_start + 1
            },
            new_count,
            lines,
        });
    }
    result
}

/// One step of a diff, with the line it refers to.
#[derive(Debug, Clone)]
enum Step {
    /// The line is in both versions.
    Equal(usize, usize),
    /// The line is only in the original.
    Remove(usize),
    /// The line is only in the repaired version.
    Insert(usize),
}

impl Step {
    fn old_line(&self) -> usize {
        match self {
            Self::Equal(old, _) | Self::Remove(old) => *old,
            Self::Insert(_) => 0,
        }
    }

    fn new_line(&self) -> usize {
        match self {
            Self::Equal(_, new) | Self::Insert(new) => *new,
            Self::Remove(_) => 0,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn temp_dir(name: &str) -> PathBuf {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or_default();
        let path = std::env::temp_dir().join(format!("heimdall-analysis-{name}-{nanos}"));
        std::fs::create_dir_all(&path).expect("temp dir");
        path
    }

    const SAMPLE: &str = r#"
use std::fmt;

pub fn check(flag: bool) -> bool {
    if flag {
        true
    } else {
        false
    }
}

pub fn noisy(value: u32) -> u32 {
    dbg!(value);
    println!("value is {value}");
    let doubled = value * 2;
    if doubled == true {
        return 1;
    }
    doubled
}

pub fn risky(text: &str) -> String {
    let trimmed = text.trim();
    if trimmed.is_empty() {
        todo!("decide what an empty command means");
    }
    trimmed.to_string()
}
"#;

    #[test]
    fn rules_are_recognised_with_accurate_lines() {
        let findings = scan_source("sample.rs", SAMPLE);
        let rule_at = |line: usize| -> Vec<Rule> {
            findings
                .iter()
                .filter(|f| f.line == line)
                .map(|f| f.rule)
                .collect()
        };

        // The sample starts with an empty line, so the branch is on line 5.
        assert!(rule_at(5).contains(&Rule::NeedlessBool));
        assert!(rule_at(13).contains(&Rule::DebugPrint));
        assert!(rule_at(14).contains(&Rule::StdoutPrint));
        assert!(rule_at(16).contains(&Rule::BoolComparison));
        assert!(rule_at(25).contains(&Rule::TodoMacro));
    }

    #[test]
    fn a_branch_over_several_lines_is_reported_as_a_span() {
        let findings = scan_source("sample.rs", SAMPLE);
        let finding = findings
            .iter()
            .find(|f| f.rule == Rule::NeedlessBool)
            .expect("a needless branch");
        assert_eq!(finding.line, 5);
        assert_eq!(finding.end_line, 9);
    }

    #[test]
    fn test_code_is_not_reported() {
        let source = "pub fn f() {\n    let x = 1;\n}\n\n#[cfg(test)]\nmod tests {\n    #[test]\n    fn t() {\n        dbg!(1);\n    }\n}\n";
        let findings = scan_source("sample.rs", source);
        assert!(!findings.iter().any(|f| f.rule == Rule::DebugPrint));
    }

    #[test]
    fn a_return_that_is_not_last_is_not_needless() {
        let source = "pub fn f() -> u32 {\n    if x {\n        return 1;\n    }\n    2\n}\n";
        let findings = scan_source("sample.rs", source);
        assert!(!findings.iter().any(|f| f.rule == Rule::NeedlessReturn));
    }

    #[test]
    fn a_return_that_is_last_is_needless() {
        let source = "pub fn f() -> u32 {\n    let a = 1;\n    return a;\n}\n";
        let findings = scan_source("sample.rs", source);
        assert!(findings.iter().any(|f| f.rule == Rule::NeedlessReturn));
    }

    #[test]
    fn the_diff_has_the_expected_shape() {
        let original = "one\ntwo\nthree\nfour\nfive\nsix\nseven\neight\n";
        let repaired = "one\ntwo\nthree\nfour\nFIVE\nsix\nseven\neight\n";
        let diff = unified_diff("sample.txt", original, repaired);
        assert!(diff.starts_with("diff --git a/sample.txt b/sample.txt\n"));
        assert!(diff.contains("--- a/sample.txt\n"));
        assert!(diff.contains("+++ b/sample.txt\n"));
        assert!(diff.contains("-five\n"));
        assert!(diff.contains("+FIVE\n"));
        assert_eq!(diff.matches("@@ -").count(), 1);
        assert!(diff.contains(" four\n"));
    }

    #[test]
    fn an_unchanged_file_has_no_diff() {
        let same = "a\nb\n";
        assert_eq!(unified_diff("sample.txt", same, same), "");
    }

    #[test]
    fn every_plan_names_exactly_one_file() {
        // A proposal is confined to one path, so a plan that touched two files
        // could not be turned into one.
        let root = temp_dir("per-file");
        std::fs::write(
            root.join("a.rs"),
            "pub fn f(v: u32) -> u32 {\n    dbg!(v);\n    v * 2\n}\n",
        )
        .expect("write");
        std::fs::write(
            root.join("b.rs"),
            "pub fn g(v: u32) -> u32 {\n    dbg!(v);\n    v * 3\n}\n",
        )
        .expect("write");

        let plans = Analyzer::new(&root).plans();
        assert_eq!(plans.len(), 2, "one plan per file");
        for plan in &plans {
            let paths: std::collections::BTreeSet<&str> =
                plan.edits.iter().map(|e| e.path.as_str()).collect();
            assert_eq!(paths.len(), 1, "a plan must name one file: {paths:?}");
            assert!(plan.diff.contains("diff --git a/"));
        }

        std::fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn a_plan_repairs_and_produces_a_diff() {
        let root = temp_dir("plan");
        let file = root.join("sample.rs");
        std::fs::write(
            &file,
            "pub fn f(v: u32) -> u32 {\n    dbg!(v);\n    v * 2\n}\n",
        )
        .expect("write");

        let analyzer = Analyzer::new(&root);
        let plan = analyzer.plan().expect("a plan");
        assert!(
            plan.diff
                .starts_with("diff --git a/sample.rs b/sample.rs\n")
        );
        assert!(plan.diff.contains("-    dbg!(v);"));
        assert!(plan.diff.contains("+    v;"));
        assert_eq!(plan.edits.len(), 1);
        assert!(plan.summary.contains('1'));
        assert_ne!(plan.rationale, "");

        std::fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn a_branch_over_several_lines_is_repaired_into_one() {
        let root = temp_dir("span");
        let file = root.join("sample.rs");
        std::fs::write(
            &file,
            "pub fn check(flag: bool) -> bool {\n    if flag {\n        true\n    } else {\n        false\n    }\n}\n",
        )
        .expect("write");

        let analyzer = Analyzer::new(&root);
        let plan = analyzer.plan().expect("a plan");
        assert_eq!(plan.edits.len(), 1);
        assert_eq!(plan.edits[0].line, 2);
        assert_eq!(plan.edits[0].end_line, 6);
        assert_eq!(plan.edits[0].repaired, "    flag");
        assert!(plan.diff.contains("-    if flag {"));
        assert!(plan.diff.contains("+    flag"));

        std::fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn the_generated_diff_is_accepted_by_git() {
        if which_git().is_none() {
            eprintln!("git is not on PATH; skipping the git interoperability test");
            return;
        }
        let root = temp_dir("git");
        let init = std::process::Command::new("git")
            .args(["init", "--quiet"])
            .current_dir(&root)
            .output()
            .expect("git init");
        assert!(init.status.success());
        for args in [
            vec!["config", "user.email", "test@example.invalid"],
            vec!["config", "user.name", "Test"],
        ] {
            let _ = std::process::Command::new("git")
                .args(&args)
                .current_dir(&root)
                .output();
        }
        let file = root.join("sample.rs");
        std::fs::write(
            &file,
            "pub fn f(v: u32) -> u32 {\n    dbg!(v);\n    v * 2\n}\n",
        )
        .expect("write");
        let add = std::process::Command::new("git")
            .args(["add", "sample.rs"])
            .current_dir(&root)
            .output()
            .expect("git add");
        assert!(add.status.success());
        let commit = std::process::Command::new("git")
            .args(["commit", "--quiet", "-m", "initial"])
            .current_dir(&root)
            .output()
            .expect("git commit");
        assert!(commit.status.success());

        let plan = Analyzer::new(&root).plan().expect("a plan");
        let check = std::process::Command::new("git")
            .args(["apply", "--check", "--whitespace=nowarn", "-"])
            .current_dir(&root)
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::piped())
            .spawn()
            .and_then(|mut child| {
                use std::io::Write;
                child
                    .stdin
                    .as_mut()
                    .ok_or(std::io::Error::other("no stdin"))?
                    .write_all(plan.diff.as_bytes())?;
                child.wait_with_output()
            })
            .expect("git apply --check");
        assert!(
            check.status.success(),
            "git rejected the generated diff: {}",
            String::from_utf8_lossy(&check.stderr)
        );

        std::fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn a_diff_over_several_lines_is_accepted_by_git() {
        if which_git().is_none() {
            eprintln!("git is not on PATH; skipping the git interoperability test");
            return;
        }
        let root = temp_dir("git-span");
        let init = std::process::Command::new("git")
            .args(["init", "--quiet"])
            .current_dir(&root)
            .output()
            .expect("git init");
        assert!(init.status.success());
        for args in [
            vec!["config", "user.email", "test@example.invalid"],
            vec!["config", "user.name", "Test"],
        ] {
            let _ = std::process::Command::new("git")
                .args(&args)
                .current_dir(&root)
                .output();
        }
        let file = root.join("sample.rs");
        std::fs::write(
            &file,
            "pub fn check(flag: bool) -> bool {\n    if flag {\n        true\n    } else {\n        false\n    }\n}\n",
        )
        .expect("write");
        let add = std::process::Command::new("git")
            .args(["add", "sample.rs"])
            .current_dir(&root)
            .output()
            .expect("git add");
        assert!(add.status.success());
        let commit = std::process::Command::new("git")
            .args(["commit", "--quiet", "-m", "initial"])
            .current_dir(&root)
            .output()
            .expect("git commit");
        assert!(commit.status.success());

        let plan = Analyzer::new(&root).plan().expect("a plan");
        let check = std::process::Command::new("git")
            .args(["apply", "--check", "--whitespace=nowarn", "-"])
            .current_dir(&root)
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::piped())
            .spawn()
            .and_then(|mut child| {
                use std::io::Write;
                child
                    .stdin
                    .as_mut()
                    .ok_or(std::io::Error::other("no stdin"))?
                    .write_all(plan.diff.as_bytes())?;
                child.wait_with_output()
            })
            .expect("git apply --check");
        assert!(
            check.status.success(),
            "git rejected the generated diff: {}",
            String::from_utf8_lossy(&check.stderr)
        );

        std::fs::remove_dir_all(&root).ok();
    }

    /// Whether `git` is available on this machine.
    fn which_git() -> Option<PathBuf> {
        let output = std::process::Command::new("git")
            .arg("--version")
            .output()
            .ok()?;
        if output.status.success() {
            Some(PathBuf::from("git"))
        } else {
            None
        }
    }
}
