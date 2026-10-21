//! Turning an approved proposal into a change on disk.
//!
//! # What this module is allowed to do
//!
//! Write exactly one approved diff, to exactly one file, inside the repository,
//! and only when the file is untouched. That is the whole job. The gate has
//! already decided that a human approved *this* content; this module's job is to
//! make sure that applying it cannot clobber something else that happened in the
//! meantime.
//!
//! # Why the tree has to be clean
//!
//! A diff is a statement about the code as it was when the model read it. If the
//! file has been edited since, the patch either fails or -- worse -- applies at
//! the wrong offset and produces code nobody approved. There is no partial
//! credit here: refusing and asking for a re-read is always cheaper than writing
//! a file whose contents no human has seen.
//!
//! # Why git, rather than a patch parser
//!
//! `git apply --check` answers "does this apply cleanly, here, now" using the
//! same implementation a developer's `git apply` would. A hand-rolled parser
//! would have to reproduce git's hunk-matching, its whitespace rules, and its
//! behaviour on malformed patches -- and any difference would be a bug in the
//! one component that writes to source code. Requiring git is a fair trade; a
//! Heimdall that cannot find git refuses to patch rather than guessing.
//!
//! # What it does not do
//!
//! It does not commit, stage, push, or run anything from the diff. The result is
//! left in the working tree as an ordinary unstaged change for a human to
//! review. A tool that rewrote its own source *and* recorded the rewrite as
//! done would be the end of the audit trail.

use std::path::{Component, Path, PathBuf};
use std::process::{Command, Stdio};

use crate::error::{Error, Result};
use crate::gate::Application;

/// Upper bound on a diff. The gate caps proposals too; this is the applier
/// refusing independently, because a patch this size is not a repair.
const MAX_DIFF_BYTES: usize = 1 << 20; // 1 MiB

/// What a successful application did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Applied {
    pub proposal_id: u64,
    pub path: PathBuf,
    pub approved_by: String,
    /// The digest that was authorised. Recorded so the audit trail says which
    /// content was written, not merely that something was.
    pub digest_hex: String,
}

/// Applies approved diffs, inside one repository.
#[derive(Debug, Clone)]
pub struct Applier {
    root: PathBuf,
}

impl Applier {
    #[must_use]
    pub fn new(root: impl Into<PathBuf>) -> Self {
        Self { root: root.into() }
    }

    /// The repository this applier is bound to.
    ///
    /// An applier cannot be pointed at a different repository after
    /// construction: the approval was given for changes to *this* tree.
    pub fn root(&self) -> &Path {
        &self.root
    }

    /// Writes the approved change.
    ///
    /// Order matters here: every check that can refuse runs before anything is
    /// written. A partially applied repair -- one file of three, or a file that
    /// applied and a second that did not -- is the worst outcome available,
    /// because it leaves the repository in a state no approval describes.
    pub fn apply(&self, application: &Application) -> Result<Applied> {
        Self::check_diff_size(application)?;
        let relative = self.resolve_target(&application.target_path)?;

        self.require_repository()?;
        self.require_clean(&[&relative])?;

        // `--check` is the whole point: it answers the question without writing.
        let check = self.git(
            &["apply", "--check", "--whitespace=nowarn", "-"],
            Some(&application.diff),
        )?;
        if !check.success {
            return Err(Error::Apply(format!(
                "the approved diff no longer applies to {}: {}",
                relative.display(),
                first_lines(&check.stderr, 3)
            )));
        }

        let applied = self.git(
            &["apply", "--whitespace=nowarn", "-"],
            Some(&application.diff),
        )?;
        if !applied.success {
            // The check passed and the apply failed. Rare, but it means the tree
            // moved between the two calls.
            return Err(Error::Apply(format!(
                "the diff was verified and then failed to apply: {}",
                first_lines(&applied.stderr, 3)
            )));
        }

        // Confirm what actually happened rather than reporting what was asked
        // for. A git that silently did nothing would otherwise be reported as a
        // successful repair.
        let changed = self.git(
            &["status", "--porcelain", "--", &relative.to_string_lossy()],
            None,
        )?;
        if changed.stdout.trim().is_empty() {
            return Err(Error::Apply(format!(
                "git reported success but {} is unchanged; refusing to record a repair that did not happen",
                relative.display()
            )));
        }

        Ok(Applied {
            proposal_id: application.id,
            path: relative,
            approved_by: application.approved_by.clone(),
            digest_hex: application.approved_digest.iter().fold(
                String::with_capacity(64),
                |mut acc, b| {
                    use std::fmt::Write as _;
                    let _ = write!(acc, "{b:02x}");
                    acc
                },
            ),
        })
    }

    /// Whether `path` is untouched in the working tree.
    ///
    /// Public because the UI shows this *before* the operator approves: the
    /// useful question is not "will this write work" but "is anyone else editing
    /// the file I am about to change".
    pub fn is_clean(&self, path: &str) -> Result<bool> {
        let relative = self.resolve_target(path)?;
        self.require_repository()?;
        let out = self.git(
            &["status", "--porcelain", "--", &relative.to_string_lossy()],
            None,
        )?;
        Ok(out.stdout.trim().is_empty())
    }

    fn check_diff_size(application: &Application) -> Result<()> {
        if application.diff.len() > MAX_DIFF_BYTES {
            return Err(Error::Apply(format!(
                "the diff is {} bytes, over the {MAX_DIFF_BYTES}-byte limit for an automatic repair",
                application.diff.len()
            )));
        }
        Ok(())
    }

    /// Resolves a proposed path to a path inside the repository.
    ///
    /// Every escape route is closed here, because this is the boundary between
    /// "a file in a source tree" and "an arbitrary file on the host": absolute
    /// paths, `..`, and anything that leaves the root after normalisation. A
    /// proposal naming `../../.ssh/authorized_keys` must fail before git is
    /// involved, not be quietly normalised into something that looks fine.
    fn resolve_target(&self, target: &str) -> Result<PathBuf> {
        let candidate = Path::new(target);

        if candidate.is_absolute() {
            return Err(Error::Apply(format!(
                "refusing an absolute path ({target}); targets are relative to the repository"
            )));
        }
        if target.trim().is_empty() {
            return Err(Error::Apply(
                "refusing a proposal that names no file".into(),
            ));
        }

        for component in candidate.components() {
            match component {
                Component::Normal(_) | Component::CurDir => {}
                Component::ParentDir => {
                    return Err(Error::Apply(format!(
                        "refusing a path that climbs out of the repository ({target})"
                    )));
                }
                Component::RootDir | Component::Prefix(_) => {
                    return Err(Error::Apply(format!("refusing a rooted path ({target})")));
                }
            }
        }

        let relative = candidate.to_path_buf();
        // Canonicalise the *parent*, because the file itself may legitimately not
        // exist yet -- a repair that creates a file is a repair.
        let full = self.root.join(&relative);
        if let Some(parent) = full.parent() {
            let parent = canonical(parent);
            if !parent.starts_with(canonical(&self.root)) {
                return Err(Error::Apply(format!(
                    "{target} resolves outside the repository ({}); refusing",
                    parent.display()
                )));
            }
        }

        Ok(relative)
    }

    fn require_repository(&self) -> Result<()> {
        let out = self.git(&["rev-parse", "--show-toplevel"], None)?;
        if !out.success {
            return Err(Error::Apply(format!(
                "{} is not inside a git repository; refusing to patch",
                self.root.display()
            )));
        }
        let toplevel = out.stdout.trim();
        // Guard against being handed a subdirectory: `git apply` would then act
        // on a tree the operator did not think they were approving changes to.
        // Both sides go through `canonical` because git's answer and
        // `Path::canonicalize` describe the same directory in different spellings
        // on Windows -- one verbatim (`\\?\...`), one not.
        if canonical(Path::new(toplevel)) != canonical(&self.root) {
            return Err(Error::Apply(format!(
                "the applier is bound to {} but the repository root is {toplevel}; refusing",
                canonical(&self.root).display()
            )));
        }
        Ok(())
    }

    fn require_clean(&self, paths: &[&PathBuf]) -> Result<()> {
        let mut args = vec!["status".to_string(), "--porcelain".to_string()];
        for p in paths {
            args.push("--".to_string());
            args.push(p.to_string_lossy().into_owned());
        }
        let arg_refs: Vec<&str> = args.iter().map(String::as_str).collect();
        let out = self.git(&arg_refs, None)?;
        let dirty = out.stdout.trim();
        if !dirty.is_empty() {
            return Err(Error::Apply(format!(
                "refusing to patch a file with uncommitted changes:\n{dirty}"
            )));
        }
        Ok(())
    }

    fn git(&self, args: &[&str], stdin: Option<&str>) -> Result<Output> {
        let mut child = Command::new("git")
            .args(args)
            .current_dir(&self.root)
            // Reading the diff from stdin rather than a file: the diff exists
            // only in memory, and writing it out to write it in would be a
            // pointless chance to leave a copy on disk.
            .stdin(if stdin.is_some() {
                Stdio::piped()
            } else {
                Stdio::null()
            })
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(|e| {
                Error::Apply(format!(
                    "cannot run git (is it installed and on PATH?): {e}"
                ))
            })?;

        if let (Some(text), Some(mut pipe)) = (stdin, child.stdin.take()) {
            use std::io::Write as _;
            pipe.write_all(text.as_bytes())
                .map_err(|e| Error::Apply(format!("cannot hand the diff to git: {e}")))?;
        }

        let out = child
            .wait_with_output()
            .map_err(|e| Error::Apply(format!("git did not finish: {e}")))?;
        Ok(Output {
            success: out.status.success(),
            stdout: String::from_utf8_lossy(&out.stdout).into_owned(),
            stderr: String::from_utf8_lossy(&out.stderr).into_owned(),
        })
    }
}

struct Output {
    success: bool,
    stdout: String,
    stderr: String,
}

/// The same path in the one spelling this module compares.
///
/// `Path::canonicalize` on Windows returns a verbatim path (`\\?\C:\...`) while
/// git prints the ordinary form, so a plain string comparison between them says
/// "different directory" when they are the same one -- which would refuse every
/// patch on the platform most likely to be running it. Where canonicalisation
/// fails (the path does not exist yet), the input is used unchanged: it is still
/// the best available answer, and the checks that depend on it have already
/// established that the parent exists.
fn canonical(path: &Path) -> PathBuf {
    path.canonicalize().unwrap_or_else(|_| path.to_path_buf())
}

/// The first few lines of a message, so an error stays readable.
///
/// git's failures quote the offending hunk. A 40-line dump in a UI status line
/// hides the sentence that says what went wrong.
fn first_lines(text: &str, n: usize) -> String {
    let joined = text.trim();
    joined
        .lines()
        .filter(|l| !l.trim().is_empty())
        .take(n)
        .collect::<Vec<_>>()
        .join("; ")
}
#[cfg(test)]
mod tests {
    use super::*;
    use std::process::Command;

    const PATCH: &str = "--- a/a.txt\n+++ b/a.txt\n@@ -1,3 +1,3 @@\n one\n-two\n+TWO\n three\n";

    /// A git repository with one committed file, or `None` if git is unavailable.
    ///
    /// Returns the applier and the root: several assertions look at the working
    /// tree directly, and re-deriving the path would be a second place to get it
    /// wrong.
    fn repo(tag: &str) -> Option<(Applier, PathBuf)> {
        let root =
            std::env::temp_dir().join(format!("heimdall-apply-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).ok()?;

        let git = |args: &[&str]| -> bool {
            Command::new("git")
                .args(args)
                .current_dir(&root)
                .env("GIT_AUTHOR_NAME", "test")
                .env("GIT_AUTHOR_EMAIL", "test@example.invalid")
                .env("GIT_COMMITTER_NAME", "test")
                .env("GIT_COMMITTER_EMAIL", "test@example.invalid")
                .output()
                .is_ok_and(|o| o.status.success())
        };

        if !git(&["init", "--quiet"]) {
            return None;
        }
        std::fs::write(root.join("a.txt"), "one\ntwo\nthree\n").ok()?;
        if !git(&["add", "."]) || !git(&["commit", "--quiet", "-m", "base"]) {
            return None;
        }
        Some((Applier::new(&root), root))
    }

    fn application(path: &str, diff: &str) -> Application {
        Application {
            id: 1,
            target_path: path.to_string(),
            diff: diff.to_string(),
            // The gate has already bound this digest to the approval by the time
            // an application exists; the applier checks nothing with it. Any 32
            // bytes will do.
            approved_digest: [7u8; 32],
            approved_by: "tester".into(),
        }
    }

    #[test]
    fn an_approved_diff_is_written_and_left_uncommitted() {
        let Some((applier, root)) = repo("apply") else {
            eprintln!("git unavailable; skipping");
            return;
        };
        let written = applier
            .apply(&application("a.txt", PATCH))
            .expect("the patch should apply");
        assert_eq!(written.path, PathBuf::from("a.txt"));

        let after = std::fs::read_to_string(root.join("a.txt")).unwrap();
        assert!(after.contains("TWO"), "the change must be on disk: {after}");

        // Not committed, not staged: the operator reviews it like any other edit.
        let out = Command::new("git")
            .args(["status", "--porcelain"])
            .current_dir(&root)
            .output()
            .expect("git should answer");
        let status = String::from_utf8_lossy(&out.stdout);
        assert!(
            // `trim_end`, not `trim`: git's XY status codes are space-sensitive,
            // and " M" -- modified, unstaged -- is the whole assertion.
            status.trim_end() == " M a.txt",
            "exactly one unstaged modification, got: {status:?}"
        );
    }

    #[test]
    fn a_dirty_target_is_refused() {
        let Some((applier, root)) = repo("dirty") else {
            eprintln!("git unavailable; skipping");
            return;
        };
        // An uncommitted edit is exactly the situation this check exists for: the
        // patch was written against a version of the file that no longer exists.
        std::fs::write(root.join("a.txt"), "edited by someone\n").unwrap();

        let err = applier
            .apply(&application("a.txt", PATCH))
            .expect_err("a dirty tree must be refused");
        assert!(
            err.to_string().contains("uncommitted"),
            "the error must say why: {err}"
        );
    }

    #[test]
    fn paths_that_leave_the_repository_are_refused_before_git_runs() {
        let Some((applier, _)) = repo("escape") else {
            eprintln!("git unavailable; skipping");
            return;
        };
        for hostile in ["../outside.txt", "../../etc/passwd", "/etc/passwd", ""] {
            let err = applier
                .apply(&application(hostile, PATCH))
                .expect_err("a path outside the tree must be refused");
            assert!(
                err.to_string().to_lowercase().contains("refus"),
                "{hostile:?} should be refused as a path, got: {err}"
            );
        }
    }

    #[test]
    fn a_diff_that_no_longer_fits_is_refused() {
        let Some((applier, _)) = repo("stale") else {
            eprintln!("git unavailable; skipping");
            return;
        };
        // Context that does not match the file: a stale patch, correctly refused.
        let stale = "--- a/a.txt\n+++ b/a.txt\n@@ -1,3 +1,3 @@\n nope\n-nope\n+nope\n nope\n";
        let err = applier
            .apply(&application("a.txt", stale))
            .expect_err("a stale diff must be refused");
        assert!(err.to_string().contains("apply"), "got: {err}");
    }

    #[test]
    fn an_oversized_diff_is_refused_before_anything_is_written() {
        let Some((applier, root)) = repo("huge") else {
            eprintln!("git unavailable; skipping");
            return;
        };
        let huge = format!(
            "--- a/a.txt\n+++ b/a.txt\n{}",
            "# padding\n".repeat(MAX_DIFF_BYTES / 10)
        );
        let err = applier
            .apply(&application("a.txt", &huge))
            .expect_err("an oversized diff must be refused");
        assert!(err.to_string().contains("limit"), "got: {err}");

        let after = std::fs::read_to_string(root.join("a.txt")).unwrap();
        assert_eq!(after, "one\ntwo\nthree\n", "nothing may have been written");
    }

    #[test]
    fn cleanliness_is_reported_before_any_approval() {
        let Some((applier, root)) = repo("check") else {
            eprintln!("git unavailable; skipping");
            return;
        };
        assert!(applier.is_clean("a.txt").expect("git should answer"));
        std::fs::write(root.join("a.txt"), "changed\n").unwrap();
        assert!(!applier.is_clean("a.txt").expect("git should answer"));
    }

    #[test]
    fn an_applier_bound_to_a_subdirectory_is_refused() {
        let Some((_, root)) = repo("subdir") else {
            eprintln!("git unavailable; skipping");
            return;
        };
        std::fs::create_dir_all(root.join("inner")).unwrap();
        let inner = Applier::new(root.join("inner"));
        let err = inner
            .is_clean("a.txt")
            .expect_err("a subdirectory is not the repository root");
        assert!(err.to_string().contains("refusing"), "got: {err}");
    }

    #[test]
    fn long_git_output_is_trimmed_to_something_readable() {
        let noisy = "line one\n\nline two\nline three\nline four\n";
        assert_eq!(first_lines(noisy, 2), "line one; line two");
    }
}
