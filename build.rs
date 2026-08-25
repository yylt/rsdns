use std::{env, process::Command};

fn command_output(program: &str, args: &[&str]) -> Option<String> {
    let output = Command::new(program).args(args).output().ok()?;
    if !output.status.success() {
        return None;
    }

    let value = String::from_utf8(output.stdout).ok()?;
    let trimmed = value.trim();
    if trimmed.is_empty() {
        None
    } else {
        Some(trimmed.to_string())
    }
}

fn main() {
    // `ring` and `aws-lc-rs` are mutually exclusive
    let ring = env::var("CARGO_FEATURE_RING").is_ok();
    let aws_lc_rs = env::var("CARGO_FEATURE_AWS_LC_RS").is_ok();
    if ring && aws_lc_rs {
        panic!("Features `ring` and `aws-lc-rs` are mutually exclusive. Enable only one.");
    }
    if !ring && !aws_lc_rs {
        panic!("Either `ring` or `aws-lc-rs` feature must be enabled.");
    }

    println!("cargo:rerun-if-changed=.git/HEAD");
    println!("cargo:rerun-if-changed=.git/refs/tags");
    println!("cargo:rerun-if-env-changed=PROFILE");
    println!("cargo:rerun-if-env-changed=TARGET");

    let git_commit = command_output("git", &["rev-parse", "--short", "HEAD"]).unwrap_or_else(|| "unknown".into());
    let git_branch = command_output("git", &["rev-parse", "--abbrev-ref", "HEAD"]).unwrap_or_else(|| "unknown".into());
    // Version tracks the closest git tag (e.g. `v0.2.0`), with distance+commit when
    // ahead of a tag (`v0.2.0-3-g4f4aeaf`) and `-dirty` for uncommitted changes.
    let version = command_output("git", &["describe", "--tags", "--always", "--dirty"])
        .or_else(|| env::var("CARGO_PKG_VERSION").ok())
        .unwrap_or_else(|| "unknown".into());
    let rustc_version = command_output("rustc", &["--version"]).unwrap_or_else(|| "unknown".into());
    let build_target = env::var("TARGET").unwrap_or_else(|_| "unknown".into());
    let build_profile = env::var("PROFILE").unwrap_or_else(|_| "unknown".into());
    let build_time = command_output("date", &["-u", "+%Y-%m-%dT%H:%M:%SZ"]).unwrap_or_else(|| "unknown".into());

    println!("cargo:rustc-env=XRAY_RS_VERSION={version}");
    println!("cargo:rustc-env=XRAY_RS_GIT_COMMIT={git_commit}");
    println!("cargo:rustc-env=XRAY_RS_GIT_BRANCH={git_branch}");
    println!("cargo:rustc-env=XRAY_RS_RUSTC_VERSION={rustc_version}");
    println!("cargo:rustc-env=XRAY_RS_BUILD_TARGET={build_target}");
    println!("cargo:rustc-env=XRAY_RS_BUILD_PROFILE={build_profile}");
    println!("cargo:rustc-env=XRAY_RS_BUILD_TIME={build_time}");
}
