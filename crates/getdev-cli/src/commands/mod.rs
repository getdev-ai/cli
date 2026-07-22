pub mod audit;
pub mod back;
pub mod check;
pub mod doctor;
pub mod env;
pub mod init;
pub mod real;
pub mod review;
pub mod ship;
pub mod snap;
pub mod update;

/// `-o/--output` emission shared by every findings command: write the full
/// JSON report (docs/SPEC-FINDINGS.md schema) to `path`, keep the terminal
/// short. With `--json` too, stdout carries only the path — script-friendly.
/// The output file is an explicitly requested artifact, not a project
/// mutation: no `--write` gate, overwrite allowed (eslint/trivy semantics).
pub(crate) fn emit_report_file(
    report: &getdev_core::findings::FindingsReport,
    path: &std::path::Path,
    json: bool,
    _no_color: bool,
) -> anyhow::Result<()> {
    let rendered = getdev_core::report::render_json(report)?;
    std::fs::write(path, &rendered)
        .map_err(|e| anyhow::anyhow!("could not write report to {}: {e}", path.display()))?;
    if json {
        println!("{}", path.display());
    } else {
        print!("{}", getdev_core::report::render_terminal_short(report));
        println!(
            "full report → {} ({} finding(s) · {} KB)",
            path.display(),
            report.findings.len(),
            rendered.len().div_ceil(1024)
        );
    }
    Ok(())
}
