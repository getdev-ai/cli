use std::collections::BTreeMap;
use std::path::Path;
use std::time::Instant;

use getdev_core::scan;

pub fn run(path: &Path) -> anyhow::Result<()> {
    let started = Instant::now();
    let (scans, skipped) = scan::scan_path(path)?;
    let elapsed = started.elapsed();

    let mut by_lang: BTreeMap<String, (usize, usize, usize)> = BTreeMap::new();
    for file in &scans {
        let entry = by_lang.entry(file.lang.to_string()).or_default();
        entry.0 += 1;
        entry.1 += file.functions;
        entry.2 += usize::from(file.has_syntax_errors);
    }

    println!("spike scan of {}", path.display());
    println!();
    println!(
        "  {:<12} {:>6} {:>10} {:>12}",
        "language", "files", "functions", "syntax errs"
    );
    for (lang, (files, functions, errors)) in &by_lang {
        println!("  {lang:<12} {files:>6} {functions:>10} {errors:>12}");
    }
    let total_files: usize = by_lang.values().map(|v| v.0).sum();
    let total_fns: usize = by_lang.values().map(|v| v.1).sum();
    println!();
    println!(
        "  {total_files} files, {total_fns} functions in {:.0} ms ({} unreadable skipped)",
        elapsed.as_secs_f64() * 1000.0,
        skipped.len()
    );

    Ok(())
}
