use indicatif::{MultiProgress, ProgressBar, ProgressStyle};
use std::time::Duration;

pub fn build_progress_bar_export(
    total_messages: usize,
    threadcnt: u16,
    prettyprint: bool,
) -> Vec<ProgressBar> {
    let mut z: Vec<ProgressBar> = Vec::new();
    if !prettyprint {
        let m = MultiProgress::new();

        for i in 0..threadcnt {
            let pb = m.add(ProgressBar::new(total_messages.try_into().unwrap()));
            // z.append(pb);

            let spinner_style =
                ProgressStyle::with_template("{prefix:.bold.dim} {spinner} {wide_msg}")
                    .unwrap()
                    .tick_chars("⠁⠂⠄⡀⢀⠠⠐⠈ ");

            pb.set_style(spinner_style.clone());

            pb.set_position(0);
            pb.enable_steady_tick(Duration::from_millis(100));
            z.insert(i.into(), pb);
        }

        let pb1 = m.add(ProgressBar::new(total_messages.try_into().unwrap()));

        pb1.set_style(
            ProgressStyle::default_bar()
                .template("{spinner:.green} [{elapsed}] [{bar:.blue}] {pos}/{len} (ETA: {eta})")
                .unwrap()
                .progress_chars("#>-"),
        );

        pb1.set_position(0);
        pb1.enable_steady_tick(Duration::from_millis(100));

        z.insert(threadcnt.into(), pb1);
    }
    return z;
}

pub fn increment_progress_bar(b: &ProgressBar) {
    b.inc(1);
}

pub fn finish_progress_bar(b: &ProgressBar) {
b.finish();
}

pub fn set_message(b: &ProgressBar, s: &str){
    b.set_message(format!("{s}..."));
}