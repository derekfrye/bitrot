use indicatif::{MultiProgress, ProgressBar, ProgressStyle};
use std::time::Duration;

pub struct Bars {
    bars: Vec<ProgressBar>,
    // prettyprint: bool
}

pub fn build_progress_bar_export(total_messages: usize, threadcnt: u16, prettyprint: bool) -> Bars {
    let mut b = Bars { bars: Vec::new() };

    // let mut z: Vec<ProgressBar> = Vec::new();
    if prettyprint {
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
            pb.enable_steady_tick(Duration::from_millis(200));
            // z.insert(i.into(), pb);
            b.bars.insert(i.into(), pb);
        }

        let pb1 = m.add(ProgressBar::new(total_messages.try_into().unwrap()));

        pb1.set_style(
            ProgressStyle::default_bar()
                .template("{spinner:.green} [{elapsed}] [{bar:.blue}] {pos}/{len} (ETA: {eta})")
                .unwrap()
                .progress_chars("#>-"),
        );

        pb1.set_position(0);
        pb1.enable_steady_tick(Duration::from_millis(200));

        // z.insert(threadcnt.into(), pb1);
        b.bars.insert(threadcnt.into(), pb1);
    }
    return b;
}

pub fn increment_progress_bar(b: usize, z: &Bars) {
    if z.bars.len() >= b + 1 {
        z.bars[b].inc(1);
        // b.inc(1);
    }
}

pub fn finish_progress_bar(b: usize, z: &Bars) {
    // b.finish();
    if z.bars.len() >= b + 1 {
        z.bars[b].finish_and_clear();
    }
}

pub fn set_message(b: usize, s: &str, z: &Bars) {
    if z.bars.len() >= b + 1 {
        z.bars[b].set_message(format!("{s}"));
        
    }
}

pub struct ProgressMessage {
    pub bar_number: usize,
    pub status_code: ProgressStatus,
pub  file_name: String ,
pub err: String,
pub md5_expected: String,
pub md5_computed: String,
}

pub enum ProgressStatus {
    Started,
    MovieCompleted,
    ThreadCompleted,
    MovieError,
    ParFileError,
}