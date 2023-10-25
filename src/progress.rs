use crate::args::{ ArgsClean, Mode };

use std::fs;
use std::io::Write;
use std::time::Duration;

use fs2::FileExt;
use indicatif::{ MultiProgress, ProgressBar, ProgressStyle };
use derivative::Derivative;

#[derive(Copy, Clone, Debug, PartialEq)]
pub enum ProgressStatus {
    Started,
    MovieCompleted,
    // ThreadCompleted,
    MovieError,
    ParFileError,
    Requesting,
    DoingNothin,
    ThreadError,
    WriteFileHeader,
}

pub struct Bars {
    bars: Vec<ProgressBar>,
    // prettyprint: bool
}

#[derive(Copy, Clone)]
#[derive(Derivative)]
#[derivative(Debug, Default)]
pub struct ProgressMessage {
    #[derivative(Default(value = "0"))]
    pub bar_number: usize,
    #[derivative(Default(value = "ProgressStatus::Started"))]
    pub status_code: ProgressStatus,
    #[derivative(Default(value = "0"))]
    pub file_number: usize,
    #[derivative(Default(value = "Default::default()"))]
    pub ondisk_digest: [char; 32],
    #[derivative(Default(value = "Default::default()"))]
    pub computed_digest: [char; 32],
    #[derivative(Default(value = "0"))]
    pub file_size: u64,
}

pub fn build_progress_bar_export(total_messages: usize, threadcnt: u16, prettyprint: bool) -> Bars {
    let mut b = Bars { bars: Vec::new() };

    // let mut z: Vec<ProgressBar> = Vec::new();
    if prettyprint {
        let m = MultiProgress::new();

        for i in 0..threadcnt {
            let pb = m.add(ProgressBar::new(total_messages.try_into().unwrap()));
            // z.append(pb);

            let spinner_style = ProgressStyle::with_template(
                "{prefix:.bold.dim} {spinner} {wide_msg}"
            )
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
                .progress_chars("#>-")
        );

        pb1.set_position(0);
        pb1.enable_steady_tick(Duration::from_millis(200));

        // z.insert(threadcnt.into(), pb1);
        b.bars.insert(threadcnt.into(), pb1);
    }
    return b;
}

fn increment_progress_bar(b: usize, z: &Bars) {
    if z.bars.len() >= b + 1 {
        z.bars[b].inc(1);
    }
}

pub fn finish_progress_bar(b: usize, z: &Bars) {
    if z.bars.len() >= b + 1 {
        z.bars[b].finish_and_clear();
    }
}

fn set_message(b: usize, s: &str, z: &Bars) {
    if z.bars.len() >= b + 1 {
        z.bars[b].set_message(format!("{s}"));
    }
}



pub fn advance_progress_bars(
    file_name: &str,
    received: ProgressMessage,
    pb: &Bars,
    args: &ArgsClean,
) {
    let fssn = file_name;

    match received.status_code {
        ProgressStatus::Started => {
            // let fssn = file_name;
            if fssn != "" {
                set_message(received.bar_number, &fssn.to_owned().to_string(), &pb);
            }
        }
        | ProgressStatus::MovieCompleted
        | ProgressStatus::ParFileError
        | ProgressStatus::MovieError => {
            increment_progress_bar(args.thread_count as usize, &pb);
        }
        ProgressStatus::DoingNothin => {
            set_message(received.bar_number, "Thread done.", &pb);
        }
        _ => {}
    }

    // if args.unit_testing {
    //     thread::sleep(Duration::from_millis(5000));
    // }
}

pub fn write_to_output(
    file_name: &str,
    file_full_name: &str,
    args: &ArgsClean,
    received: ProgressMessage,
    append: bool
) {
    let mut opts = fs::OpenOptions::new();
    if append {
        opts.write(true).create(true).append(true);
    } else {
        opts.write(true).create(true).truncate(true);
    }

    let mut fil = opts.open(&args.error_output_file).unwrap();

    // let fssn = file_name;

    match received.status_code {
        ProgressStatus::ParFileError => {
            fil.lock_exclusive().unwrap();
            fil.write(format!("No md5 on disk found for {}\n", file_name).as_bytes()).unwrap();
        }
        ProgressStatus::MovieError => {
            fil.lock_exclusive().unwrap();
            fil.write(
                format!(
                    "Error: {}, on-disk checksum: {}, our checksum: {}\n",
                    file_name,
                    format!("{}", get_a_str(received.ondisk_digest)),
                    format!("{:?}", get_a_str(received.computed_digest))
                ).as_bytes()
            ).unwrap();
        }
        ProgressStatus::MovieCompleted => {
            if args.mode == Mode::Create {
                fil.write(
                    format!(
                        "{},{},{}\n",
                        received.file_size,
                        get_a_str(received.computed_digest),
                        file_full_name,
                    ).as_bytes()
                ).unwrap();
            }
        }
        ProgressStatus::WriteFileHeader => {
            fil.write(format!("%%%% HASHDEEP-1.0\n").as_bytes()).unwrap();
            fil.write(format!("%%%% size,md5,filename\n").as_bytes()).unwrap();
        }
        _ => {}
    }

    let _ = fil.flush();
    fil.unlock().unwrap()
}

fn get_a_str(ch: [char; 32]) -> String {
    let mut x = String::from("");
    for ab in ch {
        x.push(ab);
    }
    return x;
}
