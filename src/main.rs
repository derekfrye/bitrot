mod check;
mod error;
mod progress;
mod args;

use anyhow::Result;

// if you want to use some old manual "debug" stuff below
// use chrono::{Local, Timelike};
// use console::style;

use fs2::FileExt;
use regex::Regex;
use std::fs;
use std::io::Write;

use std::path::PathBuf;
use std::sync::mpsc::{ channel, Receiver, Sender };
// use std::sync::mpsc::Sender;
use std::thread;
use std::time::Duration;

use crate::progress::ProgressStatus;

fn main() -> Result<()> {
    let args = args::args_checks();

    if args.mode == "ck" {
        println!(
            "Using data path {} and checksums path {}",
            args.path_to_data,
            args.path_to_cksums
        );

        // r"\.[Mm][4pP][vV4]$"
        let re = Regex::new(&args.data_filename_match).unwrap();

        // idea from https://stackoverflow.com/questions/58062887/filtering-files-or-directories-discovered-with-fsread-dir
        let data_files: Vec<_> = fs
            ::read_dir(args.path_to_data)?
            .into_iter()
            .filter(|z| z.is_ok())
            .map(|r| r.unwrap().path())
            .filter(|z| z.is_file())
            .into_iter()
            .filter(|ab| re.is_match(&ab.file_name().unwrap().to_string_lossy()))
            .collect();

        // old manual "debug" stuff
        // let now = Local::now();
        // let (is_pm, hour) = now.hour12();
        // println!(
        //     "{:02}:{:02}:{:02}{} Processing {} files...",
        //     style(hour).bold().dim(),
        //     style(now.minute()).bold().dim(),
        //     style(now.second()).bold().dim(),
        //     style(if is_pm { "p" } else { "a" }).bold().dim(),
        //     data_files.len()
        // );

        let pb = progress::build_progress_bar_export(
            data_files.len(),
            args.thread_count,
            args.pretty_print
        );

        let zz = assign_work(data_files, args.thread_count);
        let (tx, rx): (
            Sender<progress::ProgressMessage>,
            Receiver<progress::ProgressMessage>,
        ) = channel();

        let mut status_bar_line_entry = 0;
        for x in zz {
            let tx1 = tx.clone();
            let kjdfj = args.path_to_cksums.clone();
            thread::spawn(move || {
                let _ = check::validate_ondisk_md5(
                    x.wrok,
                    &kjdfj,
                    args.bufsize,
                    status_bar_line_entry,
                    tx1
                );
            });
            status_bar_line_entry += 1;
        }
        drop(tx);

        let final_progress_bar = args.thread_count.to_string().parse::<usize>().unwrap();
        for received in rx {
            // println!("Got: {}", received);

            // let xb = received;

            // let xa = received.split_terminator("|").collect::<Vec<&str>>();
            // let sb = xa[0].parse::<usize>().unwrap();

            match received.status_code {
                ProgressStatus::Started => {
                    progress::set_message(received.bar_number, &received.file_name, &pb);
                }
                ProgressStatus::MovieCompleted => {
                    progress::increment_progress_bar(received.bar_number, &pb);
                }
                ProgressStatus::MovieError => {
                    let mut data = String::from("Error: ");
                    data.push_str(&received.file_name);
                    data.push_str(&format!(", expected: {}", &received.md5_expected));
                    data.push_str(&format!(", got: {}\n", &received.md5_computed));

                    let mut fil = fs::OpenOptions
                        ::new()
                        .write(true)
                        .append(true)
                        .create(true)
                        .open(&args.error_output_file)?;
                    fil.lock_exclusive()?;

                    // let mut xxx = fs::OpenOptions::new()
                    fil.write(data.as_bytes()).unwrap();
                    fil.unlock()?;
                }
                ProgressStatus::ParFileError => {
                    let mut data = String::from("Error: ");
                    data.push_str(&received.file_name);

                    let mut fil = fs::OpenOptions
                        ::new()
                        .write(true)
                        .append(true)
                        .create(true)
                        .open(&args.error_output_file)?;

                    fil.lock_exclusive()?;
                    fil.write(data.as_bytes()).unwrap();
                    fil.unlock()?;
                }
                ProgressStatus::ThreadCompleted => {
                    // let mut x: usize =1;
                    // x = x+1;
                    // progress::set_message(received.bar_number, &received.file_name, &pb);
                    // &received.bar_number.clone_into(&mut x);
                    progress::set_message(received.bar_number, "Thread done.", &pb);
                    progress::finish_progress_bar(received.bar_number, &pb);
                }
            }
        }

        progress::finish_progress_bar(final_progress_bar, &pb);
        if args.unit_testing {
            thread::sleep(Duration::from_millis(5000));
        }
    }

    Ok(())
}

fn assign_work(mut z: Vec<PathBuf>, threadcnt: u16) -> Vec<Work> {
    let mut x: Vec<Work> = Vec::new();

    // these are the movies
    z.sort_by_key(|x| x.metadata().unwrap().len());
    // z.reverse();

    // now there's a queue per thread in x
    for ia in 0..threadcnt {
        // let ab: Vec<PathBuf> = Vec::new();
        let work = Work {
            wrok: Vec::new(), // , thread_num: ia
        };
        x.insert(ia.into(), work);
    }

    for ia in 0..z.len() {
        x[ia % (threadcnt as usize)].wrok.push(z[ia].to_owned());
    }

    return x;
}

struct Work {
    // thread_num: u16,
    wrok: Vec<PathBuf>,
}

#[cfg(test)]
mod tests {
    #[test]
    fn it_works() {
        let result = 2 + 2;
        assert_eq!(result, 4);
    }
}
