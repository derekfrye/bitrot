mod check;
mod error;
mod progress;
mod args;

use anyhow::Result;
// use clap::Parser;

// if you want to use some old manual "debug" stuff below
// use chrono::{Local, Timelike};
// use console::style;

use fs2::FileExt;
use regex::Regex;
use std::fs;
use std::io::Write;

use std::path::PathBuf;
use std::sync::mpsc::channel;
use std::sync::mpsc::Sender;
use std::thread;
use std::time::Duration;

fn main() -> Result<()> {
    // let args = ;

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
        let (tx, rx) = channel();

        let mut status_bar_line_entry = 0;
        for x in zz {
            let tx1 = tx.clone();
            let kjdfj = args.path_to_cksums.clone();
            let jkdf = args.unit_testing.clone();
            thread::spawn(move || {
                if jkdf {
                    let _ = do_unit_tests(x.wrok, status_bar_line_entry, tx1);
                } else {
                    let _ = check::validate_ondisk_md5(
                        x.wrok,
                        &kjdfj,
                        args.bufsize,
                        status_bar_line_entry,
                        tx1
                    );
                }
            });
            status_bar_line_entry += 1;
        }
        drop(tx);

        let final_progress_bar = args.thread_count.to_string().parse::<usize>().unwrap();
        for received in rx {
            // println!("Got: {}", received);
            let xa = received.split_terminator("|").collect::<Vec<&str>>();

            let sb = xa[0].parse::<usize>().unwrap();
            let djk = xa[1];
            // len of two is messaged when we're starting work on a file
            if xa.len() == 2 {
                // pb[sb].set_message(format!("{djk}..."));
                progress::set_message(sb, djk, &pb);
            } else if
                // len of three is used when marking the thread as done
                xa.len() == 3
            {
                progress::set_message(sb, "Thread done.", &pb);
                progress::finish_progress_bar(sb, &pb);
            } else if
                // len of 4 used when incrementing progress on this thread to the next file in its queue
                xa.len() == 4
            {
                progress::increment_progress_bar(final_progress_bar, &pb);
            } else if
                // len of 5 used to indicate the par2 file didn't exist, wasn't readable, etc.
                xa.len() == 5
            {
                let mut data = String::from("Error: ");
                data.push_str(xa[1]);

                let mut fil = fs::OpenOptions
                    ::new()
                    .write(true)
                    .append(true)
                    .create(true)
                    .open(&args.error_output_file)?;

                fil.lock_exclusive()?;
                fil.write(data.as_bytes()).unwrap();
                fil.unlock()?;
            } else if
                // len of 7 used to indciate there was a checksum mismatch for the file
                xa.len() == 7
            {
                let mut data = String::from("Error: ");
                data.push_str(xa[4]);
                data.push_str(&format!(", expected: {}", xa[5]));
                data.push_str(&format!(", got: {}\n", xa[6]));

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
        }

        progress::finish_progress_bar(final_progress_bar, &pb);
        if args.unit_testing {
            thread::sleep(Duration::from_millis(5000));
        }
    }

    Ok(())
}

// fn zip (z: &str, zz: &str){
//     let mut xxx = fs::OpenOptions::new().append(true).open(zz).expect("cannot open file");
//     xxx.write(z.as_bytes());
// }

fn do_unit_tests(
    xx: Vec<PathBuf>,
    // path_to_cksums: &str,
    // bufsize: u16,
    statusbar: u16,
    ab: Sender<String>
) -> Result<()> {
    for x in xx {
        // idea for converting to string from https://stackoverflow.com/questions/37388107/how-to-convert-the-pathbuf-to-string
        // let movie_as_str = x.to_string_lossy();
        let movie_basename = x.file_name().unwrap().to_string_lossy();

        let mut status_bar_and_working_file = statusbar.to_string();
        status_bar_and_working_file.push_str("|");
        status_bar_and_working_file.push_str(&movie_basename);

        // send we're working on file
        ab.send(status_bar_and_working_file).unwrap();

        // let _ = validate_ondisk_md5(&movie_as_str, &movie_basename, &path_to_cksums, bufsize)?;
        thread::sleep(Duration::from_millis(5000));

        // send we're done w/this unit of work
        let mut status_bar_and_working_file = statusbar.to_string();
        status_bar_and_working_file.push_str("|");
        status_bar_and_working_file.push_str(" ");
        status_bar_and_working_file.push_str("done");
        status_bar_and_working_file.push_str("|");
        status_bar_and_working_file.push_str(" ");
        status_bar_and_working_file.push_str("|");
        status_bar_and_working_file.push_str(" ");
        ab.send(status_bar_and_working_file).unwrap();
    }

    let mut status_bar_and_working_file = statusbar.to_string();
    status_bar_and_working_file.push_str("|");
    status_bar_and_working_file.push_str(" ");
    status_bar_and_working_file.push_str("done");
    status_bar_and_working_file.push_str("|");
    ab.send(status_bar_and_working_file).unwrap();

    thread::sleep(Duration::from_millis(5000));
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
