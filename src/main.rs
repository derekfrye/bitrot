mod check;
mod error;
mod progress;
mod args;

use anyhow::Result;

// if you want to use some old manual "debug" stuff below
// use chrono::{Local, Timelike};
// use console::style;

use regex::Regex;
use std::fs;

use std::path::PathBuf;
use std::sync::mpsc::{ channel, Receiver, Sender };
use std::thread;
// use std::time::Duration;
use std::sync::Mutex;

use crate::progress::{ ProgressStatus, ProgressMessage };

#[derive(Clone)]
pub struct UnitOfWork {
    file_name: PathBuf,
    file_number: usize,
}

struct StatusUpdate {
    movie_basename: String,
    progress_msg: ProgressMessage,
}

struct WorkerThread {
    join_handle: std::thread::JoinHandle<()>,
    unit_of_work: Sender<Option<UnitOfWork>>,
    progress_message: Receiver<ProgressMessage>,
}

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
        // let data_files: Arc<Mutex<Vec<_>>> = Arc::new(Mutex::new(fs
        let data_filest: Vec<_> = fs
            ::read_dir(&args.path_to_data)?
            .into_iter()
            .filter(|z| z.is_ok())
            .map(|r| r.unwrap().path())
            .filter(|z| z.is_file())
            .into_iter()
            .filter(|ab| re.is_match(&ab.file_name().unwrap().to_string_lossy()))
            .collect();

        let data_file_len = data_filest.len();

        let mut data_files: Vec<UnitOfWork> = vec![];
        let mut data_files_stable: Vec<UnitOfWork> = vec![];
        let mut cntre = 0;
        for i in data_filest {
            let u = UnitOfWork { file_name: i, file_number: cntre };
            let ub = u.clone();
            data_files.push(u);
            data_files_stable.push(ub);
            cntre += 1;
        }

        // let _jkdfjd= data_files[0];

        let data_files_mutexed = Mutex::new(data_files);
        let data_files_stable_mutexed = Mutex::new(data_files_stable);
        let mut handles: Vec<WorkerThread> = vec![];

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
            data_file_len,
            args.thread_count,
            args.pretty_print
        );

        for i in 0..args.thread_count {
            let (tx, worker_rx) = channel();
            let (worker_tx, main_rx) = channel();
            let ttj = args.clone();

            let handle = thread::spawn(move || {
                check::do_work(i as usize, ttj, worker_tx, worker_rx);
            });

            handles.push(WorkerThread {
                join_handle: handle,
                unit_of_work: tx,
                progress_message: main_rx,
            });
        }

        let final_progress_bar = args.thread_count.to_string().parse::<usize>().unwrap();

        // let mut i = 0;
        let mut doing_nothing = true;
        loop {
            for hndl in &handles {
                let status_update = poll_worker(
                    hndl,
                    &data_files_mutexed,
                    &data_files_stable_mutexed
                ).unwrap();

                progress::advance_progress_bars(
                    &status_update.movie_basename,
                    status_update.progress_msg,
                    &pb,
                    &args
                );
                
                match status_update.progress_msg.status_code {
                    ProgressStatus::DoingNothin | ProgressStatus::ThreadError => {
                        doing_nothing = true;
                    }
                    // ProgressStatus::ThreadCompleted => {
                    //     println!("Did a file.");
                    // }
                    _ => {
                        // println!("{:#?}", other);
                        doing_nothing = false;
                    }
                }
            }
            if doing_nothing {
                break;
            }

            // Sleep for a while before checking again
            thread::sleep(std::time::Duration::from_millis(100));
        }

        // for hndl in handles {
        //     hndl.join_handle.join().unwrap();
        // }

        // Sleep for a while before checking again
        thread::sleep(std::time::Duration::from_millis(1000));

        progress::finish_progress_bar(final_progress_bar, &pb);
    }

    Ok(())
}

fn poll_worker(
    worker_thread: &WorkerThread,
    muta: &Mutex<Vec<UnitOfWork>>,
    mutb: &Mutex<Vec<UnitOfWork>>
) -> Result<StatusUpdate> {
    let mut status_report = StatusUpdate {
        movie_basename: String::from(""),
        progress_msg: ProgressMessage {
            bar_number: 0,
            status_code: ProgressStatus::Started,
            file_number: 0,
            ondisk_digest: Default::default(),
            computed_digest: Default::default(),
        },
    };

    let thread_progress = worker_thread.progress_message.recv();
    match thread_progress {
        // If a message is received at all
        Ok(i) => {
            match i.status_code {
                // if the thread wants a file, pop the next one and send it
                ProgressStatus::Requesting => {
                    let mut bc_locked = muta.lock().unwrap();
                    if bc_locked.len() > 0 {
                    let path_opt = bc_locked.pop().clone();
                    let _abc = bc_locked.len();
                    worker_thread.unit_of_work.send(path_opt).unwrap();
                    }
                    else {
                        worker_thread.unit_of_work.send(None).unwrap();
                    }
                }
                _ => {
                    // let  bc_locked = muta.lock().unwrap();
                    let abc_locked = mutb.lock().unwrap();

                    let mut f = StatusUpdate {
                        movie_basename: String::from(""),
                        progress_msg: thread_progress.unwrap(),
                    };

                    if
                        abc_locked
                            .iter()
                            .any(
                                |axe: &UnitOfWork|
                                    axe.file_number == thread_progress.unwrap().file_number
                            )
                    {
                        let z = abc_locked
                            .iter()
                            .position(
                                |axe: &UnitOfWork|
                                    axe.file_number == thread_progress.unwrap().file_number
                            )
                            .unwrap();
                        f.movie_basename = abc_locked[z].file_name
                            .file_name()
                            .unwrap()
                            .to_string_lossy()
                            .to_string();
                    }
                    status_report = f;
                }
            }
        }
        Err(_) => {
            status_report.progress_msg.status_code = ProgressStatus::ThreadError;
        }
    }

    Ok(status_report)
}
