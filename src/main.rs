mod args;
mod check;
mod progress;

use anyhow::{Ok, Result};
// use std::result::Result::Ok;

// if you want to use some old manual "debug" stuff below
// use chrono::{Local, Timelike};
// use console::style;

use args::{ArgsClean, Mode};
use regex::Regex;
use std::fs;

use std::path::PathBuf;
use std::sync::mpsc::{channel, Receiver, Sender};
use std::thread;
// use std::time::Duration;
use std::sync::Mutex;

use crate::progress::{ProgressMessage, ProgressStatus};

#[derive(Clone)]
pub struct UnitOfWork {
    file_name: PathBuf,
    file_number: usize,
}

struct StatusUpdate {
    movie_basename: String,
    progress_msg: ProgressMessage,
    file_full_name: String,
}

struct WorkerThread {
    join_handle: std::thread::JoinHandle<()>,
    unit_of_work: Sender<Option<UnitOfWork>>,
    progress_message: Receiver<ProgressMessage>,
    thread_status: ProgressStatus,
}

fn main() -> Result<()> {
    let args = args::args_checks();

    // r"\.[Mm][4pP][vV4]$"
    let re = Regex::new(&args.data_filename_match).unwrap();

    // idea from https://stackoverflow.com/questions/58062887/filtering-files-or-directories-discovered-with-fsread-dir
    // let data_files: Arc<Mutex<Vec<_>>> = Arc::new(Mutex::new(fs
    let data_filest: Vec<PathBuf> = fs::read_dir(&args.path_to_data)?
        .into_iter()
        .filter(|z| z.is_ok())
        .map(|r| r.unwrap().path())
        .filter(|z| z.is_file())
        .into_iter()
        .filter(|ab| re.is_match(&ab.file_name().unwrap().to_string_lossy()))
        .collect();

    // println!(
    //     "Using data path {} and checksums path {}",
    //     args.path_to_data,
    //     args.path_to_cksums
    // );
    if args.mode == Mode::Create {
        let mut x: ProgressMessage = Default::default();
        x.status_code = ProgressStatus::WriteFileHeader;

        progress::write_to_output("", "", &args, x, false);
    }

    if args.alternate_scheduler {
        let _ = alternate_scheduler(data_filest, args);
    } else {
        let _ = main_scheduler(data_filest, args);
    }

    Ok(())
}

fn main_scheduler(data_files: Vec<PathBuf>, args: ArgsClean) -> Result<()> {
    let pb =
        progress::build_progress_bar_export(data_files.len(), args.thread_count, args.pretty_print);

    let zz = assign_work(data_files, args.thread_count);
    let tb = zz.clone();
    let (tx, rx): (
        Sender<progress::ProgressMessage>,
        Receiver<progress::ProgressMessage>,
    ) = channel();

    let mut status_bar_line_entry = 0;
    for x in zz {
        let tx1 = tx.clone();
        let kjdfj = args.clone();
        thread::spawn(move || {
            let _ = check::do_work_main(x, kjdfj, status_bar_line_entry, tx1);
        });
        status_bar_line_entry += 1;
    }
    drop(tx);

    // let final_progress_bar = args.thread_count.to_string().parse::<usize>().unwrap();
    for received in rx {
        let mut filenm = String::from("");
        let mut filenm_full = String::from("");

        match tb
            .iter()
            .find(|x| x.iter().any(|x| x.file_number == received.file_number))
        {
            Some(bx) => {
                let px = &bx.iter().find(|x| x.file_number == received.file_number);
                let tx = px.unwrap().file_name.file_name().unwrap().to_string_lossy();
                filenm = tx.to_string();
                filenm_full = px.unwrap().file_name.to_string_lossy().to_string();
            }
            None => {}
        }

        if args.pretty_print {
            progress::advance_progress_bars(
                // &tb[received.file_number].file_name().unwrap().to_string_lossy(),
                &filenm, received, &pb, &args, // &filenm_full,
            );
        }

        match received.status_code {
            ProgressStatus::ParFileError
            | ProgressStatus::MovieError
            | ProgressStatus::MovieCompleted => {
                progress::write_to_output(&filenm, &filenm_full, &args, received, true);
            }
            _ => {}
        }

        // thread::sleep(std::time::Duration::from_millis(50));
    }
    if args.pretty_print {
        progress::finish_progress_bar(args.thread_count.to_string().parse::<usize>().unwrap(), &pb);
    }
    Ok(())
}

fn assign_work(mut z: Vec<PathBuf>, threadcnt: u16) -> Vec<Vec<UnitOfWork>> {
    let mut x: Vec<Vec<UnitOfWork>> = vec![];

    // these are the files, sort them so the threads get allocated roughly equal amounts of work (ideally)
    z.sort_by_key(|x| x.metadata().unwrap().len());

    // now there's a queue for each thread
    for _ in 0..threadcnt {
        let work: Vec<UnitOfWork> = vec![];
        x.push(work);
    }

    // assign each file into the thread queues
    let mut i = 0;
    for ia in 0..z.len() {
        let t = UnitOfWork {
            file_name: z[ia].to_owned(),
            file_number: i,
        };
        x[ia % (threadcnt as usize)].push(t);
        i += 1;
    }

    return x;
}

fn alternate_scheduler(data_filest: Vec<PathBuf>, args: ArgsClean) -> Result<()> {
    let data_file_len = data_filest.len();

    let mut data_files: Vec<UnitOfWork> = vec![];
    let mut data_files_stable: Vec<UnitOfWork> = vec![];
    let mut cntre = 0;
    for i in data_filest {
        let u = UnitOfWork {
            file_name: i,
            file_number: cntre,
        };
        let ub = u.clone();
        data_files.push(u);
        data_files_stable.push(ub);
        cntre += 1;
    }

    // let _jkdfjd= data_files[0];

    let data_files_mutexed = Mutex::new(data_files);
    let data_files_stable_mutexed = Mutex::new(data_files_stable);
    let handles: Vec<WorkerThread> = vec![];
    let handles_mutexed = Mutex::new(handles);

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

    let pb =
        progress::build_progress_bar_export(data_file_len, args.thread_count, args.pretty_print);

    for i in 0..args.thread_count {
        let (tx, worker_rx) = channel();
        let (worker_tx, main_rx) = channel();
        let ttj = args.clone();

        let handle = thread::spawn(move || {
            check::do_work(i as usize, ttj, worker_tx, worker_rx);
        });

        {
            let mut abc = handles_mutexed.lock().unwrap();
            abc.push(WorkerThread {
                join_handle: handle,
                unit_of_work: tx,
                progress_message: main_rx,
                thread_status: ProgressStatus::Requesting,
            });
        }
    }

    let final_progress_bar = args.thread_count.to_string().parse::<usize>().unwrap();

    // let mut i = 0;
    // let mut doing_nothing = true;
    loop {
        let mut abc = handles_mutexed.lock().unwrap();
        for hndl in 0..abc.len() {
            let status_update =
                poll_worker(&abc[hndl], &data_files_mutexed, &data_files_stable_mutexed).unwrap();
            if args.pretty_print {
                progress::advance_progress_bars(
                    &status_update.movie_basename,
                    status_update.progress_msg,
                    &pb,
                    &args, // &status_update.file_full_name,
                );
            }

            match status_update.progress_msg.status_code {
                ProgressStatus::DoingNothin | ProgressStatus::ThreadError => {
                    abc[hndl].thread_status = ProgressStatus::DoingNothin;
                    //  handles.last().unwrap().join_handle.join().unwrap();
                }
                // ProgressStatus::ThreadCompleted => {
                //     println!("Did a file.");
                // }
                ProgressStatus::MovieCompleted => {
                    progress::write_to_output(
                        &status_update.movie_basename,
                        &status_update.file_full_name,
                        &args,
                        status_update.progress_msg,
                        true,
                    );
                }
                _ => {
                    // println!("{:#?}", other);
                }
            }
        }

        if abc
            .iter()
            .all(|axe: &WorkerThread| axe.thread_status == ProgressStatus::DoingNothin)
        {
            let _ = 1 + 1;
            break;
        }

        // Sleep for a while before checking again
        thread::sleep(std::time::Duration::from_millis(100));
    }

    // handles.last().unwrap().join_handle.join().unwrap();

    {
        let mut abc = handles_mutexed.lock().unwrap();
        for _ in 0..abc.len() {
            let t = abc.pop().unwrap();
            t.join_handle.join().unwrap();
        }
    }

    // Sleep for a while before checking again
    // thread::sleep(std::time::Duration::from_millis(1000));

    progress::finish_progress_bar(final_progress_bar, &pb);
    Ok(())
}

fn poll_worker(
    worker_thread: &WorkerThread,
    muta: &Mutex<Vec<UnitOfWork>>,
    mutb: &Mutex<Vec<UnitOfWork>>,
) -> Result<StatusUpdate> {
    let x: ProgressMessage = Default::default();

    let mut status_report = StatusUpdate {
        movie_basename: String::from(""),
        progress_msg: x,
        file_full_name: String::from(""),
    };

    let thread_progress = worker_thread.progress_message.recv();
    match thread_progress {
        // If a message is received at all
        Result::Ok(i) => {
            match i.status_code {
                // if the thread wants a file, pop the next one and send it
                ProgressStatus::Requesting => {
                    let mut bc_locked = muta.lock().unwrap();
                    if bc_locked.len() > 0 {
                        let path_opt = bc_locked.pop().clone();
                        let _abc = bc_locked.len();
                        worker_thread.unit_of_work.send(path_opt).unwrap();
                    } else {
                        worker_thread.unit_of_work.send(None).unwrap();
                    }
                }
                _ => {
                    // let  bc_locked = muta.lock().unwrap();
                    let abc_locked = mutb.lock().unwrap();

                    let mut f = StatusUpdate {
                        movie_basename: String::from(""),
                        progress_msg: thread_progress.unwrap(),
                        file_full_name: String::from(""),
                    };

                    if abc_locked.iter().any(|axe: &UnitOfWork| {
                        axe.file_number == thread_progress.unwrap().file_number
                    }) {
                        let z = abc_locked
                            .iter()
                            .position(|axe: &UnitOfWork| {
                                axe.file_number == thread_progress.unwrap().file_number
                            })
                            .unwrap();
                        f.movie_basename = abc_locked[z]
                            .file_name
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
