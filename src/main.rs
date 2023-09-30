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
use std::sync::{ mpsc, Mutex };

use crate::progress::ProgressStatus;

#[derive(Clone)]
pub struct UnitOfWork {
    file_name: PathBuf,
    file_number: usize,
}

pub struct UnitsOfWork {
    file_name: Vec<UnitOfWork>,
}

// // https://doc.rust-lang.org/book/ch17-01-what-is-oo.html
impl UnitsOfWork {
    pub fn add(&mut self, value: UnitOfWork) {
        let max = if self.file_name.len() == 0 { 0 } else { self.file_name.len() - 1 };
        self.file_name.push(UnitOfWork { file_name: value.file_name, file_number: max });
    }
}

// pub fn remove(&mut self) -> Option<UnitOfWork>{
//     let result = self.file_name.pop();
//     match result {
//         Some(value) => {

//             Some(value)
//         }
//         None => None,
//     }
// }

//     fn inc_file_number(&mut self){
//         if(self.file_number.len()==0){
//             self.file_number.push(0);
//         }
//         else{
// let max =self.file_number.iter().max().unwrap();
// self.file_number.push(max+1);
//         }
//     }
// }

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
        let data_files: Vec<_> = fs
            ::read_dir(&args.path_to_data)?
            .into_iter()
            .filter(|z| z.is_ok())
            .map(|r| r.unwrap().path())
            .filter(|z| z.is_file())
            .into_iter()
            .filter(|ab| re.is_match(&ab.file_name().unwrap().to_string_lossy()))
            .collect();

        let data_file_len = data_files.len();

        let data_files_mutexed = Mutex::new(data_files);
        let mut handles = vec![];
        let mut fils = UnitsOfWork { file_name: vec![] };

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
            let (tx, worker_rx) = mpsc::channel();
            let (worker_tx, main_rx) = mpsc::channel();
            let ttj = args.clone();
            let handle = thread::spawn(move || {
                check::do_work(i as usize, ttj, worker_tx, worker_rx);
            });

            handles.push((handle, tx, main_rx));
        }

        // let zz = assign_work(args.thread_count);
        // let (tx, rx): (
        //     Sender<progress::ProgressMessage>,
        //     Receiver<progress::ProgressMessage>,
        // ) = channel();

        // let mut status_bar_line_entry = 0;
        // for x in zz {
        //     let tx1 = tx.clone();
        //     // let rx1 = rx.clone();
        //     let kjdfj = args.path_to_cksums.clone();
        //     thread::spawn(move || {
        //         let _ = check::validate_ondisk_md5(
        //             x.wrok,
        //             &kjdfj,
        //             args.bufsize,
        //             status_bar_line_entry,
        //             tx1,

        //         );
        //     });
        //     status_bar_line_entry += 1;
        // }
        // drop(tx);

        let final_progress_bar = args.thread_count.to_string().parse::<usize>().unwrap();

        let mut i = 0;
        loop {
            let active = handles
                .iter()
                .filter(|(_, tx, main_rx)| {
                    let zz = main_rx.try_recv();
                     
                        // If a message is received, pop the next file and send it back
                        match zz.unwrap().status_code {
                            ProgressStatus::Requesting => {
                                let mut path_opt: Option<UnitOfWork> = Default::default();
                                {
                                    let mut bc_locked = data_files_mutexed.lock().unwrap();
                                    let ab = bc_locked.pop();
                                    let path_opt = UnitOfWork {
                                        file_name: ab.unwrap(),
                                        file_number: i,
                                    };

                                    let abc = path_opt.clone();
                                    fils.add(abc);

                                    i += 1;
                                }
                                let jimminy: Option<UnitOfWork> = path_opt.clone();
                                tx.send(path_opt).unwrap();
                                match jimminy {
                                    Some(i) =>{

                                        let movie_basename = i
                                        
                                        .file_name.file_name()
                                        .unwrap()
                                        .to_string_lossy();
                                    progress::something(&movie_basename, zz.unwrap(), &pb, &args);
                                    }
                                    None => {}
                                }

                                
                            }
                            other => {
                                let movie_basename = fils.file_name[
                                    zz.unwrap().file_number
                                ].file_name
                                    .file_name()
                                    .unwrap()
                                    .to_string_lossy();
                                progress::something(&movie_basename, zz.unwrap(), &pb, &args);
                            }
                        }
                        true
                     
                })
                .count();

            // If no active threads remain, break
            if active == 0 {
                break;
            }

            // Sleep for a while before checking again
            thread::sleep(std::time::Duration::from_millis(10));
        }

        for (handle, _, _) in handles {
            handle.join().unwrap();
        }

        progress::finish_progress_bar(final_progress_bar, &pb);
    }

    Ok(())
}

// fn assign_work(threadcnt: u16) -> Vec<Work> {
//     let mut x: Vec<Work> = Vec::new();

//     // these are the movies
//     // z.sort_by_key(|x| x.metadata().unwrap().len());
//     // z.reverse();

//     // now there's a queue per thread in x
//     for ia in 0..threadcnt {
//         // let ab: Vec<PathBuf> = Vec::new();
//         let work = Work {
//             wrok: Vec::new(), // , thread_num: ia
//         };
//         x.insert(ia.into(), work);
//     }

//     for ia in 0..z.len() {

// let tt = FilesToWork {
// path_buf: z[ia],
// file_num: ia
// };

//         x[ia % (threadcnt as usize)].wrok.push(tt);
//     }

//     return x;
// }

// struct Work {
//     // thread_num: u16,
//     wrok: Vec<FilesToWork>,
// }

// pub struct FilesToWork {
//     path_buf: PathBuf,
//     file_num: usize,
// }

// #[cfg(test)]
// mod tests {
//     #[test]
//     fn it_works() {
//         let result = 2 + 2;
//         assert_eq!(result, 4);
//     }
// }
