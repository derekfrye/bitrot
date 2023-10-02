mod check;
mod error;
mod progress;
mod args;

use anyhow::{Result, Ok};

// if you want to use some old manual "debug" stuff below
// use chrono::{Local, Timelike};
// use console::style;

use fs2::FileExt;
use regex::Regex;
use std::fs;
use std::io::Write;

use async_std::task;
use std::path::PathBuf;
// use std::sync::mpsc::{  Receiver, Sender };
// use std::sync::mpsc::Sender;
use std::thread;
use std::time::Duration;
use std::sync::{ mpsc, Mutex };

use crate::progress::{ProgressStatus, ProgressMessage};
// use tokio::sync::mpsc;
// use async_std::sync;
use async_std::channel::unbounded ;
// use async_std::task;

#[derive(Clone)]
pub struct UnitOfWork {
    file_name: PathBuf,
    file_number: usize,
}

pub struct UnitsOfWork {
    file_name: Vec<UnitOfWork>,
}

struct HmmFukya {
    movie_basename: String,
    progress_msg: ProgressMessage,
}

// // https://doc.rust-lang.org/book/ch17-01-what-is-oo.html
impl UnitsOfWork {
    pub fn add(&mut self, value: UnitOfWork) {
        let max = if self.file_name.len() == 0 { 0 } else { self.file_name.len() - 1 };
        self.file_name.push(UnitOfWork { file_name: value.file_name, file_number: max });
    }
}

struct Handles {
join_handle:     std::thread::JoinHandle<()>,  
    unit_of_work: async_std::channel::Sender<Option<UnitOfWork>>,  
    progress_message: async_std::channel::Receiver<ProgressMessage>,
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
        let mut handles:Vec<Handles>= vec![];
        

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
            let (tx, worker_rx) = unbounded();
            let (worker_tx, main_rx) = unbounded();
            let ttj = args.clone();

            let handle = thread::spawn(move || {
                check::do_work(i as usize, ttj, worker_tx, worker_rx);
            });

            //handles.push((handle, tx, main_rx));
            handles.push( Handles { join_handle: handle, unit_of_work: tx, progress_message: main_rx });
        }

        let final_progress_bar = args.thread_count.to_string().parse::<usize>().unwrap();

        let mut i = 0;
        let mut doing_nothing = true;
        loop {
            
            let mut fils = UnitsOfWork { file_name: vec![] };

            for Hanx in handles{
            let typos = poll_work(Hanx, data_files_mutexed).unwrap();
            progress::something(&typos.movie_basename, typos.progress_msg, &pb, &args);
            match typos.progress_msg.status_code {
                ProgressStatus::DoingNothin => 
                {
                                    }
                other => {
doing_nothing = false
                }
            }
            }

            if doing_nothing{
    break;
}

            // Sleep for a while before checking again
            thread::sleep(std::time::Duration::from_millis(10));
        }

        for handle in handles {
            handle.join_handle.join().unwrap();
        }

        progress::finish_progress_bar(final_progress_bar, &pb);
    }

    Ok(())
}

 fn poll_work(Hanx:  Handles, muta: Mutex<Vec<PathBuf>>)
-> Result<HmmFukya>
{


    let all_done = HmmFukya{
        movie_basename: String::from(""),
    progress_msg: ProgressMessage { bar_number: 0, status_code: ProgressStatus::MovieError, file_number: 0, ondisk_digest: Default::default(), computed_digest: Default::default() }
    };

    let abd= Hanx.progress_message.recv();
        match abd {
            // If a message is received at all
          Ok( iak  ) => {
            match iak.status_code {
                // ifthe message received is that the thread wants a file to process, pop the next file and send it back
                ProgressStatus::Requesting =>{
                let mut path_opt: Option<UnitOfWork> = Default::default();
                {
                    let mut bc_locked = muta.lock().unwrap();
                    let ab = bc_locked.pop();
                    let path_opt = UnitOfWork {
                        file_name: ab.unwrap(),
                        // file_number: i,
                    };

                    let abc = path_opt.clone();
                    // fils.add(abc);

                    // i += 1;
                }
                let jimminy: Option<UnitOfWork> = path_opt.clone();
              Hanx.unit_of_work.send(path_opt);
                match jimminy {
                    Some(i) => {
                        let movie_basename = i.file_name
                            .file_name()
                            .unwrap()
                            .to_string_lossy();
                        let f = HmmFukya {
movie_basename: movie_basename.to_string(),
progress_msg: iak,
                        };
                        // progress::something(&movie_basename, iak, &pb, &args);
                        Ok(f);
                    }
                    None => {}
                }
            }
            other => {

                let f = HmmFukya {
                    movie_basename: String::from(""),
progress_msg: iak,};
Ok(f);
                }
                // let movie_basename = fils.file_name[iak.file_number].file_name
                //     .file_name()
                //     .unwrap()
                //     .to_string_lossy();
                // progress::something(&movie_basename, iak, &pb, &args);
            }
        
        
        }
        Err(_)=>{
            
        }    
    }


            
Ok(all_done)


}


