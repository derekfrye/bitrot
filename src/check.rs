use crate::args::Mode;
use crate::{ progress, UnitOfWork, args::ArgsClean };

// use clap::Arg;
// use anyhow::Ok;
// use async_std::fs;
use md5::Digest;
// use core::slice::SlicePattern;
use std::io;
use std::io::BufRead;
use std::fs;
use std::path::Path;
use std::sync::mpsc::{ Receiver, Sender };
use std::str;

pub fn do_work(
    statusbar: usize,
    a: ArgsClean,
    tx_back_to_main: Sender<progress::ProgressMessage>,
    rx_from_main_to_me: Receiver<Option<UnitOfWork>>
) {
    let mut sbar = progress::ProgressMessage {
        bar_number: statusbar as usize,
        file_number: 0,
        status_code: progress::ProgressStatus::Requesting,
        computed_digest: Default::default(),
        ondisk_digest: Default::default(),
    };

    loop {
        // Ask the main thread for the next item
        tx_back_to_main.send(sbar).unwrap();

        match rx_from_main_to_me.recv() {
            Ok(Some(path)) => {
                // println!("Thread {:?} working on file: {:?}", std::thread::current().id(), path.file_name);
                validate_ondisk_md5(path, &a, statusbar, &tx_back_to_main);
            }
            Ok(None) | Err(_) => {
                // No more files to process
                sbar.status_code = progress::ProgressStatus::DoingNothin;
                tx_back_to_main.send(sbar).unwrap_or_default();
                break;
            }
        }
    }
}

pub fn do_work_main(
    pathbufs: Vec<UnitOfWork>,
    a: ArgsClean,
    statusbar: u16,
    tx_back_to_main: Sender<progress::ProgressMessage>
) {
    for x in pathbufs {
        validate_ondisk_md5(x, &a, statusbar.into(), &tx_back_to_main);
    }
}

fn validate_ondisk_md5(
    xx: UnitOfWork,
    a: &ArgsClean,
    statusbar: usize,
    transmission_channel: &Sender<progress::ProgressMessage>
) {
    let md5ending = ".md5.txt";

    let mut sbar = progress::ProgressMessage {
        bar_number: statusbar as usize,
        file_number: 0,
        status_code: progress::ProgressStatus::Started,
        computed_digest: Default::default(),
        ondisk_digest: Default::default(),
    };

    let movie_as_str = xx.file_name.to_string_lossy();
    let movie_basename = xx.file_name.file_name().unwrap().to_string_lossy();

    // let mut _i = 0;
    // if &movie_basename == "a.mp4" {
    //     _i += 1;
    // }

    sbar.file_number = xx.file_number;

    // send we're working on file
    transmission_channel.send(sbar).unwrap();

    let mut par = String::from(a.path_to_cksums.to_string());
    par.push_str(&movie_basename); // /cksumpath/datafilenm
    par.push_str(md5ending); // /cksumpath/datafilenm.md5.txt
    let par_as_path = Path::new(&par);

    // if /par2path/movienm.md5.txt exists and is readable
    // if fs::metadata(par_as_path).is_ok() {
    let digest = cksum(&movie_as_str, a.bufsize);

    let formatted_cksum = format!("{:x}", digest);
    sbar.computed_digest = formatted_cksum
        .chars()
        .take(32)
        .collect::<Vec<char>>()
        .try_into()
        .unwrap();

    if a.mode == Mode::Check {
        // got this idea from initial question
        // on https://stackoverflow.com/questions/75442962/how-to-do-partial-read-and-calculate-md5sum-of-a-large-file-in-rust
        // reads just the first entries in teh file, before any spaces or newllines
        // if par_as_path.metadata().unwrap().len() > 0 {
        let md5_ondisk: String = std::fs
            ::read_to_string(par_as_path)
            .unwrap_or_else(|_| String::from("default"));

        if "default" == md5_ondisk {
            // sbar.err = format!("No md5 on disk found for {}\n", &movie_basename.trim());
            sbar.status_code = progress::ProgressStatus::ParFileError;

            transmission_channel.send(sbar).unwrap();
        } else {
            let md5hash_fromdisk = md5_ondisk
                .split_whitespace()
                .next()
                .unwrap_or_else(|| "0000000000000000");

            // hashes do not match
            if md5hash_fromdisk != formatted_cksum {
                sbar.status_code = progress::ProgressStatus::MovieError;

                sbar.ondisk_digest = md5hash_fromdisk
                    .chars()
                    .take(32)
                    .collect::<Vec<char>>()
                    .try_into()
                    .unwrap();

                // tell caller this integrity check failed
                transmission_channel.send(sbar).unwrap();
            }
        }
    }
    sbar.status_code = progress::ProgressStatus::MovieCompleted;
    transmission_channel.send(sbar).unwrap();

    // sbar.status_code = progress::ProgressStatus::ThreadCompleted;
    // transmission_channel.send(sbar).unwrap();
}

fn cksum(file_path: &str, bufsize: u16) -> Digest {
    // https://stackoverflow.com/questions/75442962/how-to-do-partial-read-and-calculate-md5sum-of-a-large-file-in-rust
    let f = fs::File::open(file_path).unwrap();
    // Find the length of the file
    let len = f.metadata().unwrap().len();
    // Decide on a reasonable buffer size (500MB in this case, fastest will depend on hardware)
    let ss: u64 = 1024 * 1024 * (bufsize as u64);
    // println!("Buffer size {}MiB", ss / 1024 / 1024 );
    let buf_len = len.min(ss.into()) as usize;
    let mut buf = io::BufReader::with_capacity(buf_len, f);
    let mut context = md5::Context::new();

    loop {
        // Get a chunk of the file
        let part = buf.fill_buf().unwrap();
        // If that chunk was empty, the reader has reached EOF
        if part.is_empty() {
            break;
        }
        // Add chunk to the md5
        context.consume(part);
        // Tell the buffer that the chunk is consumed
        let part_len = part.len();
        buf.consume(part_len);
    }
    let digest = context.compute();
    return digest;
}
