mod error;
mod progress;
// use crate::progress::hosting;

use anyhow::Result;
use chrono::{Local, Timelike};
use clap::Parser;
use console::style;
use md5::Digest;
use regex::Regex;
use std::fs;
// use std::fs::File;
use std::io;
use std::io::BufRead;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::mpsc::channel;
use std::sync::mpsc::Sender;
use std::time::Duration;
use fs2::FileExt;

// use crossbeam_channel::{unbounded, Sender};
use std::thread;

// use thiserror::Error;

fn main() -> Result<()> {
    let args = Args::parse();

    if args.thread_count == 0 {
        panic!("wha");
    }

    // let x = Path::new(&args.error_output_file);
    // let _=fs::write(&args.error_output_file, "tt\n");

    // }

    if args.mode == "ck" {
        println!(
            "Using data path {} and checksums path {}",
            args.path_to_data, args.path_to_cksums
        );

        // r"\.[Mm][4pP][vV4]$"
        let re = Regex::new(&args.data_filename_match).unwrap();

        // idea from https://stackoverflow.com/questions/58062887/filtering-files-or-directories-discovered-with-fsread-dir
        let data_files: Vec<_> = fs::read_dir(args.path_to_data)?
            .into_iter()
            .filter(|z| z.is_ok())
            .map(|r| r.unwrap().path())
            .filter(|z| z.is_file())
            .into_iter()
            .filter(|ab| re.is_match(&ab.file_name().unwrap().to_string_lossy()))
            .collect();

        let now = Local::now();
        let (is_pm, hour) = now.hour12();
        println!(
            "{:02}:{:02}:{:02}{} Processing {} files...",
            style(hour).bold().dim(),
            style(now.minute()).bold().dim(),
            style(now.second()).bold().dim(),
            style(if is_pm { "p" } else { "a" }).bold().dim(),
            data_files.len()
        );

        let pb = progress::build_progress_bar_export(
            data_files.len(),
            args.thread_count,
            args.pretty_print,
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
                    let _ = validate_ondisk_md5(x.wrok, &kjdfj, args.bufsize, status_bar_line_entry, tx1);
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
            // len of two just means we're starting to work on the file
            if xa.len() == 2 {
                // pb[sb].set_message(format!("{djk}..."));
                progress::set_message(sb, djk, &pb);
            } 
            // marking the file as done
            else if xa.len() == 3 {
                progress::finish_progress_bar(sb, &pb);
            } 
            // just incrementing progress for the file
            else if xa.len() == 4 {
                // pb[args.thread_count.to_string().parse::<usize>().unwrap()].set_message(format!("..."));
                progress::increment_progress_bar(final_progress_bar, &pb);
                // progress::finish_progress_bar(sb, &pb);
            } 
            // the par2 file didn't exist, wasn't readable, etc.
            else if xa.len() == 5 {
                let mut data = String::from("Error: ");
                data.push_str(xa[1]);
                // data.push_str(&format!(", expected: {}", xa[5]));
                // data.push_str(&format!(", got: {}\n", xa[6]));
                // data.p
                // fs::write( &args.error_output_file, data).unwrap();

                let mut fil = fs::OpenOptions::new()
                .write(true)
                .append(true)
                .create(true)
                .open(&args.error_output_file)?;
                // let fil = File::open(&args.error_output_file)?;
                fil.lock_exclusive()?;

                // let mut xxx = fs::OpenOptions::new()
                //     .write(true)
                //     .append(true)
                //     .create(true)
                //     .open(&args.error_output_file)
                //     .expect("cannot open file");
                // let jkdfjkadf = data.clone();
                fil.write(data.as_bytes()).unwrap();

                fil.unlock()?;
            }
            // there was a checksum mismatch for the file
            else if xa.len() == 7 {
                let mut data = String::from("Error: ");
                data.push_str(xa[4]);
                data.push_str(&format!(", expected: {}", xa[5]));
                data.push_str(&format!(", got: {}\n", xa[6]));
                // data.p
                // fs::write( &args.error_output_file, data).unwrap();

                let mut fil = fs::OpenOptions::new()
                .write(true)
                .append(true)
                .create(true)
                .open(&args.error_output_file)?;
                fil.lock_exclusive()?;

                // let mut xxx = fs::OpenOptions::new()
                //     .write(true)
                //     .append(true)
                //     .create(true)
                //     .open(&args.error_output_file)
                //     .expect("cannot open file");
                // let jkdfjkadf = data.clone();
                fil.write(data.as_bytes()).unwrap();
                // write!( xxx, "{}", data.  );


                fil.unlock()?;
                //  let  jkdf= data

                // let ipz = data.clone();

                // zip(String::from(&data).as_str(), &args.error_output_file);
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
    ab: Sender<String>,
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

    // let threadworkers = Vec::new();

    // now there's a queue per thread in x
    for ia in 0..threadcnt {
        // let ab: Vec<PathBuf> = Vec::new();
        let work = Work {
            wrok: Vec::new(), // , thread_num: ia
        };
        x.insert(ia.into(), work);
    }

    for ia in 0..z.len() {
        x[ia % threadcnt as usize].wrok.push(z[ia].to_owned());
    }

    return x;
}

fn validate_ondisk_md5(
    xx: Vec<PathBuf>,
    // movie_basenm: &str,
    par_path: &str,
    bufsize: u16,
    statusbar: u16,
    transmission_channel: Sender<String>,
) -> Result<(), anyhow::Error> {
    let md5ending = ".md5.txt";

    // if re.is_match(movie_path) {
    for x in xx {
        let movie_as_str = x.to_string_lossy();
        let movie_basename = x.file_name().unwrap().to_string_lossy();

        // comes in as an auto-incremented integer, indicating which "line" on the pretty print output we can update
        let mut status_bar_and_working_file = statusbar.to_string();
        status_bar_and_working_file.push_str("|");
        status_bar_and_working_file.push_str(&movie_basename);
        // send we're working on file
        transmission_channel.send(status_bar_and_working_file).unwrap();

        let mut par = String::from(par_path);
        par.push_str(&movie_basename); // /cksumpath/datafilenm
        par.push_str(md5ending); // /cksumpath/datafilenm.md5.txt
        let par_as_path = Path::new(&par);

        // if /par2path/movienm.md5.txt exists and is readable
        // if fs::metadata(par_as_path).is_ok() {
        let digest = cksum(&movie_as_str, bufsize);

        // let mut md5hash_fromdisk = "x";

        // got this ideas from initial question
        // on https://stackoverflow.com/questions/75442962/how-to-do-partial-read-and-calculate-md5sum-of-a-large-file-in-rust
        // reads just the first entries in teh file, before any spaces or newllines
        // if par_as_path.metadata().unwrap().len() > 0 {
        let zfdfas = fs::read_to_string(par_as_path).unwrap_or_else(|_| String::from("default"));

        if "default" == zfdfas {
            
            
            let mut status_bar_and_working_file = statusbar.to_string();
            status_bar_and_working_file.push_str("|");
            // pos 2
            status_bar_and_working_file.push_str(format!("No md5 on disk found for {}\n", &movie_basename.trim()).as_str());
            status_bar_and_working_file.push_str("|");
            // pos 3
            status_bar_and_working_file.push_str(" ");
            status_bar_and_working_file.push_str("|");
            // pos 4
            status_bar_and_working_file.push_str(" ");
            status_bar_and_working_file.push_str("|");
            // pos 5
            status_bar_and_working_file.push_str(&movie_basename);
            transmission_channel.send(status_bar_and_working_file).unwrap();
            
            // i think (hope?) this return value is ignored
            // return Err(error::AppError::EmptySource)
            //     .context(format!("No md5 on disk found for {}", &movie_basename));
        } else {
            let md5hash_fromdisk = zfdfas.split_whitespace().next().unwrap();

            let formatted_cksum = format!("{:x}", digest);

            // tell caller this integrity check failed
            if md5hash_fromdisk != formatted_cksum {
                //Err(InvalidLookahead(movie_path));
                // return Err(AppError::ConfigLoad { source: movie_path });
                // return Err(error::AppError::MismatchError).context(format!(
                //     "FAIL, mismatch between {} on-disk md5.",
                //     &movie_basename
                // ));
                // 7-array
                // pos 1
                let mut status_bar_and_working_file = statusbar.to_string();
                status_bar_and_working_file.push_str("|");
                // pos 2
                status_bar_and_working_file.push_str(" ");
                status_bar_and_working_file.push_str("|");
                // pos 3
                status_bar_and_working_file.push_str(" ");
                status_bar_and_working_file.push_str("|");
                // pos 4
                status_bar_and_working_file.push_str(" ");
                status_bar_and_working_file.push_str("|");
                // pos 5
                status_bar_and_working_file.push_str(&movie_basename);
                status_bar_and_working_file.push_str("|");
                // pos 6
                status_bar_and_working_file.push_str(&md5hash_fromdisk);
                status_bar_and_working_file.push_str("|");
                // pos 7
                status_bar_and_working_file.push_str(&format!("{:x}", digest));

                // send msg
                transmission_channel.send(status_bar_and_working_file).unwrap();
            }
        }
        // } else {
        //     return Err(error::AppError::EmptySource)
        //         .context(format!("No md5 on disk found for {}", &movie_basename));
        // }

        // send we're done w/this unit of work
        let mut status_bar_and_working_file = statusbar.to_string();
        status_bar_and_working_file.push_str("|");
        status_bar_and_working_file.push_str(" ");
        status_bar_and_working_file.push_str("done");
        status_bar_and_working_file.push_str("|");
        status_bar_and_working_file.push_str(" ");
        status_bar_and_working_file.push_str("|");
        status_bar_and_working_file.push_str(" ");
        transmission_channel.send(status_bar_and_working_file).unwrap();
    }
    Ok(())
}

fn cksum(file_path: &str, bufsize: u16) -> Digest {
    // copy/paste from https://stackoverflow.com/questions/75442962/how-to-do-partial-read-and-calculate-md5sum-of-a-large-file-in-rust
    let f = fs::File::open(file_path).unwrap();
    // Find the length of the file
    let len = f.metadata().unwrap().len();
    // Decide on a reasonable buffer size (500MB in this case, fastest will depend on hardware)
    let ss: u64 = 1000000000 * bufsize as u64;
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

// help at https://docs.rs/clap/latest/clap/_derive/_tutorial/index.html
#[derive(Parser)]
#[command(author, version, about, long_about = None)]
struct Args {
    /// Path to the data files to checksum.
    #[arg(short = 'd', long, value_name = "DATA")]
    path_to_data: String,

    /// Path to the on-disk checksums, must match by /data files/filename.md5.txt.
    #[arg(short = 'c', long, value_name = "CKSUMS")]
    path_to_cksums: String,

    /// Mode to operate in. Ck or create.
    #[arg(short = 'm', long, value_name = "MODE")]
    mode: String,

    /// Buffer size for reading files, in MiB. 512 (default) seems to work well.
    #[arg(short, long, value_name = "BUFFERSIZE")]
    bufsize: u16,

    /// Regex pattern of data files to match against.
    #[arg(short = 'r', long, value_name = "REGEX")]
    data_filename_match: String,

    /// Number of threads to read and checksum data. I suggest set to num of cpu cores. Default 1.
    #[arg(short, long, value_name = "THREADCOUNT")]
    thread_count: u16,

    /// Whether to print progress or not.
    #[arg(short, long)]
    pretty_print: bool,

    /// File to write errors to. If not set, halts program on first error.
    #[arg(short, long, value_name = "ERRORFILE")]
    error_output_file: String,

    /// Do not checksum. Instead, pretend to.
    #[arg(short, long, value_name = "TESTINGONLY")]
    unit_testing: bool,
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
