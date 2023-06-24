use std::io;
// use std::env;
use std::fs;
use std::io::BufRead;
// use std::path::{Path};
// use clap::error::Result;
use md5::Digest;
use regex::Regex;
// use std::error::Error;
use thiserror::Error;
use anyhow::{Context, Result};
use clap::Parser;
use chrono::{Timelike, Local};
use indicatif::{ProgressBar, ProgressStyle, MultiProgress};
use std::time::Duration;
use console::{style};


fn main()-> Result<()>{

    let args = Args::parse();
    
    if args.mode == "ck" {
        println!("Using data path {} and cksum path {}", args.path_to_data, args.cksums);    
        
        // idea from https://stackoverflow.com/questions/58062887/filtering-files-or-directories-discovered-with-fsread-dir
        let movies: Vec<_> = fs::read_dir(args.path_to_data)?
            .into_iter()
            .filter(|z| z.is_ok())
            .map(|r| r.unwrap().path())
            .filter(|z| z.is_file())
            // .into_iter().collect();
            // .collect::Result<Vec<_>, io::e();
            // .collect::<Result<Vec<PathBuf>>, io::Error>()?;
            .collect();

        let now = Local::now();
        let (is_pm, hour) = now.hour12();
        println!("{:02}:{:02}:{:02}{} Processing {} files..."
            ,  style(hour).bold().dim()
            ,  style(now.minute()).bold().dim()
            ,  style(now.second()).bold().dim()
            ,  style(if is_pm { "p" } else { "a" }).bold().dim()
            , movies.len()
        );


        let i = movies.len();
        let pb = build_progress_bar_export(i);
        
        // iterate through movies and do the compare
        for movie_as_path in movies.iter() {
            // idea for converting to string from https://stackoverflow.com/questions/37388107/how-to-convert-the-pathbuf-to-string
            let movie_as_str = movie_as_path.to_string_lossy();
            let movie_basename = movie_as_path.file_name().unwrap().to_string_lossy();
            
            pb[0].set_message(format!("{movie_basename}..."));
            let _ = validate_ondisk_md5(&movie_as_str, &movie_basename, &args.cksums, args.bufsize)?;
            pb[0].inc(1);
            pb[1].inc(1);
        }

        pb[0].finish();
        pb[1].finish();

    }
    Ok(())
}

fn validate_ondisk_md5(movie_path: &str, movie_basenm: &str, par_path: &str, bufsize: u16)-> Result<(), anyhow::Error> {

    let re = Regex::new(r"\.[Mm][4pP][vV4]$").unwrap();
    let md5ending =".md5.txt";

    if re.is_match(movie_path) {

        let mut par = String::from(par_path);
        par.push_str(&movie_basenm); // /par2path/movienm
        par.push_str(md5ending); // /par2path/movienm.md5.txt
        let par_as_path = std::path::Path::new(&par);

        // if /par2path/movienm.md5.txt exists and is readable
        if fs::metadata(par_as_path).is_ok() {
            
            let digest = cksum(&movie_path, bufsize);
            
            let mut md5hash_fromdisk = String::from("x");
            
            // got this ideas from initial question on https://stackoverflow.com/questions/75442962/how-to-do-partial-read-and-calculate-md5sum-of-a-large-file-in-rust
            // reads just the first entries in teh file, before any spaces or newllines
            if par_as_path.metadata().unwrap().len() > 0 {
                md5hash_fromdisk = fs::read_to_string(par_as_path).unwrap().split_whitespace().collect();
            }

            // tell caller this integrity check failed
            if md5hash_fromdisk != format!("{:x}", digest) {
                //Err(InvalidLookahead(movie_path));
                // return Err(AppError::ConfigLoad { source: movie_path });
                return Err(AppError::MismatchError)
                    .context(format!("FAIL, mismatch between {} on-disk md5.", movie_path));
            }
        }
        else {
            return Err(AppError::EmptySource)
                    .context(format!("No md5 on disk found for {}", movie_path));
        }
    }

    Ok(())
}

fn cksum(file_path: &str, bufsize: u16) -> Digest{
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
#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    /// Path to the data files to checksum
    #[arg(short = 'd', long,  value_name = "DATA")]
    path_to_data: String,

    /// Path to the on-disk checksums, must match by /data files/filename.md5.txt
    #[arg(short = 'c', long, value_name = "CKSUMS")]
    cksums: String,

    /// Mode to operate in. Ck or create.
    #[arg(short = 'm', long,  value_name = "MODE")]
    mode: String,

    /// Buffer size for reading files, in MiB. 512 seems to work well.
    #[arg(short, long,  value_name = "BUFFERSIZE")]
    bufsize: u16,
}

// taken from https://nick.groenen.me/posts/rust-error-handling/
#[derive(Error, Debug)]
enum AppError {
    /// Represents an empty source. For example, an empty text file being given
    /// as input to `count_words()`.
    #[error("Missing MD5")]
    EmptySource,

    // /// Represents a failure to read from input.
    #[error("Mismatch MD5")]
    MismatchError,
    // ReadError { source: std::io::Error },    

    /// Represents all other cases of `std::io::Error`.
    #[error(transparent)]
    IOError(#[from] std::io::Error),
}

fn build_progress_bar_export(total_messages: usize) -> Vec<ProgressBar> {
    
    

    let mut z: Vec<ProgressBar> = Vec::new();
    let m = MultiProgress::new();
    
    let pb = m.add(ProgressBar::new(total_messages.try_into().unwrap()));
    // z.append(pb);
    
    let spinner_style = ProgressStyle::with_template("{prefix:.bold.dim} {spinner} {wide_msg}")
        .unwrap()
        .tick_chars("⠁⠂⠄⡀⢀⠠⠐⠈ ");

    pb.set_style(spinner_style.clone());

    pb.set_position(0);
    pb.enable_steady_tick(Duration::from_millis(100));
    
    let pb1 = m.add(ProgressBar::new(total_messages.try_into().unwrap()));

    pb1.set_style(
        ProgressStyle::default_bar()
            .template(
                "{spinner:.green} [{elapsed}] [{bar:.blue}] {pos}/{len} (ETA: {eta})",
            )
            .unwrap()
            .progress_chars("#>-"),
    );

    pb1.set_position(0);
    pb1.enable_steady_tick(Duration::from_millis(100));

    z.insert(0, pb);
    z.insert(1, pb1);

    return z;
}