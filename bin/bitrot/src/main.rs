

use std::io;
use std::env;
use std::fs;
use std::io::BufRead;
use md5::Digest;
use regex::Regex;
// use std::error::Error;
use thiserror::Error;
use anyhow::{Context, Result};



fn main()-> Result<()>{

    let args: Vec<String> = env::args().collect();
    let path_to_movies = &args[1];
    let path_to_par2s = &args[2];

    println!("Using movie path {} and par2 path {}", path_to_movies, path_to_par2s);
    
    
    let movies = fs::read_dir(path_to_movies)?
        .map(|res| res.map(|e| e.path()))
        .collect::<Result<Vec<_>, io::Error>>()?;

    for movie_as_path in movies.iter() {
        
        // idea for converting to string from https://stackoverflow.com/questions/37388107/how-to-convert-the-pathbuf-to-string
        let movie_as_str = movie_as_path.to_string_lossy();
        let movie_basename = movie_as_path.file_name().unwrap().to_string_lossy();
        
        let x = validate_ondisk_md5(&movie_as_str, &movie_basename, &path_to_par2s)?;
        
    }

    Ok(())
}

fn validate_ondisk_md5(movie_path: &str, movie_basenm: &str, par_path: &str)-> Result<(), anyhow::Error> {

    let re = Regex::new(r"\.[Mm][4pP][vV4]$").unwrap();
    let md5ending =".md5.txt";

    if re.is_match(movie_path) {

        let mut par = String::from(par_path);
        par.push_str(&movie_basenm); // /par2path/movienm
        par.push_str(md5ending); // /par2path/movienm.md5.txt
        let par_as_path = std::path::Path::new(&par);

        // if /par2path/movienm.md5.txt exists and is readable
        if fs::metadata(par_as_path).is_ok() {

            // println!("Checking {}...", movie_as_str);
            let digest = cksum(&movie_path);
            
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
                return Err(WordCountError::EmptySource)
                    .context(format!("FAIL, mismatch between {} on-disk md5.", movie_path));
            }
            // else {
            //     return Err(WordCountError::EmptySource)
            //         .context(format!("SUCCESS, match between {} on-disk md5.", movie_path));
            // }
        }
    }

    Ok(())
}

fn cksum(file_path: &str) -> Digest{
    // copy/paste from https://stackoverflow.com/questions/75442962/how-to-do-partial-read-and-calculate-md5sum-of-a-large-file-in-rust
    let f = fs::File::open(file_path).unwrap();
    // Find the length of the file
    let len = f.metadata().unwrap().len();
    // Decide on a reasonable buffer size (100MB in this case, fastest will depend on hardware)
    let buf_len = len.min(1000000*1024*500) as usize;
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


// taken from https://nick.groenen.me/posts/rust-error-handling/
/// WordCountError enumerates all possible errors returned by this library.
#[derive(Error, Debug)]
pub enum WordCountError {
    /// Represents an empty source. For example, an empty text file being given
    /// as input to `count_words()`.
    #[error("Source contains no data")]
    EmptySource,

    /// Represents a failure to read from input.
    #[error("Read error")]
    ReadError { source: std::io::Error },

    /// Represents all other cases of `std::io::Error`.
    #[error(transparent)]
    IOError(#[from] std::io::Error),
}