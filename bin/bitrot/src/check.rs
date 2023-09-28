use md5::Digest;
use std::io;
use std::io::BufRead;
use std::fs;

use std::path::{Path, PathBuf};
use std::sync::mpsc::Sender;

pub fn cksum(file_path: &str, bufsize: u16) -> Digest {
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

pub fn validate_ondisk_md5(
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

    let mut status_bar_and_working_file = statusbar.to_string();
    status_bar_and_working_file.push_str("|");
    
    status_bar_and_working_file.push_str("done");
    status_bar_and_working_file.push_str("|");
    status_bar_and_working_file.push_str(" ");
    transmission_channel.send(status_bar_and_working_file).unwrap();

    Ok(())
}