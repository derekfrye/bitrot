use crate::progress;

use md5::Digest;
use std::io;
use std::io::BufRead;
use std::fs;
use std::path::{ Path, PathBuf };
use std::sync::mpsc::Sender;

fn cksum(file_path: &str, bufsize: u16) -> Digest {
    // copy/paste from https://stackoverflow.com/questions/75442962/how-to-do-partial-read-and-calculate-md5sum-of-a-large-file-in-rust
    let f = fs::File::open(file_path).unwrap();
    // Find the length of the file
    let len = f.metadata().unwrap().len();
    // Decide on a reasonable buffer size (500MB in this case, fastest will depend on hardware)
    let ss: u64 = 1000000000 * (bufsize as u64);
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
    transmission_channel: Sender<progress::ProgressMessage>
) -> Result<(), anyhow::Error> {
    let md5ending = ".md5.txt";

    for x in xx {
        let movie_as_str = x.to_string_lossy();
        let movie_basename = x.file_name().unwrap().to_string_lossy();

        let sbar = progress::ProgressMessage {
            bar_number: statusbar as usize,
            file_name: movie_basename.to_string(),
            err: String::from(""),
            md5_computed: String::from(""),
            md5_expected: String::from(""),
            status_code: progress::ProgressStatus::Started,
        };

        // send we're working on file
        transmission_channel.send(sbar).unwrap();

        let mut par = String::from(par_path);
        par.push_str(&movie_basename); // /cksumpath/datafilenm
        par.push_str(md5ending); // /cksumpath/datafilenm.md5.txt
        let par_as_path = Path::new(&par);

        // if /par2path/movienm.md5.txt exists and is readable
        // if fs::metadata(par_as_path).is_ok() {
        let digest = cksum(&movie_as_str, bufsize);

        // got this idea from initial question
        // on https://stackoverflow.com/questions/75442962/how-to-do-partial-read-and-calculate-md5sum-of-a-large-file-in-rust
        // reads just the first entries in teh file, before any spaces or newllines
        // if par_as_path.metadata().unwrap().len() > 0 {
        let zfdfas = fs::read_to_string(par_as_path).unwrap_or_else(|_| String::from("default"));

        if "default" == zfdfas {
            let sbar_and_working_file = progress::ProgressMessage {
                bar_number: statusbar as usize,
                file_name: movie_basename.to_string(),
                err: format!("No md5 on disk found for {}\n", &movie_basename.trim()),
                md5_computed: String::from(""),
                md5_expected: String::from(""),
                status_code: progress::ProgressStatus::ParFileError,
            };

            transmission_channel.send(sbar_and_working_file).unwrap();
        } else {
            let md5hash_fromdisk = zfdfas.split_whitespace().next().unwrap();

            let formatted_cksum = format!("{:x}", digest);

            // tell caller this integrity check failed
            if md5hash_fromdisk != formatted_cksum {
                let sbsbba = progress::ProgressMessage {
                    bar_number: statusbar as usize,
                    file_name: movie_basename.to_string(),
                    err: String::from(""),
                    md5_computed: md5hash_fromdisk.to_string(),
                    md5_expected: format!("{:x}", digest).to_string(),
                    status_code: progress::ProgressStatus::MovieError,
                };

                // send msg
                transmission_channel.send(sbsbba).unwrap();
            }
        }
        
        let s4bsbb = progress::ProgressMessage {
            bar_number: statusbar as usize,
            file_name: movie_basename.to_string(),
            err: String::from(""),
            md5_computed: String::from(""),
            md5_expected: String::from(""),
            status_code: progress::ProgressStatus::MovieCompleted,
        };
        transmission_channel.send(s4bsbb).unwrap();
    }

    let s4b444sbb = progress::ProgressMessage {
        bar_number: statusbar as usize,
        file_name: String::from(""),
        err: String::from(""),
        md5_computed: String::from(""),
        md5_expected: String::from(""),
        status_code: progress::ProgressStatus::ThreadCompleted,
    };
    transmission_channel.send(s4b444sbb).unwrap();

    Ok(())
}
