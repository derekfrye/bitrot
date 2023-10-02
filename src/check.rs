use crate::{progress, UnitOfWork, args::ArgsClean};

use md5::Digest;
use std::io;
use std::io::BufRead;
use std::fs;
use std::path::Path;
// use std::sync::mpsc::Sender;
use std::str;


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

pub async fn do_work(statusbar: usize, a: ArgsClean, tx_back_to_main: async_std::channel::Sender<progress::ProgressMessage>, rx_from_main_to_me: async_std::channel::Receiver<Option<UnitOfWork>>) {

    let mut sbar = progress::ProgressMessage {
        bar_number: statusbar as usize,
        file_number: 0,
        // file_name: movie_bytes.try_into().unwrap(),
        // err: [0].try_into().unwrap(),
        // md5_computed: String::from(""),
        // md5_expected: String::from(""),
        status_code: progress::ProgressStatus::Requesting,
        computed_digest: [0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0],
            ondisk_digest  : [0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0],
    };

    loop {
        // Ask the main thread for the next PathBuf
        tx_back_to_main.send(sbar).await.unwrap();
        
        match rx_from_main_to_me.recv().await {
            Ok( Some(path)) => {
                // println!("Thread {:?} working on file: {:?}", std::thread::current().id(), path.file_name);
                // Here you can add the code to process the file if needed.
                validate_ondisk_md5(path, &a, statusbar, &tx_back_to_main);
            },
          Ok(  None)|Err(_) => {
                // No more files to process
                sbar.status_code= progress::ProgressStatus::ThreadCompleted;
                tx_back_to_main.send(sbar).await.unwrap();
                break;
            }
        }
    }
}

fn validate_ondisk_md5(
    xx: UnitOfWork,
    // movie_basenm: &str,
    a: &ArgsClean,
    // par_path: &str,
    // bufsize: u16,
    statusbar: usize,
    transmission_channel: &async_std::channel::Sender<progress::ProgressMessage>,
   
) -> Result<(), anyhow::Error> {
    let md5ending = ".md5.txt";

    let mut sbar = progress::ProgressMessage {
        bar_number: statusbar as usize,
        file_number: 0,
        // file_name: movie_bytes.try_into().unwrap(),
        // err: [0].try_into().unwrap(),
        // md5_computed: String::from(""),
        // md5_expected: String::from(""),
        status_code: progress::ProgressStatus::Started,
        computed_digest: [0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0],
            ondisk_digest  : [0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0],
    };



    // for x in xx {
        // let movie_as_str = x.to_string_lossy();
        let movie_basename = xx.file_name.file_name().unwrap().to_string_lossy();
let movie_bytes = movie_basename.as_bytes().chunks(255).into_iter().next().unwrap();
// let err: [u8;1024] = None;
// .map(str::from_utf8)
// .collect::<Result<Vec<&str>, _>>()
// .unwrap();

        sbar.file_number= xx.file_number;

        // send we're working on file
        transmission_channel.send(sbar);

        let mut par = String::from(a.path_to_cksums.to_string());
        par.push_str(&movie_basename); // /cksumpath/datafilenm
        par.push_str(md5ending); // /cksumpath/datafilenm.md5.txt
        let par_as_path = Path::new(&par);

        // if /par2path/movienm.md5.txt exists and is readable
        // if fs::metadata(par_as_path).is_ok() {
        let digest = cksum(&movie_basename, a.bufsize);

        // got this idea from initial question
        // on https://stackoverflow.com/questions/75442962/how-to-do-partial-read-and-calculate-md5sum-of-a-large-file-in-rust
        // reads just the first entries in teh file, before any spaces or newllines
        // if par_as_path.metadata().unwrap().len() > 0 {
        let zfdfas = fs::read_to_string(par_as_path).unwrap_or_else(|_| String::from("default"));

        if "default" == zfdfas {
            // let sbar_and_working_file = progress::ProgressMessage {
            //     bar_number: statusbar as usize,
            //     file_name: movie_basename.to_string(),
            //     err: format!("No md5 on disk found for {}\n", &movie_basename.trim()),
            //     md5_computed: String::from(""),
            //     md5_expected: String::from(""),
            //     status_code: progress::ProgressStatus::ParFileError,
            // };

// sbar.err = format!("No md5 on disk found for {}\n", &movie_basename.trim());
sbar.status_code = progress::ProgressStatus::ParFileError;

            transmission_channel.send(sbar);
        } else {
            let md5hash_fromdisk = zfdfas.split_whitespace().next().unwrap();

            let formatted_cksum = format!("{:x}", digest);

            // tell caller this integrity check failed
            if md5hash_fromdisk != formatted_cksum {
                // let sbsbba = progress::ProgressMessage {
                //     bar_number: statusbar as usize,
                //     file_name: movie_basename.to_string(),
                //     err: format!(
                //         "Error: {}, on-disk checksum: {}, our checksum: {}",
                //         movie_basename,
                //         md5hash_fromdisk.to_string(),
                //         format!("{:x}", digest)
                //     ),
                //     md5_computed: md5hash_fromdisk.to_string(),
                //     md5_expected: format!("{:x}", digest).to_string(),
                //     status_code: progress::ProgressStatus::MovieError,
                // };

sbar.status_code = progress::ProgressStatus::MovieError;
sbar.ondisk_digest = md5hash_fromdisk.as_bytes().try_into().unwrap();
sbar.computed_digest = formatted_cksum.as_bytes().try_into().unwrap();

                // send msg
                transmission_channel.send(sbar);
            }
        // }

        // let s4bsbb = progress::ProgressMessage {
        //     bar_number: statusbar as usize,
        //     file_name: movie_basename.to_string(),
        //     err: String::from(""),
        //     md5_computed: String::from(""),
        //     md5_expected: String::from(""),
        //     status_code: progress::ProgressStatus::MovieCompleted,
        // };
        sbar.status_code= progress::ProgressStatus::MovieCompleted;
        transmission_channel.send(sbar);
    }

    // let s4b444sbb = progress::ProgressMessage {
    //     bar_number: statusbar as usize,
    //     file_name: String::from(""),
    //     err: String::from(""),
    //     md5_computed: String::from(""),
    //     md5_expected: String::from(""),
    //     status_code: progress::ProgressStatus::ThreadCompleted,
    // };
    sbar.status_code= progress::ProgressStatus::ThreadCompleted;
    transmission_channel.send(sbar);

    Ok(())
}
