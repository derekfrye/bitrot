use std::io;
use std::env;
use std::fs;
use std::io::BufRead;

use std::path::Path;
use md5::Digest;

use regex::Regex;

fn main()-> io::Result<()>{

    let args: Vec<String> = env::args().collect();
    // dbg!(args);
    let mov = &args[1];
    let par2 = &args[2];

    println!("Using movie path {} and par2 path {}", mov, par2);

    // println!("Path to data:");
    // let mut guess = String::new();

    // io::stdin()
    // .read_line(&mut guess)
    // .expect("Failed to read path to data.");

    // let data = fs::read_dir(mov)
    //     .expect("x");

    let movies = fs::read_dir(mov)?
        .map(|res| res.map(|e| e.path()))
        .collect::<Result<Vec<_>, io::Error>>()?;

    // let par2s = fs::read_dir(par2)?
    //     .map(|res| res.map(|e| e.path()))
    //     .collect::<Result<Vec<_>, io::Error>>()?;

    // let digest = md5::compute(guess);
    // println!("md5 {:x}", digest);

    let movies_iter = movies.iter();
    // let par2_iter = par2s.iter();

    let re = Regex::new(r"\.[Mm][4pP][vV4]$").unwrap();
    let md5ending =".md5.txt";

    for x in movies_iter {
        // https://stackoverflow.com/questions/37388107/how-to-convert-the-pathbuf-to-string
        let movie = x.to_string_lossy().into_owned();
        // println!("path {}", zz);
        
        if re.is_match(&movie) {

            let mut par = String::from(par2);
            let fdn = Path::new(&movie);
            let filenm = String::from(fdn
                .file_name()
                .unwrap()
                .to_str()
                .unwrap()
            );
            par.push_str(&filenm);
            par.push_str(md5ending);

            // let abc = fs::metadata(tt).is_ok();

            // todo: why do i need to_owned()?
            // does cksum already exist
            if fs::metadata(x.as_path()).is_ok() {
                // println!("Exists: {}", par);
                println!("Checking {}...", movie);
                let digest = cksum(&movie);
                // println!("Cksum {:x}", digest);

                // got this ideas from initial question on https://stackoverflow.com/questions/75442962/how-to-do-partial-read-and-calculate-md5sum-of-a-large-file-in-rust
                // let mut par2contents = Vec::<u8>::new();
                // fs::File::open(par)
                //     .unwrap()
                //     .read_to_end(&mut par2contents).unwrap();

                let foo = fs::read_to_string(x.as_path()).unwrap();
                if foo != format!("{:x}", digest) {
                    println!("computed: {:x} vs. md5 on disk: {}", digest, foo);
                }
            }
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
    let buf_len = len.min(1000000*1024*100) as usize;
    let mut buf = io::BufReader::with_capacity(buf_len, f);
    let mut context = md5::Context::new();
    
    loop {
        // Get a chunk of the file
        let part = buf.fill_buf().unwrap();
        // let part = buf.buffer().fill_buf().unwrap();
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