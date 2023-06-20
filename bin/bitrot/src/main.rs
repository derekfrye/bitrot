use std::io;
use std::env;
use std::fs;
use std::path::Path;
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

    let par2s = fs::read_dir(par2)?
        .map(|res| res.map(|e| e.path()))
        .collect::<Result<Vec<_>, io::Error>>()?;

    // let digest = md5::compute(guess);
    // println!("md5 {:x}", digest);

    let movies_iter = movies.iter();
    let par2_iter = par2s.iter();

    let re = Regex::new(r"\.[Mm][4pP][vV4]$").unwrap();
    let md5ending =".md5.txt";

    for x in movies_iter {
        // https://stackoverflow.com/questions/37388107/how-to-convert-the-pathbuf-to-string
        let movie = x.to_string_lossy().into_owned();
        // println!("path {}", zz);
        

        
        if re.is_match(&movie) {

            let mut par = String::from(par2);
            let fdn = Path::new(&movie);
            let filenm = String::from( fdn.file_name().unwrap().to_str().unwrap());
            par.push_str(&filenm);
            par.push_str(md5ending);

            // let abc = fs::metadata(tt).is_ok();

            if fs::metadata(par.to_owned()).is_ok() {
                println!("Exists: {}", par);
            }

            // if (exists(zz)) {
            //     println!("Exists: {}", zz);
            // }

            // match (Path::new(&tt).exists()) {
            //     true => {
            //         println!("x");
            //     }
            //     false => (),
            // }
        }
    }

    Ok(())
}

fn exists(zz: String) -> bool {
    fs::metadata(zz).is_ok()
}