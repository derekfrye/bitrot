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

    let entriesd = fs::read_dir(mov)?
        .map(|res| res.map(|e| e.path()))
        .collect::<Result<Vec<_>, io::Error>>()?;

    // let digest = md5::compute(guess);
    // println!("md5 {:x}", digest);

    let xx = entriesd.iter();

    let re = Regex::new(r"\.[Mm][4pP][vV4]$").unwrap();
    let md5ending =".md5.txt";

    for x in xx {
        // https://stackoverflow.com/questions/37388107/how-to-convert-the-pathbuf-to-string
        let mut zz = String::from(x.to_string_lossy());
        // println!("path {}", zz);
        

        if re.is_match(&zz) {

            let  tt = zz.push_str(md5ending).to_owned();

            // let abc = fs::metadata(tt).is_ok();

            if (exists(&tt)) {

            }

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

fn exists(zz: &str) -> bool {
    fs::metadata(zz).is_ok()
}