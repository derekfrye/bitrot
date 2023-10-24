use clap::Parser;

use std::io::{ self, Write };
// use std::io::stdout;

pub fn args_checks() -> ArgsClean {
    let xx = Args::parse();
    let mut zz = ArgsClean {
        path_to_data: xx.path_to_data,
        path_to_cksums: xx.path_to_cksums,
        mode: Mode::Check,
        bufsize: xx.bufsize,
        data_filename_match: xx.data_filename_match,
        thread_count: xx.thread_count,
        pretty_print: xx.pretty_print,
        error_output_file: xx.error_output_file,
        unit_testing: xx.unit_testing,
        alternate_scheduler: xx.alternate_scheduler,
    };
    // let mut jkdfjak = ArgsClean::new();

    match xx.mode.as_str() {
        "check" | "ck" => {
            zz.mode = Mode::Check;
        }
        "create" | "cr" => {
            zz.mode = Mode::Create;
            // println!("mode create.");
        }
        x => {
            println!("Not a valid entry: {}. Setting to {}.", x, "create");
        }
    }

    let jkd = num_cpus::get();
    if xx.thread_count == 0 || (xx.thread_count as usize) > jkd {
        if xx.thread_count == 0 {
            println!("Cannot do 0 threads. Setting thread count to 1.");
            zz.thread_count = 1;
        } else {
            print!(
                "You specified {} threads. I think you have {} cpu cores. Specify thread count [default {}]: ",
                xx.thread_count,
                jkd,
                jkd
            );
            let _ = io::stdout().flush();
            let mut input = String::new();

            io::stdin().read_line(&mut input).expect("failed to read from stdin");

            let trimmed = input.trim();
            match trimmed.parse::<u32>() {
                Ok(i) => {
                    zz.thread_count = i as u16;
                }
                Err(..) => {
                    println!("Not a valid entry: {}. Setting to {}.", trimmed, jkd);
                    zz.thread_count = jkd as u16;
                }
            };
        }

        if zz.thread_count == 0 {
            println!("Cannot do 0 threads. Setting thread count to 1.");
            zz.thread_count = 1;
        }
    }

    return zz;
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

    /// Mode to operate in: check, or create.
    #[arg(short = 'm', long, value_name = "MODE")]
    mode: String,

    /// Buffer size for reading files, in MiB. 512 (default) seems to work well.
    #[arg(short, long, value_name = "BUFFERSIZE")]
    bufsize: u16,

    /// Regex pattern of data files to match against.
    #[arg(short = 'r', long, value_name = "REGEX")]
    data_filename_match: String,

    /// Number of threads to read and checksum data. I suggest set to num of cpu cores. Defaults to 1.
    #[arg(short, long, value_name = "THREADCOUNT")]
    thread_count: u16,

    /// Whether to pretty print progress or not.
    #[arg(short, long)]
    pretty_print: bool,

    /// File to write to. Must be set.
    #[arg(short, long, value_name = "OUTPUTFILE")]
    error_output_file: String,

    /// Do not checksum. Instead, pretend to.
    #[arg(short, long, value_name = "TESTINGONLY")]
    unit_testing: bool,

    /// Use alternate scheduler. Appears less performant. Not recommended. See github issue #1.
    #[arg(short, long, value_name = "ALTSCHEDULER")]
    alternate_scheduler: bool,
}

#[derive(Clone)]
pub struct ArgsClean {
    pub path_to_data: String,
    pub path_to_cksums: String,
    pub mode: Mode,
    pub bufsize: u16,
    pub data_filename_match: String,
    pub thread_count: u16,
    pub pretty_print: bool,
    pub error_output_file: String,
    pub unit_testing: bool,
    pub alternate_scheduler: bool,
}

#[derive(Copy, Clone, Debug, PartialEq)]
pub enum Mode {
    Check,
    Create,
}
