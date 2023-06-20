use std::io;

fn main() {
    println!("Path to data:");
    let mut guess = String::new();

    io::stdin()
    .read_line(&mut guess)
    .expect("Failed to read path to data.");

    println!("Using data path {}", guess);

    let digest = md5::compute(guess);
    println!("md5 {:x}", digest);
}