use std::{env, io::stdin};
use encryption_cli::app;
fn main() {
    let mut stdin= stdin();
    if let Err(e) = app::parse_cmd(env::args().skip(1).collect(), &mut stdin) {
        println!("error: {e}");
    }
}