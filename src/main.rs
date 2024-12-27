use std::env;
use encryption_cli::app;
fn main() {
    if let Err(e) = app::parse_cmd(env::args().skip(1).collect()) {
        println!("error: {e}");
    }
}