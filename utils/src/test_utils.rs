use std::path::{Path,PathBuf};
use std::fs;

use rand::distributions::{Alphanumeric, Standard};
use rand::Rng;


pub fn new_test_file(base_path: &Path)-> (PathBuf,Vec<u8>)  {
    let file_path= base_path.join(random_str(10)).with_extension("txt");
    assert!(!file_path.exists());

    let data=random_bytes();
    fs::write(&file_path, &data).unwrap();

    (file_path,data)
}

pub fn new_random_password(max_len: usize) -> String {
    random_str(rand::random::<usize>()%max_len+1)
}

pub fn random_str(len: usize) -> String {
    rand::thread_rng().sample_iter(&Alphanumeric).take(len).map(|x|char::from(x)).collect()
}

pub fn random_bytes() -> Vec<u8> {
    let len= rand::random::<usize>()%100;
    rand::thread_rng().sample_iter(Standard).take(len).collect()
}