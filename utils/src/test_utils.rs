use std::collections::HashMap;
use std::path::{Path,PathBuf};
use std::fs;

use rand::distributions::{Alphanumeric, Standard};
use rand::Rng;


//creates a new file in the provided path.
//panics if the file already exists
pub fn new_test_file(base_path: &Path)-> (PathBuf,Vec<u8>)  {
    let file_path= base_path.join(random_str(10)).with_extension("txt");
    assert!(!file_path.exists());

    let data=random_bytes();
    fs::write(&file_path, &data).unwrap();

    (file_path,data)
}

//creates num files in the provided path
//panics if a file already exists
pub fn new_test_files(base_path:&Path, num: usize) -> HashMap<PathBuf, Vec<u8>> {
    let mut m= HashMap::new();
    for _ in 0..num {
        let (file,data)= new_test_file(base_path);
        m.insert(file, data);
    }

    m
}

pub fn new_random_password(len: usize) -> String {
    random_str(len)
}

pub fn random_str(len: usize) -> String {
    rand::thread_rng().sample_iter(&Alphanumeric).take(len).map(|x|char::from(x)).collect()
}

pub fn random_bytes() -> Vec<u8> {
    let len= rand::random::<usize>()%100;
    rand::thread_rng().sample_iter(Standard).take(len).collect()
}