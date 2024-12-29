use std::fs;

use encryption_cli::app::parse_cmd;
use tempdir::TempDir;
use utils::test_utils;

#[test] 
fn test_encrypt_file() {
    let tempdir= TempDir::new(".").unwrap();
    let path= tempdir.path();

    let (file, expected)= test_utils::new_test_file(path);
    let expected_encrypted_file=file.with_extension("e");

    let encryption_cmd= vec!["e".to_string(), file.to_str().unwrap().to_string()];
    let password= test_utils::new_random_password(10);
    parse_cmd(encryption_cmd, &mut password.as_bytes()).unwrap();

    assert!(!file.exists(), "file was not deleted");
    assert!(expected_encrypted_file.exists(),"encrypted file not found");
    println!("file encrypted");
    
    let decryption_cmd= vec!["d".to_string(), expected_encrypted_file.to_str().unwrap().to_string()];
    parse_cmd(decryption_cmd, &mut password.as_bytes()).unwrap();

    assert!(file.exists(), "decrypted file not found");
    assert!(expected_encrypted_file.exists(),"encrypted file was deleted");

    assert_eq!(expected, fs::read(file).unwrap(), "file content does not match");
    tempdir.close().unwrap();
}

#[test]
fn test_encrypt_dir() {
    let tempdir= TempDir::new(".").unwrap();
    let path= tempdir.path();
    let base_path= path.join(test_utils::random_str(10)); 
    let expected_encrypted_file= base_path.with_extension("e");
    fs::create_dir(&base_path).unwrap();

    let files = test_utils::new_test_files(&base_path, 3);

    let encryption_cmd= vec!["e".to_string(), base_path.to_str().unwrap().to_string()];
    let password= test_utils::new_random_password(10);
    parse_cmd(encryption_cmd, &mut password.as_bytes()).unwrap();

    assert!(!base_path.exists(), "dir was not deleted");
    assert!(expected_encrypted_file.exists(),"encrypted file not found");
    println!("file encrypted");
    
    let decryption_cmd= vec!["d".to_string(), expected_encrypted_file.to_str().unwrap().to_string()];
    parse_cmd(decryption_cmd, &mut password.as_bytes()).unwrap();

    assert!(expected_encrypted_file.exists(),"encrypted file was deleted");
    for (file,expected) in files {
        assert!(file.exists(), "decrypted file not found. Expected path: {file:?}");
        assert_eq!(expected, fs::read(&file).unwrap(), "file contents do not match. File {file:?}");
    }

    tempdir.close().unwrap();
}

#[test]
fn test_location_flag() {

}

#[test]
fn test_no_delete_flag() {

}

#[test]
fn test_name_flag() {
    
}