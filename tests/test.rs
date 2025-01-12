use std::{fs, path::Path};

use encryption_cli::app::parse_cmd;
use tempdir::TempDir;
use utils::test_utils;

#[test] 
fn test_encrypt_file() {
    let tempdir= TempDir::new("").unwrap();
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
    let tempdir= TempDir::new("").unwrap();
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
fn test_encrypt_nested_dir() {
    let tempdir= TempDir::new("").unwrap();
    let path= tempdir.path();
    
    let dir= path.join(test_utils::random_str(10));
    let inner_dir= dir.join(test_utils::random_str(10));
    fs::create_dir_all(&inner_dir).unwrap();
    
    let (outer_file, outer_file_data)= test_utils::new_test_file(&dir);
    let (inner_file,inner_file_data )=test_utils::new_test_file(&inner_dir);
    
    let expected_file= path.join(dir.with_extension("e").file_name().unwrap());

    println!("outer file path: {outer_file:?}");
    println!("inner file path: {inner_file:?}");

    let pw= test_utils::new_random_password(10);
    let encrypt_cmd= vec!["e".into(), dir.to_str().unwrap().to_string()];
    parse_cmd(encrypt_cmd, &mut pw.as_bytes()).unwrap();
    
    assert!(!dir.exists(), "files were not deleted");
    assert!(expected_file.exists(), "encrypted file not found");

    let decrypt_cmd= vec!["d".into(), expected_file.to_str().unwrap().to_string()];
    parse_cmd(decrypt_cmd, &mut pw.as_bytes()).unwrap();

    assert!(dir.exists(), "outer directory not found");

    assert!(inner_dir.exists(),"inner directory not found");
    assert!(outer_file.exists(),"outer file not found");
    
    let outer_entries=dir.read_dir().unwrap().count();
    assert_eq!( outer_entries, 2,"expected 2 entries in the outer directory. Got {outer_entries}");
    assert_eq!(fs::read(outer_file).unwrap(), outer_file_data, "wrong outer file content");

    assert!(inner_file.exists());
    let inner_entries=inner_dir.read_dir().unwrap().count();
    assert_eq!(inner_entries, 1, "expected 1 entry in the inner directory. Got {inner_entries}");
    assert_eq!(fs::read(inner_file).unwrap(), inner_file_data, "wrong inner file content");

    tempdir.close().unwrap();
}

#[test]
fn test_location_flag() {
    let tempdir=TempDir::new("").unwrap();
    let path= tempdir.path();
    let (file,_)= test_utils::new_test_file(path);

    let location_dir=path.join(test_utils::random_str(10));
    fs::create_dir(&location_dir).unwrap();

    let expected_encrypted_file= location_dir.join(file.with_extension("e").file_name().unwrap());

    let cmd= vec!["e".to_string(), file.to_str().unwrap().to_string(),"--location".to_string(), location_dir.to_str().unwrap().to_string()];
    let pw= test_utils::new_random_password(10);
    parse_cmd(cmd, &mut pw.as_bytes()).unwrap();

    assert!(expected_encrypted_file.exists(),"encrypted file not found");

    let location_dir= path.join(test_utils::random_str(10));
    fs::create_dir(&location_dir).unwrap();
    let expected_decrypted_file= location_dir.join(file.file_name().unwrap());

    let cmd= vec!["d".to_string(), expected_encrypted_file.to_str().unwrap().to_string(),"--location".to_string(), location_dir.to_str().unwrap().to_string()];
    parse_cmd(cmd, &mut pw.as_bytes()).unwrap();
    
    assert!(expected_decrypted_file.exists(),"decrypted file not found");
    tempdir.close().unwrap();
}

#[test]
fn test_relative_paths() {
    let tempdir=TempDir::new("").unwrap();
    let path= tempdir.path();

    let start_cd= std::env::current_dir().unwrap();
    std::env::set_current_dir(path).unwrap();

    let (file,_)= test_utils::new_test_file(path);
    let relative_file_path= Path::new(".").join(file.file_name().unwrap());

    let dir_name=test_utils::random_str(10);
    let location_dir=path.join(&dir_name);
    fs::create_dir(&location_dir).unwrap();


    let relative_location= format!(".\\{}", &dir_name);
    let expected_encrypted_file= location_dir.join(file.with_extension("e").file_name().unwrap());

    let cmd= vec!["e".to_string(), relative_file_path.to_str().unwrap().to_string(),"--location".to_string(), relative_location.clone()];
    let pw= test_utils::new_random_password(10);
    parse_cmd(cmd, &mut pw.as_bytes()).unwrap();

    assert!(expected_encrypted_file.exists(),"encrypted file not found");

    let dir_name= test_utils::random_str(10);
    let location_dir= path.join(&dir_name);
    fs::create_dir(&location_dir).unwrap(); 

    let relative_encrypted_file_path= Path::new(&relative_location).join(expected_encrypted_file.file_name().unwrap());
    let relative_location=format!(".\\{}",&dir_name);
    let expected_decrypted_file=location_dir.join(file.file_name().unwrap());
    
    let cmd=vec!["d".to_string(), relative_encrypted_file_path.to_str().unwrap().to_string(), "--location".to_string(), relative_location];
    parse_cmd(cmd, &mut pw.as_bytes()).unwrap();

    assert!(expected_decrypted_file.exists(), "decrypted file not found");

    std::env::set_current_dir(start_cd).unwrap();
    tempdir.close().unwrap(); 
}

#[test]
fn test_encrypt_invalid_location() {
    let tempdir=TempDir::new("").unwrap();
    let path= tempdir.path();
    let (file,_)= test_utils::new_test_file(path);

    let location_dir=path.join(test_utils::random_str(10));

    let cmd= vec!["e".to_string(), file.to_str().unwrap().to_string(),"--location".to_string(), location_dir.to_str().unwrap().to_string()];
    let pw= test_utils::new_random_password(10);

    assert!(parse_cmd(cmd, &mut pw.as_bytes()).is_err(),"expected error");
    assert!(!location_dir.exists(),"the program created the directory");

    tempdir.close().unwrap();
}

#[test] 
fn test_decrypt_invalid_location() {
    let tempdir=TempDir::new("").unwrap();
    let path= tempdir.path();
    let (file,_)= test_utils::new_test_file(path);

    let location_dir=path.join(test_utils::random_str(10));
    fs::create_dir(&location_dir).unwrap();

    let expected_encrypted_file= location_dir.join(file.with_extension("e").file_name().unwrap());

    let cmd= vec!["e".to_string(), file.to_str().unwrap().to_string(),"--location".to_string(), location_dir.to_str().unwrap().to_string()];
    let pw= test_utils::new_random_password(10);
    parse_cmd(cmd, &mut pw.as_bytes()).unwrap();

    assert!(expected_encrypted_file.exists(),"encrypted file not found");

    let location_dir= path.join(test_utils::random_str(10));

    let cmd= vec!["d".to_string(), expected_encrypted_file.to_str().unwrap().to_string(),"--location".to_string(), location_dir.to_str().unwrap().to_string()];

    assert!(parse_cmd(cmd, &mut pw.as_bytes()).is_err(),"expected error");
    assert!(!location_dir.exists(), "the program created the directory");    
    tempdir.close().unwrap();

}

#[test]
fn test_no_delete_flag() {
    let tempdir= TempDir::new("").unwrap();
    let path= tempdir.path();

    let (file, _)= test_utils::new_test_file(path);

    let cmd= vec!["e".to_string(), file.to_str().unwrap().to_string(), "--no-delete".to_string()];
    let pw= test_utils::new_random_password(10);
    parse_cmd(cmd, &mut pw.as_bytes()).unwrap();

    assert!(file.exists(), "file was deleted");

    let cmd= vec!["e".to_string(), file.to_str().unwrap().to_string()];
    parse_cmd(cmd, &mut pw.as_bytes()).unwrap();
    
    assert!(!file.exists(), "file was not deleted");

    tempdir.close().unwrap();
}

#[test]
fn test_name_flag() {
    let tempdir= TempDir::new("").unwrap();
    let path= tempdir.path();

    let (file, _)= test_utils::new_test_file(path);
    let name= test_utils::random_str(10);
    let expected_file= path.join(&name).with_extension("e");

    let cmd= vec!["e".to_string(), file.to_str().unwrap().to_string(), "--name".to_string(), name.clone()];
    let pw= test_utils::new_random_password(10);
    parse_cmd(cmd, &mut pw.as_bytes()).unwrap();

    assert!(expected_file.exists(),"file with name '{}' not found",&name);

    tempdir.close().unwrap();
}

#[test]
fn test_invalid_name_flag() {
    let tempdir= TempDir::new("").unwrap();
    let path= tempdir.path();

    let (file, _)= test_utils::new_test_file(path);
    let mut name= test_utils::random_str(10);
    name.push_str("/test");

    let cmd= vec!["e".to_string(), file.to_str().unwrap().to_string(), "--name".to_string(), name.clone()];
    let pw= test_utils::new_random_password(10);
    let res= parse_cmd(cmd, &mut pw.as_bytes());

    assert!(res.is_err(), "expected error");

    tempdir.close().unwrap();
}

#[test]
fn test_corrupted_file() {
    let tempdir= TempDir::new(".").unwrap();
    let path= tempdir.path();

    let (file, _)= test_utils::new_test_file(path);
    let encrypted_file=file.with_extension("e");

    let encryption_cmd= vec!["e".to_string(), file.to_str().unwrap().to_string()];
    let password= test_utils::new_random_password(10);
    parse_cmd(encryption_cmd, &mut password.as_bytes()).unwrap();

    //change the file
    let mut data= fs::read(&encrypted_file).unwrap();
    assert!(data.len()>0, "encrypted file is empty");
    let i=rand::random::<usize>()%data.len();
    data[i] = match data[i]==0 {
        true=> 1,
        false=> 0, 
    };
    fs::write(&encrypted_file, &data).unwrap();
    
    let decryption_cmd= vec!["d".to_string(), encrypted_file.to_str().unwrap().to_string()];
    assert!(parse_cmd(decryption_cmd, &mut password.as_bytes()).is_err(), "got no error");
    tempdir.close().unwrap();
}