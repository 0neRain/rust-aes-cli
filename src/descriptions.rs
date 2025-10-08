use lazy_static::lazy_static;
use std::collections::HashMap;

pub const TOOL_DESCRIPTION:&'static str= r#"
Simple AES GCM encryption/decryption tool.

Usage Examples:
1. Encrypt a file: `encrypt file.txt --name encrypted_file`
2. Decrypt a file: `decrypt encrypted_file`

For more information use `help <command>`
"#;

lazy_static! {
    pub static ref CMD_HELP: HashMap<&'static str, &'static str>= {
        let mut m= HashMap::new();
        m.insert("encrypt", r#"
Encrypt a file or a directory. 
Syntax : encrypt <path> [flags]


Flags:
    
--name:         Specify the name of the encrypted file. If not set the name will be the name of the starting file or directory.
--no-delete:    If set, unencrypted files will not be deleted.
--location:     Specify the path where the encrypted file will be created.
"#);    

        m.insert("e", r#"
Alias for the 'encrypt' command.

Encrypt a file or a directory.
Syntax: e <path> [flags]

Flags:
--name:         Specify the name of the encrypted file. If not set, the name will default to the name of the starting file or directory.
--no-delete:    If set, unencrypted files will not be deleted.
--location:     Specify the path where the encrypted file will be created.
"#);


        m.insert("decrypt", r#"
decrypt an encrypted file or directory.
Syntax: decrypt <path> [flags]

Flags:
--location:   Specify the path where the decrypted file will be created.
"#);

        m.insert("d", r#"
Alias for the 'decrypt' command.

Decrypt an encrypted file or directory.
Syntax: d <path> [flags]

Flags:
--location:     Specify the path where the decrypted file will be created.
"#);

        m.insert("help", r#"
Display help information for commands.
Syntax: help [<command>]

Examples:
help          Display a list of all commands.
help encrypt  Display detailed help for the 'encrypt' command.
"#);  
        m
    };
}