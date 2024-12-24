use std::mem::size_of;
use std::os::windows::process;
use std::path::Path;
use std::{fs, io};
use std::{env, path::PathBuf};

use anyhow::{anyhow, Result};

use aes_gcm::{AeadCore, Aes256Gcm, KeyInit};
use aes_gcm::aead::{Aead, OsRng};

use rand::prelude::*;
use rand_pcg::Pcg64;
use rand_seeder::Seeder;

mod flags;
use flags::{Flags, CMD};

mod descriptions;
use descriptions::*;

const NONCE_LENGTH: usize= 12; //bytes
const KEY_LENGTH: usize=32;

struct Ctx <'f>{
    target :PathBuf,
    location: PathBuf,
    key: [u8;KEY_LENGTH],
    name: Option<String>,
    flags: Flags<'f>,
}


struct CtxBuilder<'f>{
    target: Option<PathBuf>,
    key: Option<[u8;KEY_LENGTH]>,

    flags: Flags<'f>,
}

impl<'f> CtxBuilder <'f>{
    fn new(cmd: CMD) -> Self {
        Self {
            target: None,
            key: None,
            flags: Flags::new(cmd),
        }
    }

    fn build(mut self) -> Result<Ctx<'f>> {
        let target= match self.target {
            Some(t) =>t,
            None => return Err(anyhow!("missing target")),
        };

        let key= match self.key {
            Some(k)=> k,
            None=> return Err(anyhow!("missing key")),
        };

        self.flags.check_flags()?;

        let name= self.flags.get_str_flag("--name").map(|n| n.clone());
        
        let location:PathBuf= self.flags.get_str_flag("--location").unwrap().into();
        if !location.is_dir() {
            return Err(anyhow!("location path {location:?} is not a directory"));
        }

        Ok(Ctx{
            target,
            location,
            key,
            name,
            flags: self.flags,
        })
    }
}
fn main() {
    if let Err(e) = parse_args() {
        println!("error: {e}");
    }

}

fn parse_args() -> Result<()> {
    let args: Vec<String>= env::args().skip(1).collect();

    if args.len()==0 {
        return Err(anyhow!("no command"));
    }

    
    match args[0].as_str(){
        "encrypt" |"e" =>{
            let mut builder= CtxBuilder::new(CMD::ENCRYPT);
            match args.get(1) {
                Some(t) => builder.target= Some(t.into()),
                None => return Err(anyhow!("expected target")),
            }
            
            parse_cmd_flags(&mut builder, &args[2..], CMD::ENCRYPT)?;
            
            if builder.flags.get_str_flag("--name").is_none() {
                builder.flags.set_str_flag("--name", builder.target.as_ref().unwrap().with_extension("").to_string_lossy().into_owned())?;
            } 
            if builder.flags.get_str_flag("--location").is_none() {
                builder.flags.set_str_flag("--location", builder.target.as_ref().unwrap().parent().unwrap().to_string_lossy().to_string())?;
            } 

            let pw=get_password();

            if pw.len()>KEY_LENGTH {
                return Err(anyhow!("password is too long"))
            }

            builder.key= Some(generate_key_from_password(&pw));

            let ctx= builder.build()?;
            let data= read_path_to_plaintext(&ctx.target)?;

            let cyphertext= encrypt(&ctx,&data)?;

            fs::write( ctx.location.join(ctx.name.unwrap()),cyphertext.as_slice()).unwrap();

            if !ctx.flags.get_bool_flag("--no-delete").unwrap() {
                fs::remove_file(&ctx.target)?;
            }
        },
        "decrypt" | "d"=> {
            let mut builder= CtxBuilder::new(CMD::DECRYPT);

            match args.get(1) {
                Some(t) => builder.target= Some(t.into()),
                None => return Err(anyhow!("expected target")),
            }

            parse_cmd_flags(&mut builder, &args[1..], CMD::ENCRYPT)?; 

            if builder.flags.get_str_flag("--location").is_none() {
                builder.flags.set_str_flag("--location", builder.target.as_ref().unwrap().parent().unwrap().to_string_lossy().to_string())?;
            } 

            let pw=get_password();

            if pw.len()>KEY_LENGTH {
                return Err(anyhow!("password is too long"))
            }

            builder.key= Some(generate_key_from_password(&pw));

            let ctx= builder.build()?;
            let data=fs::read(&ctx.target)?;
            
            let data= decrypt(&ctx,&data)?;
            
            write_data(&ctx.location,&data)?;
        },
        "help"=> match args.get(1) {
            Some(cmd)=> match CMD_HELP.get(cmd.as_str()) {
                Some(&s)=> println!("{s}"),
                None=> return Err(anyhow!("unknown command '{cmd}'")),
            },
            None=> println!("{}",TOOL_DESCRIPTION.to_string()),
        }
        _=> return Err(anyhow!("unknown command {}", args[0]))
    };

    Ok(())
}

fn parse_cmd_flags<'f>(builder: &mut CtxBuilder<'f>, args: &'f [String], cmd: CMD) -> Result<()> {
    let mut pos=0;
    while let Some(_) = args.get(pos) {
        let flag= &args[pos];
        if flags::is_valid_bool_flag(flag, cmd) {
            builder.flags.set_bool_flag(flag, true)?;
        } else if flags::is_valid_str_flag(flag, cmd) {
            pos+=1;
            let val= match args.get(pos) {
                Some(v)=> v.clone(),
                None=> return Err(anyhow!("expected value for flag {}", &args[pos])),
            };
            
            builder.flags.set_str_flag(flag, val)?;
        }

        pos+=1;
    }
    Ok(())
}

fn get_password() -> String {
    println!("password:");

    let mut pw= String::new();
    io::stdin().read_line(&mut pw).expect("expected password");

    pw.trim().into()
}

fn generate_key_from_password(pw: &str)-> [u8;KEY_LENGTH] {
    let pw=pw.as_bytes();
    let mut ret= [0u8;KEY_LENGTH];

    let mut rng: Pcg64 = Seeder::from(pw).make_rng();
    for i in 0..pw.len() {
        ret[i]=rng.gen();
    }

    ret
}

fn read_path_to_plaintext(path: &Path) -> Result<Vec<u8>> {
    if !path.exists() {
        return Err(anyhow!("path '{path:?}' does not exist"))
    }
    
    if path.is_file() {
        let mut v=fs::read(path).map_err(|_| anyhow!("failed to read file"))?;
        let name= path.file_name().unwrap().to_string_lossy();
    
        v.reserve(name.len()+ size_of::<u64>()+2);
    
        v.push(b'\n');
        for &c in name.as_bytes() {
            v.push(c);
        }
        
        v.push(b'\n');
        //len is the length of the file + length of file name + 2
        let len= (v.len() as u64).to_be_bytes();


        for c in len {
            v.push(c);
        }
        return Ok(v)
    }

    let mut v: Vec<u8>= Vec::new();
    let mut count:u64=0;
    for entry in path.read_dir().unwrap() {
        let mut res=read_path_to_plaintext(entry.unwrap().path().as_path())?;
        count+=1;
        v.append(&mut res);   
    }

    let dir_name= path.file_name().unwrap().to_string_lossy();
     
    v.reserve(dir_name.len() + size_of::<u64>() + 3);
    v.push(b'\n');
    for &c in  dir_name.as_bytes() {
        v.push(c);
    }

    v.push(b'\n');

    for c in count.to_be_bytes() {
        v.push(c);
    }

    v.push(b'\n');

    Ok(v)
}

fn write_data(path: &Path, data: &[u8])-> Result<()> {
    let mut pos= data.len()-1;
    let mut is_dir=false;

    if data[pos]==b'\n' {
        is_dir=true;
        pos-=1;
    }

    if pos<7 {
        return Err(anyhow!("wrong file format"));
    }

    let num= u64::from_be_bytes(data[pos-7..=pos].try_into().unwrap());
    pos-=8;
    if data[pos]!= b'\n' {
        return Err(anyhow!("wrong file format"));
    }
    
    let end=pos;
    pos-=1;

    while data[pos]!=b'\n' {
        pos-=1;
    }

    let name= String::from_utf8_lossy(&data[pos+1..end]).into_owned();
    if is_dir {
        let p= path.join(name);
        fs::create_dir(&p)?;
        
        return write_data(&p, &data[..pos])
    }    

    if num==0 {
        return Err(anyhow!("empty file and name"));
    }

    let start= end as u64 + 1 - num;
    if start <0{
        return Err(anyhow!("wrong file format"));
    }

    let file_data= &data[start as usize..pos];
    let file_path= path.join(name);

    fs::write(file_path, file_data)?;

    //write other files in the same directory
    if start!=0 {
        write_data(&path, &data[..start as usize])?
    }
    Ok(())
}

fn encrypt(ctx:&Ctx, data: &[u8]) -> Result<Vec<u8>> {
    let cypher= Aes256Gcm::new  (ctx.key[..].into());
    let nonce=Aes256Gcm::generate_nonce(&mut OsRng);


    let mut cyphertext=cypher.encrypt(&nonce, data.as_ref()).unwrap();

    cyphertext.reserve(NONCE_LENGTH);
    for b in nonce {
        cyphertext.push(b);
    }

    Ok(cyphertext)
}

fn decrypt(ctx: &Ctx, data: &[u8]) -> Result<Vec<u8>> {
    let (cyphertext,nonce)= data.split_at(data.len()-NONCE_LENGTH);

    let cypher= Aes256Gcm::new(ctx.key[..].into());

    cypher.decrypt(nonce.into(),cyphertext).map_err(|_| anyhow!("wrong password"))
}
