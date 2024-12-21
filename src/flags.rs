use std::{collections::HashMap, hash::Hash};
use anyhow::{anyhow, Result};
use lazy_static::lazy_static;


lazy_static! {
    static ref ALLOWED_BOOL_FLAGS: HashMap<CMD, Vec<&'static str>>= {
        let mut m= HashMap::new();
        
        m.insert(CMD::ENCRYPT, vec!["--no-delete"]);
        m.insert(CMD::DECRYPT, vec![]);
        m.insert(CMD::HELP, vec![]);

        m
    };
    static ref STR_FLAGS: HashMap<CMD, HashMap<&'static str, Option<String>>>= {
        let mut m= HashMap::new();

        m.insert(CMD::ENCRYPT, [
            ("--name",None),
            ("--location", None),
        ].into());

        m.insert(CMD::DECRYPT, [
            ("--location", None),
        ].into());

        m.insert(CMD::HELP, [].into());

        m
    };
}

#[derive(PartialEq, Eq, Hash, Clone, Copy, Debug)]
pub enum CMD {
    ENCRYPT,
    DECRYPT,
    HELP,
}

impl ToString for CMD {
    fn to_string(&self) -> String {
        match self {
            Self::ENCRYPT=> "encrypt".into(),
            Self::DECRYPT=> "decrypt".into(),
            Self::HELP=> "help".into(),
        }
    }
}

#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Flags<'k> {
    cmd:CMD,
    bool_flags: HashMap<&'k str, bool>,
    //TODO: maybe use cows
    str_flags: HashMap<&'k str, String>,
}



impl<'k> Flags<'k> {
    pub fn new(cmd: CMD)-> Self {
        let mut bool_flags= HashMap::new();
        //set all the bool_flags to false
        for &f in &ALLOWED_BOOL_FLAGS[&cmd] {
            bool_flags.insert(f, false);
        }

        Self {
            cmd,
            bool_flags,
            str_flags: HashMap::new(),
        }
    }

    pub fn get_bool_flag(&self, k: &str) -> Option<bool> {
        self.bool_flags.get(k).map(|&b| b)
    }

    pub fn get_str_flag(&self, k :&str) -> Option<&String> {
        self.str_flags.get(k)
    }

    pub fn set_bool_flag(&mut self,k :&'k str, v: bool)-> Result<()> {
        //if flag doesn't exist, it is invalid
        if !self.bool_flags.contains_key(k) {
            return Err(anyhow!("flag '{k}' is not allowed for command: {}",self.cmd.to_string()));
        }
        
        match self.bool_flags.insert(k, v).unwrap() {
            true=> Err(anyhow!("duplicate flag '{k}'")),
            false=> Ok(())
        }
    }
    
    pub fn set_str_flag(&mut self, k :&'k str, v: String)-> Result<()> {
        if !STR_FLAGS[&self.cmd].contains_key(k) {
            return Err(anyhow!("flag '{k}' is not allowed for command: {}",self.cmd.to_string()));
        } 

        match self.str_flags.insert(k, v) {
            Some(_)=> Err(anyhow!("duplicate flag '{k}'")), 
            None=> Ok(())
        }
    }

    //checks that all mandatory flags are inserted and adds default values for optional flags.
    pub fn check_flags(&mut self) -> Result<()> {
        for (&flag,default) in &STR_FLAGS[&self.cmd] {
            match default{
                //add default value
                Some(d)=> if !self.str_flags.contains_key(flag) {
                    self.str_flags.insert(flag, d.clone());
                },

                //missing mandatory flag
                None=> if !self.str_flags.contains_key(flag) {
                    return Err(anyhow!("missing mandatory flag {flag}"))
                }  
            };
        }

        Ok(())
    }

}

pub fn is_valid_bool_flag(f: &str, cmd: CMD) -> bool {
    ALLOWED_BOOL_FLAGS[&cmd].contains(&f)
}

pub fn is_valid_str_flag(f:&str, cmd:CMD) ->bool {
    STR_FLAGS[&cmd].contains_key(f)
}