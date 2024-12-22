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
#[cfg(test)]
mod test {
    use std::collections::HashSet;

    use super::*;
    #[test]
    fn test_default_values() {
        let mut flags= Flags::new(CMD::ENCRYPT);

        //get all mandatory flags
        let mandatory_flags:Vec<&str>= STR_FLAGS[&CMD::ENCRYPT].keys().filter(|&&k| STR_FLAGS[&CMD::ENCRYPT][k].is_none()).map(|&k| k).collect();

        let inserted_str_flags: HashMap<&str, &str>= HashMap::from_iter(mandatory_flags.iter().map(|&k| (k,"test")));
        let inserted_bool_flags= HashSet::from(["--no-delete"]);

        for (&f,&v) in &inserted_str_flags {
            flags.set_str_flag(f, v.to_string()).unwrap();
        }
        
        for &f in &inserted_bool_flags {
            flags.set_bool_flag(f, true).unwrap();
        }

        flags.check_flags().unwrap();
        
        for (&f,v) in &flags.str_flags {
            //check value is unchanged
            if inserted_str_flags.contains_key(f) {
                assert_eq!(inserted_str_flags[f], v, "Inserted value for key {f} was changed to {}", inserted_str_flags[f]);
            }
            //check value is set to default  
            else {
                match STR_FLAGS[&CMD::ENCRYPT][f] { 
                    None=> assert!(flags.get_str_flag(f).is_none(),"Flag {f} has no default value and was not inserted, but is set to {}", flags.get_str_flag(f).unwrap()),
                    Some(d) => assert_eq!(v.clone(), d, "Expected default value {d} for flag {f}. Got {v}"),
                }
            }
        }

        for (&f, &v) in &flags.bool_flags {
            let expected= inserted_bool_flags.contains(f);
            assert_eq!(flags.bool_flags[f], expected, "expected value {expected} for flag {f}. got {}", !expected);
        }
    }
    
    #[test]
    fn test_mandatory_values() {
        let mut flags= Flags::new(CMD::ENCRYPT);
        //vector of strings that will be referenced by the keys (they must outlive flags)
        let mandatory_flags: Vec<String>=STR_FLAGS[&CMD::ENCRYPT].keys().filter(|&&k| STR_FLAGS[&CMD::ENCRYPT][k].is_none()).map(|&k| k.to_string()).collect(); 
        let mut unset_mandatory_flags: HashSet<&str>= HashSet::from_iter(mandatory_flags.iter().map(|x| x.as_str()));
        
        while let Err(err) = flags.check_flags() {  
            let s= err.to_string();
            assert!(s.starts_with("missing mandatory flag"),"unexpected error");

            let flag=s.split_ascii_whitespace().last().unwrap().to_string();
            assert!(unset_mandatory_flags.contains(flag.as_str()));

            flags.set_str_flag(*unset_mandatory_flags.get(flag.as_str()).unwrap(), "test".into()).unwrap(); 
            unset_mandatory_flags.remove(flag.as_str());
        }

        assert!(unset_mandatory_flags.is_empty())
    }
}