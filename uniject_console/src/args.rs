use std::fmt::Debug;
use std::str::FromStr;

pub struct CommandLineArguments<'a> {
    args: &'a [String],
}

impl<'a> CommandLineArguments<'a> {
    pub fn new(args: &'a [String]) -> Self {
        Self { args }
    }

    pub fn is_switch_present(&self, name: &str) -> bool {
        self.args.iter().any(|arg| arg == name)
    }

    pub fn get_long_arg(&self, name: &str) -> Option<i64> {
        self.get_arg_value::<i64>(name, 16)
    }

    pub fn get_int_arg(&self, name: &str) -> Option<i32> {
        self.get_arg_value::<i32>(name, 16)
    }

    pub fn get_string_arg(&self, name: &str) -> Option<&str> {
        self.get_arg_index(name).and_then(|index| self.args.get(index + 1).map(|s| s.as_str()))
    }

    fn get_arg_index(&self, name: &str) -> Option<usize> {
        self.args.iter().position(|arg| arg == name)
    }

    fn get_arg_value<T>(&self, name: &str, radix: u32) -> Option<T>
    where
        T: FromStr + Debug + TryFrom<i64> + TryFrom<i32>,
        <T as FromStr>::Err: Debug,
        <T as TryFrom<i64>>::Error: Debug,
        <T as TryFrom<i32>>::Error: Debug,
    {
        self.get_string_arg(name).and_then(|str_val| {
            let value_str = if str_val.starts_with("0x") { &str_val[2..] } else { str_val };

            if radix == 16 {
                if let Ok(value) = i64::from_str_radix(value_str, 16) {
                    return T::try_from(value).ok();
                }
            }

            value_str.parse::<T>().ok()
        })
    }
}
