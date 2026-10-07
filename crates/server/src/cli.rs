//! Command-line parsing. Configuration comes from environment variables; arguments only
//! select what the process does, so help and version never open state or start services.

pub const USAGE: &str = "\
Usage: locallycloud [COMMAND]

Run the LocallyCloud local AWS emulator on one endpoint (default http://127.0.0.1:4566).

Commands:
  (none)                  Start the server
  migrate-s3-encryption   Encrypt S3 object bodies stored by an earlier version, then exit

Options:
  -h, --help              Print this help and exit
  -V, --version           Print the version and exit

Configuration uses environment variables. LOCALLYCLOUD_KMS_MASTER_KEY (base64 of
32 bytes) is required to start the server or migrate. See `man locallycloud` and
https://locallycloud.zentostudio.com";

#[derive(Debug, PartialEq, Eq)]
pub enum Command {
    Serve,
    MigrateS3Encryption,
    Help,
    Version,
}

pub fn parse(arguments: &[String]) -> Result<Command, String> {
    match arguments {
        [] => Ok(Command::Serve),
        [single] => match single.as_str() {
            "-h" | "--help" => Ok(Command::Help),
            "-V" | "--version" => Ok(Command::Version),
            "migrate-s3-encryption" => Ok(Command::MigrateS3Encryption),
            other => Err(format!("unknown argument: {other}")),
        },
        [first, ..] => Err(format!("unexpected arguments after {first}")),
    }
}

#[cfg(test)]
mod tests {
    use super::{parse, Command};

    fn args(values: &[&str]) -> Vec<String> {
        values.iter().map(|value| (*value).to_string()).collect()
    }

    #[test]
    fn known_commands_and_flags_parse() {
        assert_eq!(parse(&args(&[])), Ok(Command::Serve));
        assert_eq!(parse(&args(&["--help"])), Ok(Command::Help));
        assert_eq!(parse(&args(&["-h"])), Ok(Command::Help));
        assert_eq!(parse(&args(&["--version"])), Ok(Command::Version));
        assert_eq!(parse(&args(&["-V"])), Ok(Command::Version));
        assert_eq!(
            parse(&args(&["migrate-s3-encryption"])),
            Ok(Command::MigrateS3Encryption)
        );
    }

    #[test]
    fn unknown_or_extra_arguments_are_rejected() {
        assert!(parse(&args(&["migrate-s3-encription"])).is_err());
        assert!(parse(&args(&["--port", "4567"])).is_err());
        assert!(parse(&args(&["migrate-s3-encryption", "extra"])).is_err());
    }
}
