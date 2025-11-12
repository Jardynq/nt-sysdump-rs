use nt_sysdump::{Arch, LoadFile, LoadSource, NtdllMethod, Win32uMethod};

#[cfg(feature = "no_std")]
compile_error!("`no_std` is not supported for this binary");

#[cfg(windows)]
fn print_usage() {
    let mem = if cfg!(windows) {
        " (default: load from memory)"
    } else {
        ""
    };

    eprintln!("Usage:");
    eprintln!("    nt_sysdump.exe <image> <method> [options]");
    eprintln!();
    eprintln!("Options:");
    eprintln!("    --file=<PATH>            Load image file from disk{mem}");
    eprintln!("    --arch=<x86|x64|wow64>   Image architecture (default: infer)");
    eprintln!("    --version=<BUILD>        Image targeted windows version (default: infer)");
    eprintln!("                             Eg. --version=26100 for windows 11 24H2");
    eprintln!();
    eprintln!("Supported images and methods:");
    eprintln!("    ntdll    : sorting, assembly");
    eprintln!("    win32u   : sorting, assembly");
    eprintln!();
    eprintln!("Methods descriptions:");
    eprintln!("    sorting:     Try to grab all exports that match a pattern");
    eprintln!("                 and sort them by their address in memory.");
    eprintln!("                 This should work for all versions of NTDLL");
    eprintln!("    assembly:    Try to grab all exports that match a pattern");
    eprintln!("                 and directly extract the syscall indices from the assembly.");
}

fn inner(args: Vec<String>) -> Result<(), String> {
    let (file, source, arch, version) = parse_args(args)?;

    let result = nt_sysdump::dump(file, source, arch, version).map_err(|e| e.to_string())?;

    let size = result
        .iter()
        .map(|(name, id)| name.len() + (id + 1).ilog10() as usize + 1)
        .sum();
    let mut buf = String::with_capacity(size);
    for (name, index) in result {
        //buf.push_str(&format!("{name}:{index}\n"));
        buf.push_str(&format!("{index:x}:{name}\n"));
    }
    println!("{buf}");

    Ok(())
}

pub fn main() -> std::process::ExitCode {
    match inner(std::env::args().collect::<Vec<String>>()) {
        Ok(()) => std::process::ExitCode::SUCCESS,
        Err(err) => {
            println!("{}", err);
            print_usage();
            std::process::ExitCode::FAILURE
        }
    }
}

fn parse_args(
    args: Vec<String>,
) -> Result<(LoadFile, LoadSource, Option<Arch>, Option<u32>), String> {
    if args.len() < 3 && args.len() > 6 {
        return Err("Incorrect number of arguments".to_string());
    }

    let mut args = args.into_iter();

    // Ignore self
    let _ = args.next();

    // Parse image and method
    let file = match args.next().as_deref() {
        Some("ntdll") => match args.next().as_deref() {
            Some("sorting") => LoadFile::Ntdll(NtdllMethod::Sorting),
            Some("assembly") => LoadFile::Ntdll(NtdllMethod::Assembly),
            Some(other) => return Err(format!("Invalid ntdll method {other}")),
            None => return Err("Missing method for ntdll".to_string()),
        },
        Some("ntoskrl") => unimplemented!(),
        Some("win32u") => match args.next().as_deref() {
            Some("sorting") => LoadFile::Win32u(Win32uMethod::Sorting),
            Some("assembly") => LoadFile::Win32u(Win32uMethod::Assembly),
            Some(other) => return Err(format!("Invalid win32u method {other}")),
            None => return Err("Missing method for win32u".to_string()),
        },
        Some("win32k") => unimplemented!(),
        Some(other) => return Err(format!("Invalid image type {other}")),
        None => return Err("Missing image type".to_string()),
    };

    // Parse options
    let mut arch = None;
    let mut source = None;
    let mut version = None;
    for arg in args {
        if let Some(arch_str) = arg.strip_prefix("--arch=") {
            arch = match arch_str.to_lowercase().as_str() {
                "x86" => Some(Arch::X86),
                "x64" => Some(Arch::X64),
                //"wow64" => Some(Arch::Wow64),
                other => return Err(format!("Invalid architecture {other}")),
            }
        } else if let Some(path_str) = arg.strip_prefix("--file=") {
            source = if path_str.starts_with('"') {
                Some(path_str[1..path_str.len() - 1].to_string())
            } else {
                Some(path_str.to_string())
            };
        } else if let Some(version_str) = arg.strip_prefix("--version=") {
            version = match version_str.parse::<u32>() {
                Ok(version) => Some(version),
                Err(err) => return Err(format!("Invalid version {version_str}, {err}")),
            }
        } else {
            return Err(format!("Invalid argument {arg}"));
        }
    }

    let source = match source {
        Some(path) => match std::fs::exists(&path) {
            #[cfg(feature = "no_std")]
            Ok(true) => unreachable!(),
            #[cfg(not(feature = "no_std"))]
            Ok(true) => LoadSource::File(path),
            Ok(false) => return Err(format!("File not found {path}")),
            Err(err) => return Err(format!("{err}")),
        },
        None => {
            if cfg!(not(windows)) {
                return Err("Must specify --file argument on non windows platforms".to_string());
            }
            LoadSource::Memory
        }
    };
    Ok((file, source, arch, version))
}
