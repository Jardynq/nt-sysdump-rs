use std::collections::BTreeMap;
use std::sync::LazyLock;
use std::{env, fs, path::Path};

static FILES: [(&str, &str, &str); 4] = [
    ("x64/csv/nt.csv", "nt64.rs", "NTDLL64"),
    ("x86/csv/nt.csv", "nt86.rs", "NTDLL32"),
    ("x64/csv/win32k.csv", "win64.rs", "WIN64"),
    ("x86/csv/win32k.csv", "win86.rs", "WIN32"),
];

static VERSIONS: LazyLock<Vec<(&'static str, u32)>> = LazyLock::new(|| {
    vec![
        ("Windows NT 3.x (3.1)", 528),
        ("Windows NT 3.x (3.5)", 807),
        ("Windows NT 3.x (3.51)", 1057),
        ("Windows NT 4.0 (SP0)", 1381),
        ("Windows NT 4.0 (SP1)", 1381),
        ("Windows NT 4.0 (SP2)", 1381),
        ("Windows NT 4.0 (SP3)", 1381),
        ("Windows NT 4.0 (SP3 TSE)", 1381),
        ("Windows NT 4.0 (SP4)", 1381),
        ("Windows NT 4.0 (SP5)", 1381),
        ("Windows NT 4.0 (SP6)", 1381),
        ("Windows 2000 (SP0)", 2195),
        ("Windows 2000 (SP1)", 2195),
        ("Windows 2000 (SP2)", 2195),
        ("Windows 2000 (SP3)", 2195),
        ("Windows 2000 (SP4)", 2195),
        ("Windows XP (SP0)", 2600),
        ("Windows XP (SP1)", 2600),
        ("Windows XP (SP2)", 2600),
        ("Windows XP (SP3)", 2600),
        ("Windows Server 2003 (SP0)", 3790),
        ("Windows Server 2003 (SP1)", 3790),
        ("Windows Server 2003 (SP2)", 3790),
        ("Windows Server 2003 (R2)", 3790),
        ("Windows Server 2003 (R2 SP2)", 3790),
        ("Windows Vista (SP0)", 6000),
        ("Windows Vista (SP1)", 6001),
        ("Windows Vista (SP2)", 6002),
        ("Windows 7 (SP0)", 7600),
        ("Windows 7 (SP1)", 7601),
        ("Windows 8 (8.0)", 9200),
        ("Windows 8 (8.1)", 9600),
        ("Windows 10 (1507)", 10240),
        ("Windows 10 (1511)", 10586),
        ("Windows 10 (1607)", 14393),
        ("Windows 10 (1703)", 15063),
        ("Windows 10 (1709)", 16299),
        ("Windows 10 (1803)", 17134),
        ("Windows 10 (1809)", 17763),
        ("Windows 10 (1903)", 18362),
        ("Windows 10 (1909)", 19002),
        ("Windows 10 (2004)", 19041),
        ("Windows 10 (20H2)", 19042),
        ("Windows 10 (21H1)", 19043),
        ("Windows 10 (21H2)", 19044),
        ("Windows 10 (22H2)", 19045),
        ("Windows 11 and Server (Server 2022)", 22000),
        ("Windows 11 and Server (11 21H2)", 22000),
        ("Windows 11 and Server (11 22H2)", 22621),
        ("Windows 11 and Server (11 23H2)", 22631),
        ("Windows 11 and Server (Server 23H2)", 22631),
        ("Windows 11 and Server (11 24H2)", 26100),
        ("Windows 11 and Server (Server 2025)", 26100),
    ]
});

static VERSIONS_MAP: LazyLock<BTreeMap<&'static str, u32>> =
    LazyLock::new(|| VERSIONS.iter().cloned().collect());

fn main() {
    /*
    if env::var("CARGO_FEATURE_STATIC").is_err() {
        return;
    }
    */

    let src_dir = Path::new(&env::var("CARGO_MANIFEST_DIR").unwrap()).join("windows-syscalls");
    let out_dir = env::var("OUT_DIR").unwrap();
    let out_dir = Path::new(&out_dir);
    fs::create_dir_all(out_dir).unwrap();

    gen_versions(&out_dir.join("versions.rs"));
    for (file, dest, name) in FILES {
        gen_phf(&src_dir.join(file), &out_dir.join(dest), name);
    }
}

fn create_map(src: &Path) -> BTreeMap<u32, BTreeMap<String, String>> {
    let csv = fs::read_to_string(src).unwrap();
    let mut lines = csv.lines();
    let headers: Vec<&str> = lines
        .next()
        .unwrap()
        .split(',')
        .skip(1)
        .map(|s| s.trim())
        .collect();

    let mut entries = BTreeMap::new();
    for line in lines {
        let mut cells = line.split(',').map(|s| s.trim());
        let syscall = cells.next().unwrap();

        for (version, value) in headers.iter().zip(cells) {
            if value.is_empty() {
                continue;
            }
            let version = VERSIONS_MAP
                .get(*version)
                .unwrap_or_else(|| panic!("Unknown Windows version in CSV: {}", version));
            entries
                .entry(*version)
                .and_modify(|inner: &mut BTreeMap<String, String>| {
                    inner.entry(syscall.to_owned()).or_insert(value.to_owned());
                })
                .or_insert(BTreeMap::new());
        }
    }
    entries
}

fn gen_versions(dest: &Path) {
    let mut sorted = VERSIONS.clone();
    sorted.sort_by(|(_, a), (_, b)| a.cmp(b));
    let mut deduped = sorted.clone();
    deduped.dedup_by(|(_, a), (_, b)| a == b);

    let mut code = String::new();
    code.push_str(&format!(
        "pub static VERSIONS: [u32; {}] = [\n",
        deduped.len()
    ));
    for (_, value) in deduped {
        code.push_str(&format!("    {value},\n"));
    }
    code.push_str("];\n");
    /*
    code.push_str("pub static VERSIONS_MAP: phf::Map<&'static str, u32> = phf::phf_map! {\n");
    for (version, value) in &sorted {
        code.push_str(&format!("    \"{version}\" => {value},\n"));
    }
    code.push_str("};\n");

    code.push_str("pub static VERSIONS_MAP_INV: phf::Map<u32, &'static str> = phf::phf_map! {\n");
    for (version, value) in &sorted {
        code.push_str(&format!("    {version} => \"{value}\",\n"));
    }
    code.push_str("};\n");
    */
    fs::write(dest, code).unwrap();
}

fn gen_phf(src: &Path, dest: &Path, name: &str) {
    let mut code = format!(
        "pub static SYSCALLS_{name}: phf::Map<u32, phf::Map<&'static str, u16>> = phf::phf_map! {{\n"
    );
    for (version, inner) in create_map(src) {
        let mut inner_code = String::new();
        inner_code.push_str("phf::phf_map! {\n");
        for (syscall, value) in inner {
            inner_code.push_str(&format!("        \"{syscall}\" => {value},\n"));
        }
        inner_code.push_str("    }");
        let line = format!("    {version} => {inner_code},\n");
        code.push_str(&line);
    }
    code.push_str("};\n");

    fs::write(dest, code).unwrap();
}
