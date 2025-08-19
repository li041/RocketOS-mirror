use std::env;
use std::fs::{read_dir, File};
use std::io::{Result, Write};

fn main() {
    let target_path = env::var("USER_TARGET_PATH")
        .unwrap_or_else(|_| "../user/target/loongarch64-unknown-none/release/".to_string());
    println!("cargo:rerun-if-changed=../user/src/");
    println!("cargo:rerun-if-changed={}", target_path);
    insert_app_data(&target_path).unwrap();
}

fn insert_app_data(target_path: &str) -> Result<()> {
    let mut f = File::create("src/link_app.S").unwrap();
    // 收集 ../user/src/bin 下的应用 (Rust 编译出来的 ELF)
    let mut apps: Vec<(String, String)> = read_dir("../user/src/bin")
        .unwrap()
        .into_iter()
        .filter(|dir_entry| dir_entry.as_ref().unwrap().file_type().unwrap().is_file())
        .map(|dir_entry| {
            let mut name_with_ext = dir_entry.unwrap().file_name().into_string().unwrap();
            name_with_ext.drain(name_with_ext.find('.').unwrap()..name_with_ext.len());
            let name = name_with_ext.clone();
            let path = format!("{}{}", target_path, name); // 对应 release 下的可执行文件
            (name, path)
        })
        .collect();
    let arch = if target_path.contains("loongarch64") {
        "la"
    } else {
        "rv"
    };
    let img_path = format!("../img/{}/", arch);
    // 收集 ./img/bin 下的应用 (直接是ELF可执行文件)
    let mut img_apps: Vec<(String, String)> = read_dir(img_path)
        .unwrap()
        .into_iter()
        .filter(|dir_entry| dir_entry.as_ref().unwrap().file_type().unwrap().is_file())
        .map(|dir_entry| {
            let name = dir_entry.unwrap().file_name().into_string().unwrap();
            let path = format!("../img/{}/{}", arch, name);
            (name, path)
        })
        .collect();
    // 合并
    apps.append(&mut img_apps);

    // 按名字排序，保证顺序稳定
    apps.sort_by(|a, b| a.0.cmp(&b.0));

    // 写 _num_app
    writeln!(
        f,
        r#"
    .align 3
    .section .data
    .global _num_app
_num_app:
    .quad {}"#,
        apps.len()
    )?;

    for i in 0..apps.len() {
        writeln!(f, r#"    .quad app_{}_start"#, i)?;
    }
    writeln!(f, r#"    .quad app_{}_end"#, apps.len() - 1)?;

    // 写 _app_names
    writeln!(
        f,
        r#"
    .global _app_names
_app_names:"#
    )?;
    for (name, _) in apps.iter() {
        writeln!(f, r#"    .string "{}""#, name)?;
    }

    // 写每个 app 的数据段
    for (idx, (name, path)) in apps.iter().enumerate() {
        println!("app_{}: {} ({})", idx, name, path);
        writeln!(
            f,
            r#"
    .section .data
    .global app_{0}_start
    .global app_{0}_end
    .align 3
app_{0}_start:
    .incbin "{1}"
app_{0}_end:"#,
            idx, path
        )?;
    }
    Ok(())
}
