use std::{env, path::PathBuf};

fn main() {
    println!("cargo:rustc-check-cfg=cfg(incy_embedded_xray)");
    for name in ["INCY_XRAY_BINARY", "INCY_GEOIP_BINARY", "INCY_GEOSITE_BINARY", "INCY_TUN2SOCKS_BINARY"] {
        println!("cargo:rerun-if-env-changed={name}");
    }
    let assets = ["INCY_XRAY_BINARY", "INCY_GEOIP_BINARY", "INCY_GEOSITE_BINARY", "INCY_TUN2SOCKS_BINARY"]
        .map(|name| (name, env::var(name).ok()));
    let provided = assets.iter().filter(|(_, path)| path.is_some()).count();
    if provided == 0 { return; }
    if provided != assets.len() {
        panic!("Bundle builds require INCY_XRAY_BINARY, INCY_GEOIP_BINARY, INCY_GEOSITE_BINARY and INCY_TUN2SOCKS_BINARY");
    }
    for (name, value) in assets {
        let path = PathBuf::from(value.expect("checked above"));
        if !path.is_file() { panic!("{name} does not point to a file"); }
        println!("cargo:rustc-env={name}={}", path.display());
        println!("cargo:rerun-if-changed={}", path.display());
    }
    println!("cargo:rustc-cfg=incy_embedded_xray");
}
