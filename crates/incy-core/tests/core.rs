use incy_core::{config, share_link, subscription, AppState, Endpoint, Profile, Protocol, Security, Settings, Store, Theme};
use uuid::Uuid;

fn vless() -> Profile {
    Profile {
        id: Uuid::new_v4(), name: "Example node".into(), subscription_id: None, raw_xray_config: None,
        endpoint: Endpoint {
            address: "example.org".into(), port: 443,
            protocol: Protocol::Vless { id: Uuid::new_v4(), flow: String::new(), encryption: "none".into() },
            transport: Default::default(),
            security: Security::Tls { sni: "example.org".into(), alpn: vec!["h2".into()], fingerprint: "chrome".into(), allow_insecure: false },
        },
    }
}

#[test]
fn parses_share_link_and_keeps_tls_secure_by_default() {
    let uuid = "d9428888-122b-4b8b-b4a4-3fce4a123456";
    let profile = share_link::parse(&format!("vless://{uuid}@edge.example:443?type=ws&path=%2Fgateway&host=cdn.example&security=tls&sni=edge.example#Work%20node")).unwrap();
    assert_eq!(profile.name, "Work node");
    assert!(matches!(profile.endpoint.security, Security::Tls { allow_insecure: false, .. }));
    assert_eq!(profile.endpoint.transport.path, "/gateway");
    assert_eq!(profile.endpoint.transport.host, "cdn.example");
}

#[test]
fn imports_full_xray_json_but_refuses_non_loopback_listeners() {
    let input = r#"{"inbounds":[{"tag":"socks","listen":"127.0.0.1","port":1080,"protocol":"socks","settings":{}}],"outbounds":[{"protocol":"freedom","tag":"direct"}],"routing":{"rules":[]},"observatory":{"subjectSelector":["proxy"]}}"#;
    let profile = config::import_xray_json("Imported profile", input).unwrap();
    let mut state = AppState::default();
    state.profiles.push(profile.clone());
    state.selected_profile = Some(profile.id);
    state.validate().unwrap();
    assert_eq!(profile.raw_xray_config.as_ref().unwrap()["observatory"]["subjectSelector"][0], "proxy");
    assert_eq!(profile.raw_xray_config.as_ref().unwrap()["inbounds"][0]["port"], 1080);
    let exposed = input.replace("127.0.0.1", "0.0.0.0");
    assert!(config::import_xray_json("unsafe", &exposed).is_err());
    assert!(config::import_xray_json("missing listen", r#"{"inbounds":[{"protocol":"socks","port":1080}],"outbounds":[{"protocol":"freedom"}]}"#).is_err());
}

#[test]
fn rejects_insecure_tls_and_bad_ports() {
    let uuid = "d9428888-122b-4b8b-b4a4-3fce4a123456";
    let link = format!("vless://{uuid}@edge.example:443?security=tls&allowInsecure=1");
    assert!(share_link::parse(&link).is_err());
    let mut p = vless(); p.endpoint.port = 0;
    assert!(p.endpoint.validate().is_err());
}

#[test]
fn generated_xray_config_binds_only_loopback_and_routes_fragment() {
    let p = vless();
    let mut settings = Settings::default(); settings.fragment = Some(Default::default());
    let cfg = config::generate(&p.endpoint, &settings).unwrap();
    for inbound in cfg["inbounds"].as_array().unwrap() { assert_eq!(inbound["listen"], "127.0.0.1"); }
    assert_eq!(cfg["outbounds"][0]["streamSettings"]["sockopt"]["dialerProxy"], "fragment");
    assert_eq!(cfg["outbounds"].as_array().unwrap().iter().find(|o| o["tag"] == "fragment").unwrap()["settings"]["fragment"]["packets"], "tlshello");
}

#[test]
fn rejects_fragmentation_without_tls_and_hysteria() {
    let mut endpoint = vless().endpoint; endpoint.security = Security::None;
    let mut settings = Settings::default(); settings.fragment = Some(Default::default());
    assert!(config::generate(&endpoint, &settings).is_err());
}

#[test]
fn subscription_is_https_only_and_bad_line_fails_whole_refresh() {
    assert!(subscription::validate_url("https://example.org/sub?id=private").is_ok());
    assert!(subscription::validate_url("http://example.org/sub").is_err());
    assert!(subscription::validate_url("https://user:pass@example.org/sub").is_err());
    let good = "vless://d9428888-122b-4b8b-b4a4-3fce4a123456@edge.example:443#A";
    assert_eq!(subscription::parse_body(good).unwrap().len(), 1);
    assert!(subscription::parse_body(&format!("{good}\nnot-a-link")).is_err());
}

#[test]
fn store_round_trip_and_backup_are_versioned() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("state.json");
    let mut store = Store::open(&path).unwrap();
    let profile = vless(); let id = profile.id;
    store.add_profiles(vec![profile]).unwrap();
    store.update_settings(Settings { theme: Theme::Ocean, ..Settings::default() }).unwrap();
    assert_eq!(store.state().selected_profile, Some(id));
    assert!(path.with_extension("json.bak").exists());
    let loaded = Store::open(&path).unwrap();
    assert_eq!(loaded.state().profiles.len(), 1);
    assert_eq!(loaded.state().settings.theme, Theme::Ocean);
}

#[test]
fn state_version_is_checked() {
    let mut state = AppState::default(); state.version = 99;
    assert!(state.validate().is_err());
}
