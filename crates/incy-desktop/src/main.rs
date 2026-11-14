use clap::{Parser, Subcommand};
use incy_core::{config, share_link, Store};
use uuid::Uuid;

#[cfg(incy_embedded_xray)]
static EMBEDDED_XRAY: incy_core::runtime::EmbeddedXray<'static> = incy_core::runtime::EmbeddedXray {
    executable: include_bytes!(env!("INCY_XRAY_BINARY")),
    geoip: include_bytes!(env!("INCY_GEOIP_BINARY")),
    geosite: include_bytes!(env!("INCY_GEOSITE_BINARY")),
};
#[cfg(incy_embedded_xray)]
fn embedded_xray() -> Option<incy_core::runtime::EmbeddedXray<'static>> { Some(EMBEDDED_XRAY) }
#[cfg(not(incy_embedded_xray))]
fn embedded_xray() -> Option<incy_core::runtime::EmbeddedXray<'static>> { None }

#[derive(Parser)]
#[command(name = "nikitavpnclient", version, about = "NikitaVPNClient desktop app powered by Xray-core")]
struct Cli {
    #[command(subcommand)]
    command: Option<Command>,
}
#[derive(Subcommand)]
enum Command {
    /// Open the native desktop application (the default).
    Gui,
    /// Print saved profiles without revealing server credentials.
    List,
    /// Import one VLESS/VMess/Trojan/SS/SOCKS/Hysteria2/WireGuard share link.
    ImportLink { link: String },
    /// Import a complete Xray JSON config (listeners are restricted to loopback).
    ImportConfig { path: std::path::PathBuf, #[arg(long, default_value = "Imported Xray config")] name: String },
    /// Print a generated Xray config to stdout. Treat the output as a secret.
    Config { profile: Uuid },
    /// Print the path to the local state file.
    DataPath,
}

fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();
    let mut store = Store::open_default()?;
    match cli.command.unwrap_or(Command::Gui) {
        Command::Gui => {
            let options = eframe::NativeOptions {
                viewport: eframe::egui::ViewportBuilder::default()
                    .with_inner_size([1120.0, 760.0])
                    .with_min_inner_size([760.0, 560.0]),
                ..Default::default()
            };
            eframe::run_native("NikitaVPNClient", options, Box::new(move |_cc| Ok(Box::new(ui::IncyApp::new(store)))))?;
        }
        Command::List => {
            for p in &store.state().profiles {
                let detail = if p.raw_xray_config.is_some() { "Xray JSON config".to_owned() } else { format!("{}:{} · {}", p.endpoint.address, p.endpoint.port, p.endpoint.summary()) };
                println!("{}\t{}\t{}", p.id, p.name.replace(['\t','\n','\r'], " "), detail);
            }
        }
        Command::ImportLink { link } => {
            let profile = share_link::parse(&link)?;
            let id = profile.id;
            store.add_profiles(vec![profile])?;
            println!("Imported profile {id}");
        }
        Command::ImportConfig { path, name } => {
            let input = std::fs::read_to_string(path)?;
            let profile = config::import_xray_json(&name, &input)?;
            let id = profile.id;
            store.add_profiles(vec![profile])?;
            println!("Imported Xray config profile {id}");
        }
        Command::Config { profile } => {
            let p = store.state().profiles.iter().find(|p| p.id == profile).ok_or_else(|| anyhow::anyhow!("profile not found"))?;
            let value = match &p.raw_xray_config { Some(value) => value.clone(), None => config::generate(&p.endpoint, &store.state().settings)? };
            println!("{}", serde_json::to_string_pretty(&value)?);
        }
        Command::DataPath => println!("{}", store.path().display()),
    }
    Ok(())
}

mod ui {
    use crate::embedded_xray;
    use std::collections::HashSet;
    use std::sync::mpsc::{self, Receiver, Sender};
    use std::time::{Duration, Instant};
    use eframe::egui::{self, Align, Color32, Layout, RichText, Stroke, Vec2};
    use incy_core::{config, runtime, share_link, subscription, Error, Store};
    use uuid::Uuid;

    #[derive(Clone, Copy)]
    struct Palette { bg: Color32, panel: Color32, card: Color32, accent: Color32, muted: Color32, text: Color32 }
    fn palette(theme: incy_core::Theme) -> Palette {
        let (bg, panel, card, accent, muted, text) = match theme {
            incy_core::Theme::Light => ((240,244,249),(255,255,255),(229,235,243),(62,103,214),(95,108,128),(28,36,49)),
            incy_core::Theme::Ocean => ((8,20,30),(12,31,45),(19,45,63),(42,190,220),(135,169,185),(235,247,250)),
            incy_core::Theme::Forest => ((12,22,18),(19,34,27),(29,48,37),(66,181,120),(145,173,153),(235,245,237)),
            incy_core::Theme::Midnight => ((10,10,20),(19,18,34),(29,27,48),(163,117,255),(157,151,183),(243,239,255)),
            _ => ((11,15,23),(18,24,35),(24,32,46),(93,130,255),(147,160,181),(245,247,250)),
        };
        let color = |(r,g,b)| Color32::from_rgb(r,g,b);
        Palette { bg: color(bg), panel: color(panel), card: color(card), accent: color(accent), muted: color(muted), text: color(text) }
    }
    const GREEN: Color32 = Color32::from_rgb(73, 205, 151);

    pub struct IncyApp {
        store: Store,
        runtime: Option<runtime::Runtime>,
        tab: Tab,
        search: String,
        link_input: String,
        config_input: String,
        config_name: String,
        sub_name: String,
        sub_url: String,
        status: String,
        selected: Option<Uuid>,
        routing_editor: String,
        xray_path: String,
        download_tx: Sender<DownloadResult>,
        download_rx: Receiver<DownloadResult>,
        active_http_port: Option<u16>,
        refreshing: HashSet<Uuid>,
        last_auto_refresh: Instant,
        tray: Option<tray_icon::TrayIcon>,
        tray_error: Option<String>,
        quit_requested: bool,
    }
    struct DownloadResult { intent: DownloadIntent, result: incy_core::Result<subscription::Download> }
    enum DownloadIntent { Refresh(Uuid), Add { name: String, url: String } }
    #[derive(PartialEq, Eq)] enum Tab { Servers, Subscriptions, Settings }
    impl IncyApp {
        pub fn new(store: Store) -> Self {
            let selected = store.state().selected_profile;
            let routing_editor = serde_json::to_string_pretty(&store.state().settings.routing).unwrap_or_default();
            let xray_path = store.state().settings.xray_path.as_ref().map(|p| p.display().to_string()).unwrap_or_default();
            let (download_tx, download_rx) = mpsc::channel();
            let (tray, tray_error) = create_tray();
            Self { store, runtime: None, tab: Tab::Servers, search: String::new(), link_input: String::new(), config_input: String::new(), config_name: "Imported Xray config".into(), sub_name: String::new(), sub_url: String::new(), status: "Готово к подключению".into(), selected, routing_editor, xray_path, download_tx, download_rx, active_http_port: None, refreshing: HashSet::new(), last_auto_refresh: Instant::now() - Duration::from_secs(60), tray, tray_error, quit_requested: false }
        }
        fn begin_download(&mut self, intent: DownloadIntent, url: String) {
            self.status = "Загружаю подписку…".into();
            let sender = self.download_tx.clone();
            std::thread::spawn(move || { let result = subscription::download(&url); let _ = sender.send(DownloadResult { intent, result }); });
        }
        fn finish_downloads(&mut self) {
            while let Ok(job) = self.download_rx.try_recv() {
                if let DownloadIntent::Refresh(id) = &job.intent { self.refreshing.remove(id); }
                match job.result {
                    Ok(download) => match job.intent {
                        DownloadIntent::Refresh(id) => {
                            let count = download.profiles.len();
                            let result = self.store.replace_subscription(id, download.profiles, download.user_info);
                            self.message(result, &format!("Обновлено серверов: {count}"));
                        }
                        DownloadIntent::Add { name, url } => {
                            let result = self.store.add_subscription(name, url, 3600, download.profiles);
                            self.message(result.map(|_| ()), "Подписка добавлена");
                            self.sub_name.clear(); self.sub_url.clear();
                        }
                    },
                    Err(error) => self.status = safe_error(error),
                }
            }
        }
        fn message(&mut self, result: incy_core::Result<()>, ok: &str) {
            self.status = match result { Ok(()) => ok.into(), Err(e) => safe_error(e) };
        }
        fn add_xray_config(&mut self) {
            match config::import_xray_json(&self.config_name, &self.config_input) {
                Ok(profile) => {
                    let id = profile.id;
                    match self.store.add_profiles(vec![profile]) {
                        Ok(_) => { self.selected = Some(id); self.config_input.clear(); self.status = "Полная конфигурация Xray импортирована".into(); }
                        Err(error) => self.status = safe_error(error),
                    }
                }
                Err(error) => self.status = safe_error(error),
            }
        }
        fn add_link(&mut self) {
            match share_link::parse(&self.link_input) {
                Ok(profile) => {
                    self.selected = Some(profile.id);
                    match self.store.add_profiles(vec![profile]) { Ok(_) => { self.link_input.clear(); self.status = "Сервер импортирован".into(); }, Err(e) => self.status = safe_error(e) }
                }
                Err(e) => self.status = safe_error(e),
            }
        }
        fn connect(&mut self, id: Uuid) {
            let Some(profile) = self.store.state().profiles.iter().find(|p| p.id == id).cloned() else { self.status = "Профиль не найден".into(); return; };
            let result = (|| -> incy_core::Result<(runtime::Runtime, Option<u16>)> {
                let xray = runtime::find_xray(&self.store.state().settings, embedded_xray())?;
                let cfg = match &profile.raw_xray_config {
                    Some(value) => value.clone(),
                    None => config::generate(&profile.endpoint, &self.store.state().settings)?,
                };
                let probe_port = if profile.raw_xray_config.is_some() { runtime::http_inbound_port(&cfg) } else { Some(self.store.state().settings.http_port) };
                let run = runtime::Runtime::start(profile.id, &profile.name, cfg, &self.store.state().settings, &xray)?;
                Ok((run, probe_port))
            })();
            match result { Ok((run, probe_port)) => { self.runtime = Some(run); self.active_http_port = probe_port; self.selected = Some(id); self.status = format!("Подключено: {}", profile.name); }, Err(e) => self.status = safe_error(e) }
        }
        fn refresh_subscription(&mut self, id: Uuid) {
            if !self.refreshing.insert(id) { return; }
            let Some(sub) = self.store.state().subscriptions.iter().find(|s| s.id == id).cloned() else { self.refreshing.remove(&id); return; };
            self.begin_download(DownloadIntent::Refresh(id), sub.url);
        }
        fn save_settings(&mut self) {
            if self.runtime.is_some() { self.status = "Отключитесь перед изменением настроек".into(); return; }
            let mut settings = self.store.state().settings.clone();
            settings.xray_path = if self.xray_path.trim().is_empty() { None } else { Some(std::path::PathBuf::from(self.xray_path.trim())) };
            match serde_json::from_str::<incy_core::Routing>(&self.routing_editor) {
                Ok(routing) => settings.routing = routing,
                Err(_) => { self.status = "Правила маршрутизации содержат ошибку JSON".into(); return; }
            }
            let result = self.store.update_settings(settings); self.message(result, "Настройки сохранены");
        }
        fn set_theme(ctx: &egui::Context, theme: incy_core::Theme, colors: Palette) {
            let mut visuals = if theme == incy_core::Theme::Light { egui::Visuals::light() } else { egui::Visuals::dark() };
            visuals.window_fill = colors.panel;
            visuals.panel_fill = colors.bg;
            visuals.widgets.inactive.bg_fill = colors.card;
            visuals.selection.bg_fill = colors.accent;
            visuals.override_text_color = Some(colors.text);
            ctx.set_visuals(visuals);
        }
    }

    impl eframe::App for IncyApp {
        #[allow(deprecated)]
        fn ui(&mut self, root_ui: &mut egui::Ui, _frame: &mut eframe::Frame) {
            let ctx = root_ui.ctx().clone();
            self.finish_downloads();
            while let Ok(event) = tray_icon::menu::MenuEvent::receiver().try_recv() {
                match event.id.as_ref() {
                    "open" => {
                        ctx.send_viewport_cmd(egui::ViewportCommand::Visible(true));
                        ctx.send_viewport_cmd(egui::ViewportCommand::Focus);
                    }
                    "toggle" => {
                        if let Some(run) = self.runtime.take() {
                            match run.stop() {
                                Ok(()) => self.status = "Подключение остановлено; системный прокси восстановлен".into(),
                                Err(_) => self.status = "Подключение остановлено, но системный прокси не удалось восстановить автоматически".into(),
                            }
                            self.active_http_port = None;
                        } else if let Some(id) = self.selected {
                            self.connect(id);
                        } else {
                            self.status = "Сначала выберите сервер".into();
                        }
                    }
                    "quit" => {
                        self.quit_requested = true;
                        ctx.send_viewport_cmd(egui::ViewportCommand::Close);
                    }
                    _ => {}
                }
            }
            if ctx.input(|input| input.viewport().close_requested()) && self.tray.is_some() && !self.quit_requested {
                ctx.send_viewport_cmd(egui::ViewportCommand::CancelClose);
                ctx.send_viewport_cmd(egui::ViewportCommand::Visible(false));
            }
            if self.last_auto_refresh.elapsed() >= Duration::from_secs(20) {
                self.last_auto_refresh = Instant::now();
                for id in subscription::due(self.store.state()) { self.refresh_subscription(id); }
            }
            if let Some(run) = &mut self.runtime {
                if let Some(error) = run.poll_exit() { self.status = error; self.runtime.take(); self.active_http_port = None; }
            }
            let theme = self.store.state().settings.theme;
            let colors = palette(theme);
            Self::set_theme(&ctx, theme, colors);
            let mut style = (*ctx.global_style()).clone();
            style.spacing.item_spacing = Vec2::new(10.0, 10.0);
            ctx.set_global_style(style);

            egui::TopBottomPanel::top("header").frame(egui::Frame::new().fill(colors.bg).inner_margin(egui::Margin::symmetric(24, 20))).show(&ctx, |ui| {
                ui.horizontal(|ui| {
                    ui.label(RichText::new("NikitaVPNClient").size(25.0).strong().color(colors.text));
                    ui.add_space(12.0);
                    ui.label(RichText::new("SECURE DESKTOP").size(11.0).strong().color(colors.accent));
                    ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                        let online = self.runtime.is_some();
                        let (dot, label) = if online { (GREEN, "ПОДКЛЮЧЕНО") } else { (colors.muted, "НЕ ПОДКЛЮЧЕНО") };
                        ui.label(RichText::new(label).size(11.0).strong().color(dot));
                        ui.label(RichText::new("●").color(dot));
                    });
                });
                ui.add_space(4.0);
                ui.label(RichText::new("Защищённый доступ через Xray-core").size(13.0).color(colors.muted));
            });
            egui::TopBottomPanel::bottom("status").frame(egui::Frame::new().fill(colors.panel).inner_margin(egui::Margin::symmetric(24, 13))).show(&ctx, |ui| {
                ui.horizontal(|ui| {
                    ui.label(RichText::new(if self.runtime.is_some() { "●" } else { "○" }).color(if self.runtime.is_some() { GREEN } else { colors.muted }));
                    ui.label(RichText::new(&self.status).color(Color32::from_rgb(209, 217, 230)));
                    ui.with_layout(Layout::right_to_left(Align::Center), |ui| { ui.label(RichText::new(format!("{} серверов", self.store.state().profiles.len())).color(colors.muted).small()); });
                });
            });
            egui::SidePanel::left("navigation").resizable(false).exact_width(206.0).frame(egui::Frame::new().fill(colors.panel).inner_margin(egui::Margin::symmetric(14, 18))).show(&ctx, |ui| {
                ui.label(RichText::new("ПОДКЛЮЧЕНИЕ").size(10.0).strong().color(colors.muted)); ui.add_space(10.0);
                nav(ui, &mut self.tab, Tab::Servers, "◈", "Серверы", colors);
                nav(ui, &mut self.tab, Tab::Subscriptions, "↻", "Подписки", colors);
                ui.add_space(22.0); ui.label(RichText::new("ПРИЛОЖЕНИЕ").size(10.0).strong().color(colors.muted)); ui.add_space(10.0);
                nav(ui, &mut self.tab, Tab::Settings, "⚙", "Настройки", colors);
                ui.with_layout(Layout::bottom_up(Align::Min), |ui| {
                    ui.label(RichText::new(format!("NikitaVPNClient · {}", env!("CARGO_PKG_VERSION"))).size(11.0).color(colors.muted));
                    ui.label(RichText::new("Powered by Xray-core").size(10.0).color(colors.muted));
                });
            });
            egui::CentralPanel::default().frame(egui::Frame::new().fill(colors.bg).inner_margin(egui::Margin::symmetric(28, 24))).show(&ctx, |ui| {
                match self.tab {
                    Tab::Servers => self.servers(ui, &ctx),
                    Tab::Subscriptions => self.subscriptions(ui),
                    Tab::Settings => self.settings(ui),
                }
            });
            ctx.request_repaint_after(Duration::from_secs(1));
        }
    }

    fn create_tray() -> (Option<tray_icon::TrayIcon>, Option<String>) {
        let result = (|| -> Result<tray_icon::TrayIcon, String> {
            use tray_icon::menu::{Menu, MenuItem};
            let mut menu = Menu::new();
            for (id, title) in [("open", "Открыть NikitaVPNClient"), ("toggle", "Подключить / отключить"), ("quit", "Выход")] {
                let item = MenuItem::with_id(id, title, true, None);
                menu.append(&item).map_err(|error| error.to_string())?;
            }
            let mut rgba = vec![0_u8; 16 * 16 * 4];
            for y in 1..15 {
                for x in 2..14 {
                    // A compact blue shield mark, generated in memory so the
                    // app does not depend on an external icon file at runtime.
                    let inside = y < 4 || (x >= 3 + (y - 4) / 2 && x <= 12 - (y - 4) / 2);
                    if inside {
                        let offset = (y * 16 + x) * 4;
                        rgba[offset..offset + 4].copy_from_slice(&[82, 132, 255, 255]);
                    }
                }
            }
            let icon = tray_icon::Icon::from_rgba(rgba, 16, 16).map_err(|error| error.to_string())?;
            tray_icon::TrayIconBuilder::new()
                .with_tooltip("NikitaVPNClient")
                .with_icon(icon)
                .with_menu(Box::new(menu))
                .build()
                .map_err(|error| error.to_string())
        })();
        match result { Ok(tray) => (Some(tray), None), Err(error) => (None, Some(error)) }
    }

    fn nav(ui: &mut egui::Ui, current: &mut Tab, target: Tab, icon: &str, label: &str, colors: Palette) {
        let active = *current == target;
        let frame = if active { egui::Frame::new().fill(colors.card).corner_radius(8).stroke(Stroke::new(1.0, colors.accent.gamma_multiply(0.45))) } else { egui::Frame::new() };
        frame.inner_margin(egui::Margin::symmetric(10, 10)).show(ui, |ui| {
            if ui.add(egui::Button::new(RichText::new(format!("{icon}    {label}")).color(if active { colors.text } else { colors.muted })).fill(Color32::TRANSPARENT).frame(false).min_size(Vec2::new(160.0, 24.0))).clicked() { *current = target; }
        });
    }
    impl IncyApp {
        fn servers(&mut self, ui: &mut egui::Ui, ctx: &egui::Context) {
            let colors = palette(self.store.state().settings.theme);
            ui.horizontal(|ui| { ui.heading(RichText::new("Серверы").size(25.0).strong()); ui.with_layout(Layout::right_to_left(Align::Center), |ui| { ui.label(RichText::new("Выберите узел для подключения").color(colors.muted)); }); });
            ui.add_space(16.0);
            ui.horizontal(|ui| {
                ui.add(egui::TextEdit::singleline(&mut self.search).hint_text("Поиск серверов…").desired_width(260.0));
                ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                    if self.runtime.is_some() {
                        if ui.add(egui::Button::new(RichText::new("Отключить").strong()).fill(Color32::from_rgb(150, 57, 66)).min_size(Vec2::new(120.0, 38.0))).clicked() {
                            if let Some(run) = self.runtime.take() {
                                self.active_http_port = None;
                                match run.stop() { Ok(()) => self.status = "Подключение остановлено; системный прокси восстановлен".into(), Err(_) => self.status = "Подключение остановлено, но системный прокси не удалось восстановить автоматически".into() }
                            }
                        }
                    } else if let Some(id) = self.selected.or(self.store.state().selected_profile) {
                        if ui.add(egui::Button::new(RichText::new("▶  Подключить").strong()).fill(colors.accent).min_size(Vec2::new(138.0, 38.0))).clicked() { self.connect(id); }
                    }
                });
            });
            ui.add_space(14.0);
            let profiles = self.store.state().profiles.clone();
            let selected = self.selected.or(self.store.state().selected_profile);
            egui::ScrollArea::vertical().max_height(360.0).show(ui, |ui| {
                for profile in profiles.iter().filter(|p| p.name.to_lowercase().contains(&self.search.to_lowercase()) || p.endpoint.address.to_lowercase().contains(&self.search.to_lowercase())) {
                    let active = selected == Some(profile.id);
                    let frame = egui::Frame::new().fill(if active { Color32::from_rgb(29, 41, 65) } else { colors.panel }).stroke(Stroke::new(if active { 1.2 } else { 0.6 }, if active { colors.accent } else { colors.card })).corner_radius(10).inner_margin(14);
                    frame.show(ui, |ui| {
                        ui.horizontal(|ui| {
                            ui.radio(active, "").clicked().then(|| { self.selected = Some(profile.id); let _ = self.store.select(Some(profile.id)); });
                            ui.vertical(|ui| {
                                ui.label(RichText::new(&profile.name).strong().size(15.0).color(colors.text));
                                let detail = if profile.raw_xray_config.is_some() { "Полная конфигурация Xray · пользовательские маршруты".to_owned() } else { format!("{} · {}:{}", profile.endpoint.summary(), profile.endpoint.address, profile.endpoint.port) };
                                ui.label(RichText::new(detail).size(12.0).color(colors.muted));
                            });
                            ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                                if self.runtime.is_none() && ui.small_button("Удалить").clicked() { let _ = self.store.remove_profile(profile.id); self.selected = self.store.state().selected_profile; }
                            });
                        });
                    });
                    ui.add_space(7.0);
                }
            });
            ui.add_space(14.0);
            card(ui, "Добавить сервер по ссылке", colors, |ui| {
                ui.horizontal(|ui| {
                    ui.add(egui::TextEdit::singleline(&mut self.link_input).hint_text("vless://… / vmess://… / trojan://…").desired_width(f32::INFINITY));
                    if ui.add(egui::Button::new("Импортировать").fill(colors.accent)).clicked() { self.add_link(); }
                });
                ui.label(RichText::new("Импортируемые протоколы: VLESS, VMess, Trojan, Shadowsocks, SOCKS5, Hysteria2, WireGuard").small().color(colors.muted));
            });
            ui.add_space(9.0);
            card(ui, "Импорт полного Xray JSON", colors, |ui| {
                ui.add(egui::TextEdit::singleline(&mut self.config_name).hint_text("Название профиля").desired_width(360.0));
                ui.add(egui::TextEdit::multiline(&mut self.config_input).code_editor().desired_rows(5).desired_width(f32::INFINITY).hint_text("{\\n  \\\"inbounds\\\": [...],\\n  \\\"outbounds\\\": [...]\\n}"));
                ui.label(RichText::new("Конфигурация сохраняется локально; все входящие слушатели обязаны быть привязаны только к localhost/loopback.").small().color(colors.muted));
                if ui.add(egui::Button::new("Импортировать полный конфиг").fill(colors.accent)).clicked() { self.add_xray_config(); }
            });
            if self.runtime.is_some() {
                ui.add_space(12.0);
                if let Some(port) = self.active_http_port {
                    if ui.button("Проверить соединение (HTTPS)").clicked() {
                        self.status = "Проверяю защищённый туннель…".into();
                        match runtime::probe(port) { Ok(ms) => self.status = format!("Соединение работает · {} мс", ms.as_millis()), Err(e) => self.status = safe_error(e) }
                    }
                } else {
                    ui.label(RichText::new("В импортированной конфигурации нет HTTP inbound для встроенной проверки.").small().color(colors.muted));
                }
            }
            if self.store.state().profiles.is_empty() { ctx.request_repaint_after(Duration::from_secs(2)); }
        }
        fn subscriptions(&mut self, ui: &mut egui::Ui) {
            let colors = palette(self.store.state().settings.theme);
            ui.heading(RichText::new("Подписки").size(25.0).strong());
            ui.label(RichText::new("HTTPS-подписки с автоматическим обновлением списка узлов").color(colors.muted)); ui.add_space(16.0);
            let subs = self.store.state().subscriptions.clone();
            for sub in subs {
                card(ui, &sub.name, colors, |ui| {
                    ui.label(RichText::new(format!("Обновление каждые {} мин · серверов: {}", sub.refresh_secs / 60, self.store.state().profiles.iter().filter(|p| p.subscription_id == Some(sub.id)).count())).color(colors.muted));
                    ui.horizontal(|ui| {
                        if ui.button("Обновить сейчас").clicked() { self.refresh_subscription(sub.id); }
                        if ui.button("Удалить подписку").clicked() { let result = self.store.remove_subscription(sub.id, true); self.message(result, "Подписка удалена; серверы оставлены"); }
                        if let Some(info) = &sub.user_info { ui.label(RichText::new(info).small().color(colors.muted)); }
                    });
                }); ui.add_space(8.0);
            }
            ui.add_space(12.0);
            card(ui, "Добавить HTTPS-подписку", colors, |ui| {
                ui.add(egui::TextEdit::singleline(&mut self.sub_name).hint_text("Название (необязательно)").desired_width(380.0));
                ui.add(egui::TextEdit::singleline(&mut self.sub_url).hint_text("https://provider.example/subscription").desired_width(f32::INFINITY));
                ui.label(RichText::new("Ссылка на подписку содержит секретный токен и хранится локально.").small().color(colors.muted));
                if ui.add(egui::Button::new("Добавить подписку").fill(colors.accent)).clicked() {
                    let name = if self.sub_name.trim().is_empty() { "Subscription".into() } else { self.sub_name.trim().to_owned() };
                    let url = self.sub_url.clone();
                    self.begin_download(DownloadIntent::Add { name, url: url.clone() }, url);
                }
            });
        }
        fn settings(&mut self, ui: &mut egui::Ui) {
            let colors = palette(self.store.state().settings.theme);
            ui.heading(RichText::new("Настройки").size(25.0).strong());
            ui.label(RichText::new("Клиентский профиль и локальные правила").color(colors.muted)); ui.add_space(14.0);
            card(ui, "Системный трей", colors, |ui| {
                if self.tray.is_some() {
                    ui.label(RichText::new("Значок активен. Закрытие окна сворачивает приложение в трей.").color(colors.text));
                    ui.label(RichText::new("Через меню значка можно открыть окно, подключиться или отключиться, а также завершить приложение.").small().color(colors.muted));
                } else {
                    ui.label(RichText::new(format!("Системный трей недоступен: {}", self.tray_error.as_deref().unwrap_or("ошибка инициализации"))).color(Color32::from_rgb(238, 181, 105)));
                    ui.label(RichText::new("Закрытие окна завершит приложение; подключение будет остановлено штатно.").small().color(colors.muted));
                }
            });
            ui.add_space(10.0);
            card(ui, "Xray-core", colors, |ui| {
                ui.label("Путь к исполняемому файлу (пусто — поиск рядом с приложением и в PATH)");
                ui.add(egui::TextEdit::singleline(&mut self.xray_path).hint_text(if cfg!(windows) { "C:\\incy\\xray.exe" } else { "/usr/bin/xray" }).desired_width(f32::INFINITY));
                ui.label(RichText::new("Xray-core не включён в комплект: установите официальный бинарный файл отдельно.").small().color(colors.muted));
            });
            ui.add_space(10.0);
            card(ui, "Прокси и интерфейс", colors, |ui| {
                let mut settings = self.store.state().settings.clone();
                ui.horizontal(|ui| { ui.label("SOCKS5 порт"); ui.add(egui::DragValue::new(&mut settings.socks_port).range(1..=65535)); ui.label("HTTP порт"); ui.add(egui::DragValue::new(&mut settings.http_port).range(1..=65535)); });
                ui.checkbox(&mut settings.set_system_proxy, "Устанавливать пользовательский системный прокси при подключении");
                ui.label(RichText::new("Это не kill switch и не VPN/TUN: другие приложения могут обходить системный прокси.").small().color(Color32::from_rgb(238, 181, 105)));
                ui.horizontal(|ui| {
                    ui.label("Тема"); egui::ComboBox::from_id_salt("theme").selected_text(format!("{:?}", settings.theme)).show_ui(ui, |ui| { ui.selectable_value(&mut settings.theme, incy_core::Theme::Dark, "Графит"); ui.selectable_value(&mut settings.theme, incy_core::Theme::Light, "Светлая"); ui.selectable_value(&mut settings.theme, incy_core::Theme::Midnight, "Полночь"); ui.selectable_value(&mut settings.theme, incy_core::Theme::Ocean, "Океан"); ui.selectable_value(&mut settings.theme, incy_core::Theme::Forest, "Лес"); ui.selectable_value(&mut settings.theme, incy_core::Theme::System, "Системная (графит)"); });
                });
                if ui.add_enabled(self.runtime.is_none(), egui::Button::new("Сохранить параметры прокси и темы")).clicked() { let result = self.store.update_settings(settings); self.message(result, "Настройки сохранены"); }
            });
            ui.add_space(10.0);
            card(ui, "Маршрутизация Xray (JSON)", colors, |ui| {
                ui.label(RichText::new("Списки доменов/IP адресов; приватные сети обходятся напрямую, если включён bypassLan.").small().color(colors.muted));
                ui.add(egui::TextEdit::multiline(&mut self.routing_editor).code_editor().desired_rows(8).desired_width(f32::INFINITY));
                if ui.button("Проверить и сохранить маршруты").clicked() { self.save_settings(); }
            });
            ui.add_space(10.0);
            card(ui, "Локальные данные", colors, |ui| {
                ui.label(RichText::new(self.store.path().display().to_string()).small().color(colors.muted));
                ui.label(RichText::new("Серверные ключи и подписки сохраняются в приватном локальном файле.").small().color(colors.muted));
            });
        }
    }
    fn card(ui: &mut egui::Ui, title: &str, colors: Palette, add: impl FnOnce(&mut egui::Ui)) {
        egui::Frame::new().fill(colors.panel).stroke(Stroke::new(0.7, colors.card)).corner_radius(10).inner_margin(16).show(ui, |ui| { ui.label(RichText::new(title).size(14.0).strong().color(colors.text)); ui.add_space(8.0); add(ui); });
    }
    fn safe_error(error: Error) -> String {
        match error {
            Error::InvalidProfile(m) | Error::Limit(m) => format!("Проверьте данные: {m}"),
            Error::XrayNotFound => "Xray-core не найден. Укажите путь в Настройках.".into(),
            Error::PortInUse => "Локальный порт занят другим приложением.".into(),
            Error::XrayStartup | Error::XrayRejected(_) => "Xray не запустился. Проверьте конфигурацию и версию Xray-core.".into(),
            Error::SystemProxy(_) => "Не удалось изменить системный прокси; проверьте окружение рабочего стола и настройки.".into(),
            Error::Http(_) => "Не удалось загрузить подписку. Проверьте HTTPS-ссылку и доступность провайдера.".into(),
            _ => "Операция не выполнена; проверьте введённые данные.".into(),
        }
    }
}
