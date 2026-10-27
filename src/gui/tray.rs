//! System-tray integration. Windows-first (the shipping target); other
//! platforms get an inert stub so the GUI compiles — the window alone is
//! fully functional there.

use super::App;

#[derive(Debug, Clone, PartialEq)]
#[allow(dead_code)] // variants are constructed on Windows only
pub enum Action {
    None,
    Connect,
    Disconnect,
    Quit,
}

#[cfg(not(windows))]
mod imp {
    use super::{Action, App};
    use eframe::egui::Context;

    pub struct Tray;

    impl Tray {
        pub fn create() -> Option<Self> {
            None
        }
        pub fn set_connected(&mut self, _connected: bool) {}
        pub fn poll(&mut self, _ctx: &Context) -> Action {
            Action::None
        }
    }

    #[allow(dead_code)]
    fn _typecheck(_app: &mut App) {}
}

#[cfg(not(windows))]
pub use imp::Tray;

#[cfg(windows)]
mod imp {
    use super::{Action, App};
    use eframe::egui::Context;
    use tray_icon::menu::{Menu, MenuEvent, MenuItem};
    use tray_icon::{Icon, TrayIcon, TrayIconBuilder};

    const ID_CONNECT: &str = "cfssh.connect";
    const ID_DISCONNECT: &str = "cfssh.disconnect";
    const ID_QUIT: &str = "cfssh.quit";

    pub struct Tray {
        tray: TrayIcon,
        connect_item: MenuItem,
        disconnect_item: MenuItem,
        green_icon: Icon,
        gray_icon: Icon,
        connected: bool,
    }

    impl Tray {
        pub fn create() -> Option<Self> {
            let green_icon = make_icon([90, 190, 90]);
            let gray_icon = make_icon([150, 150, 150]);
            let connect_item = MenuItem::with_id(ID_CONNECT, "Connect", true, None);
            let disconnect_item = MenuItem::with_id(ID_DISCONNECT, "Disconnect", false, None);
            let quit = MenuItem::with_id(ID_QUIT, "Quit (stops the forwarder)", true, None);
            let mut menu = Menu::new();
            let _ = menu.append(&connect_item);
            let _ = menu.append(&disconnect_item);
            let _ = menu.append(&quit);

            let tray = TrayIconBuilder::new()
                .with_tooltip("cfssh-proxy — SSH over Cloudflare Tunnel")
                .with_icon(gray_icon.clone())
                .with_menu(Box::new(menu))
                .with_menu_on_left_click(true)
                .build()
                .ok()?;

            Some(Tray {
                tray,
                connect_item,
                disconnect_item,
                green_icon,
                gray_icon,
                connected: false,
            })
        }

        pub fn set_connected(&mut self, connected: bool) {
            self.connected = connected;
            self.connect_item.set_enabled(!connected);
            self.disconnect_item.set_enabled(connected);
            self.tray.set_icon(
                (if connected {
                    &self.green_icon
                } else {
                    &self.gray_icon
                })
                .clone(),
            );
        }

        /// Drain tray menu events; translate to App actions.
        pub fn poll(&mut self, _ctx: &Context) -> Action {
            let mut action = Action::None;
            while let Ok(ev) = MenuEvent::receiver().try_recv() {
                match ev.id().as_ref() {
                    ID_CONNECT => action = Action::Connect,
                    ID_DISCONNECT => action = Action::Disconnect,
                    ID_QUIT => action = Action::Quit,
                    _ => {}
                }
            }
            action
        }
    }

    /// A solid rounded square; color indicates the forwarder state.
    fn make_icon([r, g, b]: [u8; 3]) -> Icon {
        const S: u32 = 32;
        let mut rgba = Vec::with_capacity((S * S * 4) as usize);
        for y in 0..S {
            for x in 0..S {
                let border = x < 2 || y < 2 || x > S - 3 || y > S - 3;
                rgba.push(if border { 30 } else { r });
                rgba.push(if border { 30 } else { g });
                rgba.push(if border { 30 } else { b });
                rgba.push(255);
            }
        }
        Icon::from_rgba(rgba, S, S).expect("icon rgba")
    }

    #[allow(dead_code)]
    fn _typecheck(_app: &mut App) {}
}

#[cfg(windows)]
pub use imp::{Action, Tray};
