//! The tray icon: the only visible part of a portable tool.
//!
//! PLAN.md section 1 asked for a start popup that says the tool is running and shows its address.
//! That popup is the balloon the icon arrives with: it needs no window of its own, it closes
//! itself, and it holds nobody up. Clicking the icon opens the browser on the UI, the right button
//! offers `Open`, `Pause learning`, `Pause protection` and `Quit` (plus `Relaunch elevated` while
//! the process is not elevated), and nothing else happens at startup, so the tool stays out of the
//! way until it is asked for.
//!
//! A tray icon is not a widget: `Shell_NotifyIconW` binds an icon to a *window* and delivers its
//! clicks as messages to that window's procedure. So this module owns a message-only window and the
//! thread that pumps its messages, which is also why the tray cannot live on one of the server's
//! request threads.
//!
//! The right button opens a menu with `Open`, `Pause learning`, `Pause protection` and `Quit`, and
//! `Relaunch elevated` before `Quit` while the process is unelevated. The protection pause and the
//! relaunch are POSTs to the server's own routes, which is what keeps the tray a client of the
//! guarded API rather than a second way in. The learning pause is the one entry the tray applies
//! itself: it flips the running [`live`](crate::server::Live) flag and writes no file, so it
//! reaches the same flag the settings route writes without sending a request of its own. It
//! lasts for this run, which is what a pause means, and a settings change through the web remains
//! the way to decide it permanently. Protection is not even flipped here, because that is the code
//! that knows what pausing the firewall means.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{Sender, channel};
use std::sync::{Arc, Mutex};
use std::thread::{self, JoinHandle};

/// The URL a click opens.
///
/// A window procedure is a bare function pointer and cannot be handed a context, so the one value it
/// needs lives in the process. There is exactly one tray per process, which is what makes that
/// acceptable rather than merely convenient.
#[cfg(windows)]
static UI_URL: Mutex<String> = Mutex::new(String::new());

/// The flag that keeps the server's accept loop alive, cleared by `Quit`.
///
/// The window procedure needs it and, like [`UI_URL`], cannot be handed a capture, so it lives in
/// the process next to it. There is exactly one tray per process here too.
#[cfg(windows)]
static SERVER_RUNNING: Mutex<Option<Arc<AtomicBool>>> = Mutex::new(None);

/// The two settings that may change while the process runs, shared so the menu can pause learning.
#[cfg(windows)]
static LIVE: Mutex<Option<Arc<crate::server::Live>>> = Mutex::new(None);

/// Our icon's identifier among this window's icons.
#[cfg(windows)]
const ICON_ID: u32 = 1;

/// The id of the icon `build.rs` put in the executable's resources.
///
/// `winresource` always writes the icon under id 1, and `MAKEINTRESOURCE` is a pointer-sized integer
/// rather than a string, which is what [`LoadIconW`] takes for a resource that is named by number.
#[cfg(windows)]
const APP_ICON: u16 = 1;

/// The identifiers of the menu items.
#[cfg(windows)]
const MENU_QUIT: usize = 0x100;

#[cfg(windows)]
const MENU_OPEN: usize = 0x101;

#[cfg(windows)]
const MENU_PAUSE: usize = 0x102;

#[cfg(windows)]
const MENU_PROTECTION: usize = 0x103;

/// The entry that asks the server to stop and be replaced by an elevated start. Only offered
/// while the process is not elevated, because a process cannot raise itself twice.
const MENU_RELAUNCH: usize = 0x104;

/// The icon in the notification area, plus the thread that answers its clicks.
pub struct Tray {
    /// The tray thread, as soon as it has its window. A thread id is a number rather than a handle,
    /// which is what lets the shutdown reach it from another thread.
    thread: Arc<Mutex<Option<u32>>>,
    join: Option<JoinHandle<()>>,
    /// Whether the icon reached the notification area.
    added: bool,
}

impl Tray {
    /// Put the icon in the notification area.
    ///
    /// A machine where the icon cannot be added is not a failure of the tool: the server answers
    /// anyway and the user types the address, so a refused icon is only logged.
    ///
    /// `running` is the server's flag: choosing `Quit` clears it, which is what ends the process
    /// rather than only the tray thread. `live` is what `Pause learning` flips.
    pub fn start(url: String, running: Arc<AtomicBool>, live: Arc<crate::server::Live>) -> Self {
        let thread = Arc::new(Mutex::new(None));
        let (ready, ready_receiver) = channel::<bool>();

        // The window procedure is a bare function pointer, so it reads the URL and the flag from
        // the process rather than from a capture. Both are set before the thread that could answer
        // a click starts.
        #[cfg(windows)]
        {
            *UI_URL.lock().expect("url lock poisoned") = url;
            *SERVER_RUNNING.lock().expect("running lock poisoned") = Some(running);
            *LIVE.lock().expect("live lock poisoned") = Some(live);
        }

        #[cfg(not(windows))]
        {
            let _ = url;
            let _ = running;
            let _ = live;
        }

        let join = {
            let thread = Arc::clone(&thread);

            thread::spawn(move || run(thread, ready))
        };

        // Waiting for the thread keeps the shutdown honest: posting to a thread that has not got its
        // window yet would drop the message and leave the thread running until the process ends.
        // The thread only sends when the icon is really there, so a closed channel means it gave up.
        let added = ready_receiver.recv().unwrap_or(false);

        Self {
            thread,
            join: Some(join),
            added,
        }
    }

    /// Whether the icon is in the notification area.
    pub fn added(&self) -> bool {
        self.added
    }
}

impl Drop for Tray {
    fn drop(&mut self) {
        #[cfg(windows)]
        if let Some(id) = *self.thread.lock().expect("tray thread lock poisoned") {
            use windows::Win32::Foundation::{LPARAM, WPARAM};
            use windows::Win32::UI::WindowsAndMessaging::{PostThreadMessageW, WM_QUIT};

            // `WM_QUIT` ends `GetMessageW` directly, which is what a thread with no visible window
            // needs: there is no window to close in order to unblock it.
            unsafe {
                PostThreadMessageW(id, WM_QUIT, WPARAM(0), LPARAM(0)).ok();
            }
        }

        if let Some(join) = self.join.take() {
            let _ = join.join();
        }
    }
}

/// Register the icon and pump the window's messages until the process is done with it.
#[cfg(windows)]
fn run(thread: Arc<Mutex<Option<u32>>>, ready: Sender<bool>) {
    use tracing::{debug, warn};
    use windows::Win32::Foundation::HINSTANCE;
    use windows::Win32::System::LibraryLoader::GetModuleHandleW;
    use windows::Win32::UI::Shell::{
        NIF_ICON, NIF_INFO, NIF_MESSAGE, NIF_TIP, NIIF_INFO, NIM_ADD, NIM_DELETE, NIM_MODIFY,
        NOTIFYICONDATAW, Shell_NotifyIconW,
    };
    use windows::Win32::UI::WindowsAndMessaging::{
        CreateWindowExW, DestroyWindow, DispatchMessageW, GetMessageW, HWND_MESSAGE, LoadIconW,
        MSG, RegisterClassW, TranslateMessage, WINDOW_EX_STYLE, WINDOW_STYLE, WM_APP, WNDCLASSW,
    };
    use windows::core::PCWSTR;

    // `HMODULE` and `HINSTANCE` are separate types in the crate but the same value, and the window
    // class wants the latter.
    let instance = match unsafe { GetModuleHandleW(None) } {
        Ok(module) => HINSTANCE(module.0),
        Err(error) => {
            warn!(reason = %format!("{error}"), "tray could not read the module handle");

            return;
        }
    };

    // Our own icon, taken out of the executable rather than from a file next to it, so a single
    // portable `.exe` is still enough. Should the resource be missing — a build without `build.rs`,
    // which happens when the resource compiler is not installed — the system's default application
    // icon is a perfectly good fallback.
    let icon = match unsafe { LoadIconW(Some(instance), PCWSTR(APP_ICON as *const u16)) } {
        Ok(icon) => icon,
        Err(_) => unsafe {
            LoadIconW(
                None,
                windows::Win32::UI::WindowsAndMessaging::IDI_APPLICATION,
            )
        }
        .unwrap_or_default(),
    };

    let class = wide("winfw-mcp-tray");
    let title = wide("winfw-mcp");

    let registration = WNDCLASSW {
        lpfnWndProc: Some(wndproc),
        hInstance: instance,
        hIcon: icon,
        lpszClassName: PCWSTR(class.as_ptr()),
        ..Default::default()
    };

    if unsafe { RegisterClassW(&registration) } == 0 {
        warn!("tray window class was refused");

        return;
    }

    // A message-only window: never visible, and parented to the special `HWND_MESSAGE`, which is
    // what keeps it out of the taskbar and the alt-tab list.
    let handle = match unsafe {
        CreateWindowExW(
            WINDOW_EX_STYLE::default(),
            PCWSTR(class.as_ptr()),
            PCWSTR(title.as_ptr()),
            WINDOW_STYLE::default(),
            0,
            0,
            0,
            0,
            Some(HWND_MESSAGE),
            None,
            Some(instance),
            None,
        )
    } {
        Ok(handle) => handle,
        Err(error) => {
            warn!(reason = %format!("{error}"), "tray window could not be created");

            return;
        }
    };

    // The id of the thread that owns the window is this one, and it is what the shutdown posts
    // `WM_QUIT` to.
    thread
        .lock()
        .expect("tray thread lock poisoned")
        .replace(current_thread_id());

    let mut data = NOTIFYICONDATAW {
        cbSize: std::mem::size_of::<NOTIFYICONDATAW>() as u32,
        hWnd: handle,
        uID: ICON_ID,
        uFlags: NIF_MESSAGE | NIF_ICON | NIF_TIP,
        uCallbackMessage: WM_APP + 1,
        hIcon: icon,
        ..Default::default()
    };

    copy_wide(&mut data.szTip, "winfw-mcp");

    if !unsafe { Shell_NotifyIconW(NIM_ADD, &data) }.as_bool() {
        warn!("shell refused the tray icon");

        unsafe {
            DestroyWindow(handle).ok();
        }

        return;
    }

    // The start popup. A balloon the shell will not show costs a log line and nothing else: the
    // icon is already in the notification area, and clicking it opens the page anyway. The version
    // is deliberately left unset, which is what keeps the mouse events where the window procedure
    // reads them today; the price is that the shell does not report a click on the balloon, so the
    // balloon is read rather than used, and it goes away on its own.
    let popup = balloon_text(&UI_URL.lock().expect("url lock poisoned"));

    if !popup.is_empty() {
        data.uFlags = NIF_INFO;
        data.dwInfoFlags = NIIF_INFO;
        copy_wide(&mut data.szInfoTitle, "winfw-mcp");
        copy_wide(&mut data.szInfo, &popup);

        if !unsafe { Shell_NotifyIconW(NIM_MODIFY, &data) }.as_bool() {
            debug!("shell refused the start balloon");
        }
    }

    let _ = ready.send(true);
    debug!("tray icon added");

    let mut message = MSG::default();

    // `GetMessageW` returns 0 on `WM_QUIT` and -1 on failure, so only a positive value continues.
    // The quit comes either from `Quit` in the menu or from dropping the `Tray`.
    while unsafe { GetMessageW(&raw mut message, None, 0, 0) }.0 > 0 {
        unsafe {
            let _ = TranslateMessage(&raw const message);
            DispatchMessageW(&raw const message);
        }
    }

    unsafe {
        let _ = Shell_NotifyIconW(NIM_DELETE, &data);
        DestroyWindow(handle).ok();
    }

    thread.lock().expect("tray thread lock poisoned").take();

    debug!("tray icon removed");
}

/// Answer one message of the tray window.
#[cfg(windows)]
unsafe extern "system" fn wndproc(
    handle: windows::Win32::Foundation::HWND,
    message: u32,
    wparam: windows::Win32::Foundation::WPARAM,
    lparam: windows::Win32::Foundation::LPARAM,
) -> windows::Win32::Foundation::LRESULT {
    use windows::Win32::UI::WindowsAndMessaging::{
        DefWindowProcW, WM_APP, WM_LBUTTONUP, WM_RBUTTONUP,
    };

    // The callback message the icon was registered with.
    const TRAY_MESSAGE: u32 = WM_APP + 1;

    if message == TRAY_MESSAGE {
        // Because no version was set on the icon, the mouse event that caused the callback is the
        // high word of `lparam`.
        match ((lparam.0 as usize) >> 16) as u32 {
            WM_LBUTTONUP => open_browser(),
            WM_RBUTTONUP => show_menu(handle),
            _ => {}
        }

        return windows::Win32::Foundation::LRESULT(0);
    }

    unsafe { DefWindowProcW(handle, message, wparam, lparam) }
}

/// Hand a URL to the shell, which is what opens the default browser.
///
/// The tray's own click ends up here, and so does a second process that found the instance name
/// already taken and has nothing else to offer the user.
#[cfg(windows)]
pub fn open_url(url: &str) {
    use tracing::info;
    use windows::Win32::UI::Shell::ShellExecuteW;
    use windows::Win32::UI::WindowsAndMessaging::SW_SHOWNORMAL;
    use windows::core::{PCWSTR, w};

    let path = wide(url);

    // `ShellExecuteW` reports a value rather than an error for anything that went wrong, and there
    // is nothing a tray icon can do about it beyond logging: the browser is the user's, not ours.
    let status = unsafe {
        ShellExecuteW(
            None,
            w!("open"),
            PCWSTR(path.as_ptr()),
            PCWSTR::null(),
            PCWSTR::null(),
            SW_SHOWNORMAL,
        )
    };

    info!(%url, status = status.0 as usize, "asked the shell for the browser");
}

/// The URL the tray was started with, handed to the shell.
#[cfg(windows)]
fn open_browser() {
    let url = UI_URL.lock().expect("url lock poisoned").clone();

    open_url(&url);
}

/// The authority and the session token of a tray URL.
///
/// The tray URL is what the browser gets — `http://127.0.0.1:8788/#token=…` — and a request the
/// tray makes itself needs exactly two things out of it: where to connect, and what to write with.
/// `None` for a URL that carries no token, which is the second instance's plain URL rather than
/// this process's.
fn split_url(url: &str) -> Option<(&str, &str)> {
    let rest = url.trim().strip_prefix("http://")?;

    let (authority, fragment) = rest.split_once('/')?;
    let fragment = fragment.strip_prefix('#').unwrap_or(fragment);
    let fragment = fragment.split('&').next().unwrap_or_default();

    let token = fragment
        .strip_prefix("token=")
        .filter(|token| !token.is_empty())?;

    Some((authority, token))
}

/// Send one writing request to the server over loopback and report whether it answered 200.
///
/// The tray is a client of the API exactly like the page is, which is deliberate: the flag, the
/// store work and the log line all live in the one route, so the menu cannot end up disagreeing
/// with the server about what the firewall is doing. A tray that rebuilt the store itself would be
/// a second implementation of the same decision, and the one the tests do not reach.
#[cfg(windows)]
fn api_post(path: &str, body: &str) -> bool {
    use std::io::{BufRead, BufReader, Write};
    use std::net::TcpStream;
    use std::time::Duration;
    use tracing::warn;

    let url = UI_URL.lock().expect("url lock poisoned").clone();

    let Some((authority, token)) = split_url(&url) else {
        warn!(url = %url, "the tray could not read the server address");

        return false;
    };

    let request = format!(
        "POST {path} HTTP/1.1\r\nHost: {authority}\r\nOrigin: http://{authority}\
         \r\nContent-Type: application/json\r\nx-winfw-token: {token}\
         \r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len(),
    );

    let answer = TcpStream::connect(authority).and_then(|mut stream| {
        // Bounded, because the tray thread answers the icon: a server that stopped reading must
        // not take the notification area down with it.
        stream.set_write_timeout(Some(Duration::from_secs(5)))?;
        stream.set_read_timeout(Some(Duration::from_secs(5)))?;

        stream.write_all(request.as_bytes())?;
        stream.flush()?;

        // Only the status line is read. The body is the whole state, which the tray has no use
        // for, and reading it would mean trusting the server to close the connection.
        let mut line = String::new();
        BufReader::new(&mut stream).read_line(&mut line)?;

        Ok(line)
    });

    match answer {
        Ok(line) if line.starts_with("HTTP/1.1 200") => true,
        Ok(line) => {
            warn!(
                status = line.trim(),
                "the server refused the tray's request"
            );

            false
        }
        Err(error) => {
            warn!(reason = %error, "the tray could not reach the server");

            false
        }
    }
}

/// Show the right-button menu and act on what was chosen.
#[cfg(windows)]
fn show_menu(handle: windows::Win32::Foundation::HWND) {
    use tracing::{info, warn};
    use windows::Win32::UI::WindowsAndMessaging::{
        AppendMenuW, CreatePopupMenu, DestroyMenu, GetCursorPos, MF_SEPARATOR, MF_STRING,
        PostQuitMessage, SetForegroundWindow, TPM_BOTTOMALIGN, TPM_RETURNCMD, TrackPopupMenu,
    };
    use windows::core::{PCWSTR, w};

    let Ok(menu) = (unsafe { CreatePopupMenu() }) else {
        return;
    };

    // The menu says what pausing would do, which is only honest while it reflects the flags the
    // server reads. A change made in the web between two openings is picked up the same way,
    // because both labels are read from the flags every time the menu is built.
    let (learning, protection) = LIVE
        .lock()
        .expect("live lock poisoned")
        .as_ref()
        .map_or((false, true), |live| (live.learning(), live.protection()));

    unsafe {
        AppendMenuW(menu, MF_STRING, MENU_OPEN, w!("Open")).ok();
        AppendMenuW(menu, MF_SEPARATOR, 0, PCWSTR::null()).ok();

        AppendMenuW(
            menu,
            MF_STRING,
            MENU_PAUSE,
            if learning {
                w!("Pause learning")
            } else {
                w!("Resume learning")
            },
        )
        .ok();

        AppendMenuW(
            menu,
            MF_STRING,
            MENU_PROTECTION,
            if protection {
                w!("Pause protection")
            } else {
                w!("Resume protection")
            },
        )
        .ok();

        if !crate::elevated::is_elevated() {
            AppendMenuW(menu, MF_STRING, MENU_RELAUNCH, w!("Relaunch elevated")).ok();
        }

        AppendMenuW(menu, MF_SEPARATOR, 0, PCWSTR::null()).ok();
        AppendMenuW(menu, MF_STRING, MENU_QUIT, w!("Quit")).ok();

        let mut point = windows::Win32::Foundation::POINT::default();
        GetCursorPos(&raw mut point).ok();

        // Without this the menu can stay open over the window it belongs to.
        let _ = SetForegroundWindow(handle);

        // `TPM_RETURNCMD` makes the choice the return value instead of a `WM_COMMAND` that would
        // have to be picked out of the message loop, which keeps quitting in one place.
        let choice = TrackPopupMenu(
            menu,
            TPM_BOTTOMALIGN | TPM_RETURNCMD,
            point.x,
            point.y,
            Some(0),
            handle,
            None,
        );

        DestroyMenu(menu).ok();

        if choice.0 == MENU_OPEN as i32 {
            open_browser();

            return;
        }

        if choice.0 == MENU_PAUSE as i32 {
            let guard = LIVE.lock().expect("live lock poisoned");

            if let Some(live) = guard.as_ref() {
                info!(
                    learning = live.toggle_learning(),
                    "tray flipped learning mode"
                );
            } else {
                warn!("tray pause found no live settings");
            }

            return;
        }

        if choice.0 == MENU_PROTECTION as i32 {
            api_post("/api/protection", "{}");

            return;
        }

        if choice.0 == MENU_RELAUNCH as i32 {
            // The route stops the server when the shell granted the elevated start. The accept
            // loop ends with it, but this thread answers the icon on its own message loop, so it
            // leaves that loop only once the server actually agreed.
            if api_post("/api/relaunch", "{}") {
                info!("the tray asked for an elevated relaunch");

                PostQuitMessage(0);
            }

            return;
        }

        if choice.0 == MENU_QUIT as i32 {
            // Clearing the flag is what stops the accept loop and with it the process. On its own
            // `PostQuitMessage` ends only this thread's message loop, which would leave a running
            // server behind with no icon in the notification area.
            if let Some(running) = SERVER_RUNNING
                .lock()
                .expect("running lock poisoned")
                .as_ref()
            {
                running.store(false, Ordering::SeqCst);
            }

            PostQuitMessage(0);
        }
    }
}

/// Encode a string as a terminated wide string.
fn wide(value: &str) -> Vec<u16> {
    let mut encoded: Vec<u16> = value.encode_utf16().collect();
    encoded.push(0);

    encoded
}

/// The text of the start balloon: the address, without the token the tray opens the browser with.
///
/// The token is thirty-odd characters the user did not ask for and cannot type, and a balloon is
/// readable for a few seconds. The address alone is what PLAN.md section 1 wants shown, and the
/// page gets its token from the fragment of the URL, so the shorter text loses nothing.
#[cfg(windows)]
fn balloon_text(url: &str) -> String {
    url.split_once(['?', '#'])
        .map_or_else(|| url.to_owned(), |(head, _)| head.to_owned())
}

/// Copy a string into one of the fixed wide buffers of a shell struct.
#[cfg(windows)]
fn copy_wide(buffer: &mut [u16], value: &str) {
    let encoded = wide(value);
    let take = encoded.len().min(buffer.len());

    buffer[..take].copy_from_slice(&encoded[..take]);
}

/// The id of the calling thread, for `PostThreadMessageW`.
#[cfg(windows)]
fn current_thread_id() -> u32 {
    unsafe { windows::Win32::System::Threading::GetCurrentThreadId() }
}

/// Hand a URL to the shell. Without a shell there is nothing to hand it to.
#[cfg(not(windows))]
pub fn open_url(url: &str) {
    let _ = url;
}

/// The non-Windows tray exists so the crate still builds for a doc tool.
#[cfg(not(windows))]
fn run(thread: Arc<Mutex<Option<u32>>>, ready: Sender<bool>) {
    let _ = thread;
    // Nothing is sent, so the icon counts as not added.
    drop(ready);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_wide_string_is_nul_terminated() {
        assert_eq!(wide("ab"), vec![u16::from(b'a'), u16::from(b'b'), 0]);
    }

    /// The balloon shows the address, not the session token the tray URL carries with it.
    #[cfg(windows)]
    #[test]
    fn the_start_balloon_names_the_address_and_not_the_token() {
        assert_eq!(
            balloon_text("http://127.0.0.1:8788/#token=0f3a"),
            "http://127.0.0.1:8788/"
        );
        assert_eq!(
            balloon_text("http://127.0.0.1:8788"),
            "http://127.0.0.1:8788"
        );
    }

    /// The self-request the protection menu item makes reads two things out of the tray URL, and
    /// the plain URL a second instance hands to the shell has neither of them.
    #[test]
    fn a_tray_url_yields_the_authority_and_the_token() {
        assert_eq!(
            split_url("http://127.0.0.1:8788/#token=0f3a"),
            Some(("127.0.0.1:8788", "0f3a"))
        );
        assert_eq!(
            split_url("http://localhost:8788/#token=0f3a"),
            Some(("localhost:8788", "0f3a"))
        );
    }

    #[test]
    fn a_tray_url_without_a_token_has_nothing_to_write_with() {
        assert_eq!(split_url("http://127.0.0.1:8788"), None);
        assert_eq!(split_url("http://127.0.0.1:8788/"), None);
        assert_eq!(split_url("http://127.0.0.1:8788/#token="), None);
    }

    #[cfg(windows)]
    #[test]
    fn a_tip_is_copied_without_its_surplus() {
        let mut buffer = [0u16; 4];

        copy_wide(&mut buffer, "abcdef");

        assert_eq!(
            buffer,
            [
                u16::from(b'a'),
                u16::from(b'b'),
                u16::from(b'c'),
                u16::from(b'd')
            ]
        );
    }
}
