//! The tray icon: the only visible part of a portable tool.
//!
//! PLAN.md section 1 replaced simplewall's startup popup with a notification-area icon, because a
//! tool started by double-click has no terminal to print its address in. Clicking the icon opens
//! the browser on the UI, the right button offers `Quit`, and nothing else happens at startup, so
//! the tool stays out of the way until it is asked for.
//!
//! A tray icon is not a widget: `Shell_NotifyIconW` binds an icon to a *window* and delivers its
//! clicks as messages to that window's procedure. So this module owns a message-only window and the
//! thread that pumps its messages, which is also why the tray cannot live on one of the server's
//! request threads.

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

/// Our icon's identifier among this window's icons.
#[cfg(windows)]
const ICON_ID: u32 = 1;

/// The id of the icon `build.rs` put in the executable's resources.
///
/// `winresource` always writes the icon under id 1, and `MAKEINTRESOURCE` is a pointer-sized integer
/// rather than a string, which is what [`LoadIconW`] takes for a resource that is named by number.
#[cfg(windows)]
const APP_ICON: u16 = 1;

/// The identifier of the `Quit` menu item.
#[cfg(windows)]
const MENU_QUIT: usize = 0x100;

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
    /// rather than only the tray thread.
    pub fn start(url: String, running: Arc<AtomicBool>) -> Self {
        let thread = Arc::new(Mutex::new(None));
        let (ready, ready_receiver) = channel::<bool>();

        // The window procedure is a bare function pointer, so it reads the URL and the flag from
        // the process rather than from a capture. Both are set before the thread that could answer
        // a click starts.
        #[cfg(windows)]
        {
            *UI_URL.lock().expect("url lock poisoned") = url;
            *SERVER_RUNNING.lock().expect("running lock poisoned") = Some(running);
        }

        #[cfg(not(windows))]
        {
            let _ = url;
            let _ = running;
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
        NIF_ICON, NIF_MESSAGE, NIF_TIP, NIM_ADD, NIM_DELETE, NOTIFYICONDATAW, Shell_NotifyIconW,
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

/// Show the right-button menu and act on what was chosen.
#[cfg(windows)]
fn show_menu(handle: windows::Win32::Foundation::HWND) {
    use windows::Win32::UI::WindowsAndMessaging::{
        AppendMenuW, CreatePopupMenu, DestroyMenu, GetCursorPos, MF_STRING, PostQuitMessage,
        SetForegroundWindow, TPM_BOTTOMALIGN, TPM_RETURNCMD, TrackPopupMenu,
    };
    use windows::core::w;

    let Ok(menu) = (unsafe { CreatePopupMenu() }) else {
        return;
    };

    unsafe {
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
