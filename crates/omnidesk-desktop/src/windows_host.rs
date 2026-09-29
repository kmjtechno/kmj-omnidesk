#![cfg(windows)]

use windows::{
    core::w,
    Win32::{
        Foundation::{HINSTANCE, HWND, LPARAM, LRESULT, WPARAM},
        UI::WindowsAndMessaging::{
            CreateWindowExW, DefWindowProcW, DispatchMessageW, GetMessageW, RegisterClassW,
            TranslateMessage, CW_USEDEFAULT, MSG, WINDOW_EX_STYLE, WINDOW_STYLE, WNDCLASSW,
            WS_OVERLAPPEDWINDOW, WS_VISIBLE,
        },
    },
};

unsafe extern "system" fn window_proc(
    window: HWND,
    message: u32,
    wparam: WPARAM,
    lparam: LPARAM,
) -> LRESULT {
    unsafe { DefWindowProcW(window, message, wparam, lparam) }
}

/// Creates the smallest native Windows host for the M7 desktop shell.
///
/// # Errors
///
/// Returns the underlying Windows error when class registration or window
/// creation fails.
pub fn run() -> windows::core::Result<()> {
    unsafe {
        let instance = HINSTANCE::default();
        let class_name = w!("KMJOmniDeskWindow");
        let class = WNDCLASSW {
            lpfnWndProc: Some(window_proc),
            hInstance: instance,
            lpszClassName: class_name,
            ..Default::default()
        };

        if RegisterClassW(&class) == 0 {
            return Err(windows::core::Error::from_win32());
        }

        CreateWindowExW(
            WINDOW_EX_STYLE::default(),
            class_name,
            w!("KMJ OmniDesk"),
            WINDOW_STYLE(WS_OVERLAPPEDWINDOW.0 | WS_VISIBLE.0),
            CW_USEDEFAULT,
            CW_USEDEFAULT,
            960,
            640,
            None,
            None,
            Some(instance.0 as _),
            None,
        )?;

        let mut message = MSG::default();
        while GetMessageW(&mut message, None, 0, 0).as_bool() {
            let _ = TranslateMessage(&message);
            DispatchMessageW(&message);
        }
    }
    Ok(())
}
