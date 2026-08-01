use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use rand::{distr::Alphanumeric, Rng};
use serde_json::json;
use sha2::{Digest, Sha256};
use std::{
    io::{Read, Write},
    net::TcpListener,
    sync::atomic::{AtomicBool, Ordering},
    time::{Duration, Instant},
};
use tauri::{webview::NewWindowResponse, WebviewUrl, WebviewWindowBuilder};
use tauri_plugin_opener::OpenerExt;

const APP_ORIGIN: &str = "https://ilegallearn.com";
const OAUTH_BRIDGE_SCHEME: &str = "ilegallearn-desktop";
const OAUTH_TIMEOUT: Duration = Duration::from_secs(300);
static OAUTH_IN_PROGRESS: AtomicBool = AtomicBool::new(false);

fn is_internal_url(url: &tauri::Url) -> bool {
    url.scheme() == "https" && url.host_str() == Some("ilegallearn.com")
}

fn is_system_url(url: &tauri::Url) -> bool {
    matches!(url.scheme(), "http" | "https" | "mailto" | "tel")
}

fn is_razorpay_embedded_url(url: &tauri::Url) -> bool {
    url.scheme() == "https"
        && matches!(
            url.host_str(),
            Some("api.razorpay.com" | "checkout.razorpay.com")
        )
}

fn desktop_oauth_client_id(url: &tauri::Url) -> Option<String> {
    if url.scheme() != OAUTH_BRIDGE_SCHEME
        || url.host_str() != Some("oauth")
        || url.path() != "/start"
    {
        return None;
    }

    url.query_pairs()
        .find(|(key, _)| key == "client_id")
        .map(|(_, value)| value.into_owned())
        .filter(|value| value.ends_with(".apps.googleusercontent.com"))
}

fn send_oauth_result(app: &tauri::AppHandle, detail: serde_json::Value) {
    use tauri::Manager;

    let Some(window) = app.get_webview_window("main") else {
        eprintln!("Cannot deliver Google OAuth result: main window was not found");
        return;
    };

    let script = format!(
        "window.dispatchEvent(new CustomEvent('ilegallearn:google-oauth-result', {{ detail: {} }}));",
        detail
    );
    if let Err(error) = window.eval(script) {
        eprintln!("Failed to deliver Google OAuth result to the webview: {error}");
    }
    let _ = window.unminimize();
    let _ = window.show();
    let _ = window.set_focus();
}

fn oauth_error(app: &tauri::AppHandle, message: impl Into<String>) {
    send_oauth_result(app, json!({ "error": message.into() }));
}

fn random_token(length: usize) -> String {
    rand::rng()
        .sample_iter(&Alphanumeric)
        .take(length)
        .map(char::from)
        .collect()
}

fn callback_value(callback_url: &tauri::Url, key: &str) -> Option<String> {
    callback_url
        .query_pairs()
        .find(|(candidate, _)| candidate == key)
        .map(|(_, value)| value.into_owned())
}

fn write_callback_page(mut stream: &std::net::TcpStream, successful: bool) {
    let heading = if successful {
        "Sign-in complete"
    } else {
        "Sign-in could not be completed"
    };
    let message = if successful {
        "You can close this tab and return to iLegalLearn."
    } else {
        "Return to iLegalLearn and try again."
    };
    let body = format!(
        "<!doctype html><html><head><meta charset=\"utf-8\"><title>{heading}</title></head><body><h1>{heading}</h1><p>{message}</p></body></html>"
    );
    let response = format!(
        "HTTP/1.1 200 OK\r\nContent-Type: text/html; charset=utf-8\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
        body.len(),
        body
    );
    let _ = stream.write_all(response.as_bytes());
}

fn run_google_oauth(app: tauri::AppHandle, client_id: String) {
    if OAUTH_IN_PROGRESS.swap(true, Ordering::SeqCst) {
        oauth_error(&app, "A Google sign-in is already in progress.");
        return;
    }

    std::thread::spawn(move || {
        let result = (|| -> Result<(), String> {
            let listener = TcpListener::bind("127.0.0.1:0")
                .map_err(|error| format!("Could not start the OAuth callback listener: {error}"))?;
            listener.set_nonblocking(true).map_err(|error| {
                format!("Could not configure the OAuth callback listener: {error}")
            })?;
            let port = listener
                .local_addr()
                .map_err(|error| format!("Could not read the OAuth callback address: {error}"))?
                .port();
            let redirect_uri = format!("http://127.0.0.1:{port}/oauth2callback");
            let state = random_token(48);
            let code_verifier = random_token(96);
            let code_challenge = URL_SAFE_NO_PAD.encode(Sha256::digest(code_verifier.as_bytes()));

            let mut authorization_url =
                tauri::Url::parse("https://accounts.google.com/o/oauth2/v2/auth").map_err(
                    |error| format!("Could not construct the Google authorization URL: {error}"),
                )?;
            authorization_url
                .query_pairs_mut()
                .append_pair("client_id", &client_id)
                .append_pair("redirect_uri", &redirect_uri)
                .append_pair("response_type", "code")
                .append_pair("scope", "openid email profile")
                .append_pair("state", &state)
                .append_pair("code_challenge", &code_challenge)
                .append_pair("code_challenge_method", "S256")
                .append_pair("access_type", "online")
                .append_pair("prompt", "select_account");

            app.opener()
                .open_url(authorization_url.to_string(), None::<&str>)
                .map_err(|error| {
                    format!("Could not open Google sign-in in the browser: {error}")
                })?;

            let started_at = Instant::now();
            while started_at.elapsed() < OAUTH_TIMEOUT {
                match listener.accept() {
                    Ok((mut stream, _address)) => {
                        let mut request = [0_u8; 16_384];
                        let bytes_read = stream.read(&mut request).map_err(|error| {
                            format!("Could not read the OAuth callback: {error}")
                        })?;
                        let request = String::from_utf8_lossy(&request[..bytes_read]);
                        let request_target = request
                            .lines()
                            .next()
                            .and_then(|line| line.split_whitespace().nth(1))
                            .ok_or_else(|| {
                                "The OAuth callback request was malformed.".to_string()
                            })?;
                        let callback_url =
                            tauri::Url::parse(&format!("http://127.0.0.1:{port}{request_target}"))
                                .map_err(|error| {
                                    format!("The OAuth callback URL was invalid: {error}")
                                })?;

                        if callback_url.path() != "/oauth2callback" {
                            write_callback_page(&stream, false);
                            continue;
                        }

                        if callback_value(&callback_url, "state").as_deref() != Some(state.as_str())
                        {
                            write_callback_page(&stream, false);
                            return Err(
                                "Google sign-in returned an invalid state value.".to_string()
                            );
                        }

                        if let Some(error) = callback_value(&callback_url, "error") {
                            write_callback_page(&stream, false);
                            return Err(format!("Google sign-in was not completed: {error}"));
                        }

                        let code = callback_value(&callback_url, "code").ok_or_else(|| {
                            "Google did not return an authorization code.".to_string()
                        })?;
                        write_callback_page(&stream, true);
                        send_oauth_result(
                            &app,
                            json!({
                                "code": code,
                                "codeVerifier": code_verifier,
                                "redirectUri": redirect_uri
                            }),
                        );
                        return Ok(());
                    }
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                        std::thread::sleep(Duration::from_millis(100));
                    }
                    Err(error) => {
                        return Err(format!("The OAuth callback listener failed: {error}"));
                    }
                }
            }

            Err("Google sign-in timed out. Please try again.".to_string())
        })();

        if let Err(error) = result {
            oauth_error(&app, error);
        }
        OAUTH_IN_PROGRESS.store(false, Ordering::SeqCst);
    });
}

fn open_with_system(app: tauri::AppHandle, url: tauri::Url) {
    if !is_system_url(&url) {
        eprintln!("Blocked unsupported external URL scheme: {url}");
        return;
    }

    std::thread::spawn(move || {
        if let Err(error) = app.opener().open_url(url.to_string(), None::<&str>) {
            eprintln!("Failed to open URL with the system handler: {error}");
        }
    });
}

#[tauri::command]
async fn save_pdf_download(
    app: tauri::AppHandle,
    file_name: String,
    base64_data: String,
) -> Result<String, String> {
    use base64::engine::general_purpose::STANDARD;

    eprintln!(
        "PDF bridge invoked for {file_name} ({} encoded bytes)",
        base64_data.len()
    );

    const MAX_ENCODED_PDF_SIZE: usize = 70 * 1024 * 1024;
    if base64_data.len() > MAX_ENCODED_PDF_SIZE {
        return Err("The PDF is too large to save.".to_string());
    }

    let requested_name = std::path::Path::new(&file_name)
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("iLegalLearn.pdf");
    let mut safe_name: String = requested_name
        .chars()
        .map(|character| {
            if matches!(
                character,
                '<' | '>' | ':' | '"' | '/' | '\\' | '|' | '?' | '*'
            ) {
                '_'
            } else {
                character
            }
        })
        .take(180)
        .collect();
    if !safe_name.to_ascii_lowercase().ends_with(".pdf") {
        safe_name.push_str(".pdf");
    }

    let bytes = STANDARD
        .decode(base64_data)
        .map_err(|error| format!("The PDF data was invalid: {error}"))?;
    if !bytes.starts_with(b"%PDF-") {
        return Err("The downloaded file was not a valid PDF.".to_string());
    }

    use tauri::Manager;
    let downloads = app
        .path()
        .download_dir()
        .map_err(|error| format!("Could not locate the Downloads folder: {error}"))?;
    let requested_path = std::path::Path::new(&safe_name);
    let stem = requested_path
        .file_stem()
        .and_then(|value| value.to_str())
        .unwrap_or("iLegalLearn");
    let mut destination = downloads.join(&safe_name);
    let mut copy_number = 1_u32;
    while destination.exists() {
        destination = downloads.join(format!("{stem} ({copy_number}).pdf"));
        copy_number += 1;
    }
    std::fs::write(&destination, bytes)
        .map_err(|error| format!("Could not save the PDF: {error}"))?;
    Ok(destination
        .file_name()
        .and_then(|value| value.to_str())
        .unwrap_or("iLegalLearn.pdf")
        .to_string())
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .plugin(tauri_plugin_opener::init())
        .invoke_handler(tauri::generate_handler![save_pdf_download])
        .setup(|app| {
            let navigation_app = app.handle().clone();
            let new_window_app = app.handle().clone();

            WebviewWindowBuilder::new(
                app,
                "main",
                WebviewUrl::External(APP_ORIGIN.parse().expect("valid app URL")),
            )
            .initialization_script(
                r#"
                  Object.defineProperty(window, '__ILEGALLEARN_DESKTOP__', { value: true, configurable: false });
                  console.info('[iLegalLearn Desktop] PDF save bridge installed');

                  const showDownloadToast = (message, isError = false) => {
                    document.getElementById('ilegallearn-desktop-download-toast')?.remove();
                    const toast = document.createElement('div');
                    toast.id = 'ilegallearn-desktop-download-toast';
                    toast.setAttribute('role', isError ? 'alert' : 'status');
                    toast.setAttribute('aria-live', 'polite');
                    toast.textContent = message;
                    Object.assign(toast.style, {
                      position: 'fixed', top: '24px', right: '24px', zIndex: '2147483647',
                      maxWidth: '420px', padding: '14px 18px', borderRadius: '10px',
                      color: '#fff', background: isError ? '#b91c1c' : '#166534',
                      boxShadow: '0 10px 30px rgba(0,0,0,.25)', fontFamily: 'system-ui, sans-serif',
                      fontSize: '14px', fontWeight: '600', lineHeight: '1.4'
                    });
                    document.body.appendChild(toast);
                    setTimeout(() => toast.remove(), 5000);
                  };
                  Object.defineProperty(window, '__ILEGALLEARN_SHOW_DOWNLOAD_TOAST__', {
                    value: showDownloadToast,
                    configurable: false,
                  });

                  const savingPdfAnchors = new WeakSet();
                  const savePdfAnchor = (anchor) => {
                    if (!(anchor instanceof HTMLAnchorElement)
                      || !anchor.href.startsWith('blob:')
                      || savingPdfAnchors.has(anchor)) return false;
                    const fileName = anchor.getAttribute('download') || 'iLegalLearn.pdf';
                    if (!fileName.toLowerCase().endsWith('.pdf')) return false;
                    savingPdfAnchors.add(anchor);
                    console.info('[iLegalLearn Desktop] Captured PDF download', fileName);

                    void (async () => {
                      try {
                        const response = await fetch(anchor.href);
                        const bytes = new Uint8Array(await response.arrayBuffer());
                        let binary = '';
                        for (let offset = 0; offset < bytes.length; offset += 0x8000) {
                          binary += String.fromCharCode(...bytes.subarray(offset, offset + 0x8000));
                        }
                        const invoke = window.__TAURI__?.core?.invoke || window.__TAURI_INTERNALS__?.invoke;
                        if (typeof invoke !== 'function') throw new Error('Desktop save bridge is unavailable.');
                        const savedFileName = await invoke('save_pdf_download', { fileName, base64Data: btoa(binary) });
                        showDownloadToast(`PDF downloaded — ${savedFileName}`);
                      } catch (error) {
                        console.error('Could not save PDF:', error);
                        showDownloadToast(error?.message || 'Could not save the PDF.', true);
                        alert(error?.message || 'Could not save the PDF. Please try again.');
                      } finally {
                        savingPdfAnchors.delete(anchor);
                      }
                    })();
                    return true;
                  };

                  Object.defineProperty(window, 'saveAs', {
                    configurable: false,
                    value: (blob, fileName = 'iLegalLearn.pdf') => {
                      if (!(blob instanceof Blob) || !String(fileName).toLowerCase().endsWith('.pdf')) {
                        throw new Error('Only PDF downloads are supported by the desktop save bridge.');
                      }
                      const anchor = document.createElement('a');
                      anchor.href = URL.createObjectURL(blob);
                      anchor.download = fileName;
                      savePdfAnchor(anchor);
                      setTimeout(() => URL.revokeObjectURL(anchor.href), 40_000);
                    },
                  });

                  const nativeDispatchEvent = HTMLAnchorElement.prototype.dispatchEvent;
                  HTMLAnchorElement.prototype.dispatchEvent = function (event) {
                    if (event?.type === 'click' && savePdfAnchor(this)) return true;
                    return nativeDispatchEvent.call(this, event);
                  };

                  const nativeClick = HTMLAnchorElement.prototype.click;
                  HTMLAnchorElement.prototype.click = function () {
                    if (savePdfAnchor(this)) return;
                    return nativeClick.call(this);
                  };

                  document.addEventListener('click', (event) => {
                    const anchor = event.target instanceof Element
                      ? event.target.closest('a[download]')
                      : null;
                    if (anchor && savePdfAnchor(anchor)) {
                      event.preventDefault();
                      event.stopImmediatePropagation();
                    }
                  }, true);
                "#,
            )
            .title("iLegalLearn")
            .inner_size(1280.0, 800.0)
            .min_inner_size(1000.0, 700.0)
            .on_download(|_webview, event| {
                match event {
                    tauri::webview::DownloadEvent::Requested { url, destination } => {
                        eprintln!("WebView download requested: {url} -> {destination:?}");
                    }
                    tauri::webview::DownloadEvent::Finished { url, path, success } => {
                        eprintln!("WebView download finished: {url} -> {path:?}, success={success}");
                    }
                    _ => {}
                }
                true
            })
            .on_page_load(|window, payload| {
                if payload.event() != tauri::webview::PageLoadEvent::Finished
                    || payload.url().scheme() != "https"
                    || payload.url().host_str() != Some("ilegallearn.com")
                {
                    return;
                }

                let _ = window.eval(
                    r#"
                    if (!window.__ILEGALLEARN_PDF_BRIDGE_READY__) {
                      Object.defineProperty(window, '__ILEGALLEARN_PDF_BRIDGE_READY__', { value: true });
                      const originalDispatchEvent = HTMLAnchorElement.prototype.dispatchEvent;
                      HTMLAnchorElement.prototype.dispatchEvent = function (event) {
                        const fileName = this.getAttribute('download') || '';
                        if (event?.type === 'click'
                          && this.href.startsWith('blob:')
                          && fileName.toLowerCase().endsWith('.pdf')) {
                          void (async () => {
                            try {
                              const blob = await fetch(this.href).then(response => response.blob());
                              const bytes = new Uint8Array(await blob.arrayBuffer());
                              let binary = '';
                              for (let offset = 0; offset < bytes.length; offset += 0x8000) {
                                binary += String.fromCharCode(...bytes.subarray(offset, offset + 0x8000));
                              }
                              const invoke = window.__TAURI__?.core?.invoke || window.__TAURI_INTERNALS__?.invoke;
                              if (typeof invoke !== 'function') throw new Error('Desktop IPC is unavailable.');
                              const savedFileName = await invoke('save_pdf_download', { fileName, base64Data: btoa(binary) });
                              window.__ILEGALLEARN_SHOW_DOWNLOAD_TOAST__?.(`PDF downloaded — ${savedFileName}`);
                            } catch (error) {
                              console.error('[iLegalLearn Desktop] PDF save failed:', error);
                              window.__ILEGALLEARN_SHOW_DOWNLOAD_TOAST__?.(error?.message || 'Could not save the PDF.', true);
                              alert(error?.message || 'Could not save the PDF. Please try again.');
                            }
                          })();
                          return true;
                        }
                        return originalDispatchEvent.call(this, event);
                      };
                      console.info('[iLegalLearn Desktop] Post-load PDF bridge installed');
                    }
                    "#,
                );
            })
            .on_navigation(move |url| {
                if is_internal_url(url) {
                    true
                } else if let Some(client_id) = desktop_oauth_client_id(url) {
                    run_google_oauth(navigation_app.clone(), client_id);
                    false
                } else {
                    open_with_system(navigation_app.clone(), url.clone());
                    false
                }
            })
            .on_new_window(move |url, _features| {
                if is_razorpay_embedded_url(&url) {
                    eprintln!("Ignored Razorpay embedded new-window request: {url}");
                } else {
                    open_with_system(new_window_app.clone(), url);
                }
                NewWindowResponse::Deny
            })
            .build()?;

            Ok(())
        })
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
