//! Local browser bridge for a `mattrs` manager's live inspector snapshots.

use std::io::{self, BufRead, BufReader, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::sync::{Arc, Condvar, Mutex, MutexGuard};
use std::time::Duration;

use clap::Parser;
use mattrs::inspector::ManagerSnapshot;
use serde::Serialize;

const INDEX_HTML: &str = include_str!("../web/index.html");
const APP_JS: &str = include_str!("../web/app.js");
const STYLE_CSS: &str = include_str!("../web/style.css");

#[derive(Parser, Debug)]
#[command(
    name = "mattrs-inspector",
    about = "Browser graph inspector for a live mattrs manager"
)]
struct Args {
    /// Manager inspector host to connect to.
    #[arg(long, default_value = "127.0.0.1")]
    host: String,
    /// Manager inspector TCP port to connect to.
    #[arg(long, default_value_t = 34443)]
    port: u16,
    /// Address on which to serve the browser interface.
    #[arg(long, default_value = "127.0.0.1:34444")]
    listen: SocketAddr,
}

#[derive(Clone, Serialize)]
struct BrowserState {
    connected: bool,
    snapshot: Option<ManagerSnapshot>,
}

struct VersionedState {
    browser: BrowserState,
    revision: u64,
}

struct SharedState {
    state: Mutex<VersionedState>,
    changed: Condvar,
}

impl SharedState {
    fn new() -> Self {
        Self {
            state: Mutex::new(VersionedState {
                browser: BrowserState {
                    connected: false,
                    snapshot: None,
                },
                revision: 0,
            }),
            changed: Condvar::new(),
        }
    }

    fn lock(&self) -> MutexGuard<'_, VersionedState> {
        self.state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    fn set_connected(&self, connected: bool) {
        let mut state = self.lock();
        if state.browser.connected != connected {
            state.browser.connected = connected;
            state.revision = state.revision.wrapping_add(1);
            self.changed.notify_all();
        }
    }

    fn set_snapshot(&self, snapshot: ManagerSnapshot) {
        let mut state = self.lock();
        state.browser.snapshot = Some(snapshot);
        state.revision = state.revision.wrapping_add(1);
        self.changed.notify_all();
    }
}

fn main() -> io::Result<()> {
    let args = Args::parse();
    let shared = Arc::new(SharedState::new());
    spawn_manager_reader(Arc::clone(&shared), args.host.clone(), args.port);

    let listener = TcpListener::bind(args.listen)?;
    println!("mattrs inspector: http://{}", listener.local_addr()?);
    println!("manager snapshots:  {}:{}", args.host, args.port);

    for stream in listener.incoming() {
        match stream {
            Ok(stream) => {
                let shared = Arc::clone(&shared);
                std::thread::spawn(move || {
                    let _ = handle_http(stream, &shared);
                });
            }
            Err(error) => eprintln!("inspector HTTP accept error: {error}"),
        }
    }
    Ok(())
}

fn spawn_manager_reader(shared: Arc<SharedState>, host: String, port: u16) {
    std::thread::spawn(move || loop {
        match TcpStream::connect((host.as_str(), port)) {
            Ok(stream) => {
                shared.set_connected(true);
                let reader = BufReader::new(stream);
                for line in reader.lines() {
                    let Ok(line) = line else {
                        break;
                    };
                    match serde_json::from_str::<ManagerSnapshot>(&line) {
                        Ok(snapshot) => shared.set_snapshot(snapshot),
                        Err(error) => eprintln!("invalid manager snapshot: {error}"),
                    }
                }
                shared.set_connected(false);
            }
            Err(_) => shared.set_connected(false),
        }
        std::thread::sleep(Duration::from_secs(2));
    });
}

fn handle_http(mut stream: TcpStream, shared: &SharedState) -> io::Result<()> {
    stream.set_read_timeout(Some(Duration::from_secs(5)))?;
    let request = read_request(&stream)?;
    let Some((method, target)) = request else {
        return Ok(());
    };
    let path = target.split('?').next().unwrap_or(target.as_str());

    if method != "GET" && method != "HEAD" {
        return write_response(
            &mut stream,
            "405 Method Not Allowed",
            "text/plain; charset=utf-8",
            b"method not allowed\n",
            method == "HEAD",
        );
    }

    match path {
        "/" | "/index.html" => write_response(
            &mut stream,
            "200 OK",
            "text/html; charset=utf-8",
            INDEX_HTML.as_bytes(),
            method == "HEAD",
        ),
        "/app.js" => write_response(
            &mut stream,
            "200 OK",
            "text/javascript; charset=utf-8",
            APP_JS.as_bytes(),
            method == "HEAD",
        ),
        "/style.css" => write_response(
            &mut stream,
            "200 OK",
            "text/css; charset=utf-8",
            STYLE_CSS.as_bytes(),
            method == "HEAD",
        ),
        "/api/state" => {
            let body = serde_json::to_vec(&shared.lock().browser).map_err(io::Error::other)?;
            write_response(
                &mut stream,
                "200 OK",
                "application/json; charset=utf-8",
                &body,
                method == "HEAD",
            )
        }
        "/api/events" if method == "GET" => write_event_stream(stream, shared),
        _ => write_response(
            &mut stream,
            "404 Not Found",
            "text/plain; charset=utf-8",
            b"not found\n",
            method == "HEAD",
        ),
    }
}

fn read_request(stream: &TcpStream) -> io::Result<Option<(String, String)>> {
    let mut reader = BufReader::new(stream);
    let mut first = String::new();
    if reader.read_line(&mut first)? == 0 {
        return Ok(None);
    }
    let mut parts = first.split_whitespace();
    let Some(method) = parts.next() else {
        return Ok(None);
    };
    let Some(target) = parts.next() else {
        return Ok(None);
    };

    let mut total = first.len();
    loop {
        let mut line = String::new();
        let read = reader.read_line(&mut line)?;
        total += read;
        if read == 0 || line == "\r\n" || line == "\n" {
            break;
        }
        if total > 32 * 1024 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "HTTP headers exceed 32 KiB",
            ));
        }
    }
    Ok(Some((method.to_string(), target.to_string())))
}

fn write_response(
    stream: &mut TcpStream,
    status: &str,
    content_type: &str,
    body: &[u8],
    head_only: bool,
) -> io::Result<()> {
    write!(
        stream,
        "HTTP/1.1 {status}\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\nCache-Control: no-store\r\nX-Content-Type-Options: nosniff\r\nConnection: close\r\n\r\n",
        body.len()
    )?;
    if !head_only {
        stream.write_all(body)?;
    }
    stream.flush()
}

fn write_event_stream(mut stream: TcpStream, shared: &SharedState) -> io::Result<()> {
    stream.set_write_timeout(Some(Duration::from_secs(10)))?;
    stream.write_all(
        b"HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nCache-Control: no-cache\r\nX-Accel-Buffering: no\r\nConnection: keep-alive\r\n\r\n",
    )?;

    let mut state = shared.lock();
    let mut revision = state.revision;
    write_sse_state(&mut stream, &state.browser)?;
    loop {
        let (next, timeout) = shared
            .changed
            .wait_timeout_while(state, Duration::from_secs(15), |candidate| {
                candidate.revision == revision
            })
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        state = next;
        if timeout.timed_out() {
            stream.write_all(b": keep-alive\n\n")?;
            stream.flush()?;
            continue;
        }
        revision = state.revision;
        write_sse_state(&mut stream, &state.browser)?;
    }
}

fn write_sse_state(stream: &mut TcpStream, state: &BrowserState) -> io::Result<()> {
    let json = serde_json::to_string(state).map_err(io::Error::other)?;
    write!(stream, "event: state\ndata: {json}\n\n")?;
    stream.flush()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn embedded_assets_are_present() {
        assert!(INDEX_HTML.contains("contract-canvas"));
        assert!(APP_JS.contains("EventSource"));
        assert!(STYLE_CSS.contains("detail-panel"));
    }

    #[test]
    fn state_revision_changes_only_for_connection_transitions() {
        let state = SharedState::new();
        assert_eq!(state.lock().revision, 0);
        state.set_connected(false);
        assert_eq!(state.lock().revision, 0);
        state.set_connected(true);
        assert_eq!(state.lock().revision, 1);
        state.set_connected(true);
        assert_eq!(state.lock().revision, 1);
    }
}
