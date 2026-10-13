//! Shared local/remote file operations used by terminal and web frontends.
use crate::{bastion::label, protocol::Control};
use futures_util::{SinkExt, StreamExt};
pub(crate) use russh_sftp::client::SftpSession;
use russh_sftp::protocol::{FileType, OpenFlags};
use sha2::{Digest, Sha256};
use std::{
    ffi::OsString,
    io,
    path::PathBuf,
    sync::atomic::{AtomicBool, Ordering},
    time::{Duration, Instant},
};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio_tungstenite::tungstenite::{Message, client::IntoClientRequest};
use url::Url;
type Result<T> = std::result::Result<T, Box<dyn std::error::Error + Send + Sync>>;
pub(crate) type WorkResult<T> = std::result::Result<T, String>;
#[derive(Debug, Clone, serde::Serialize)]
pub(crate) struct Inspection {
    pub title: String,
    pub lines: Vec<String>,
}
pub(crate) struct Task(pub(crate) tokio::task::JoinHandle<()>);
impl Drop for Task {
    fn drop(&mut self) {
        self.0.abort();
    }
}

pub(crate) async fn connect(
    base: &Url,
    token: &str,
    host: &str,
    login: &str,
    sudo_readonly: bool,
) -> Result<(SftpSession, Task)> {
    let mut url = base.join("/api/v1/files")?;
    url.set_scheme(if base.scheme() == "https" {
        "wss"
    } else {
        "ws"
    })
    .map_err(|_| "Invalid WebSocket scheme")?;
    url.query_pairs_mut()
        .extend_pairs([("host_id", host), ("login", login)]);
    if sudo_readonly {
        url.query_pairs_mut().append_pair("sudo_readonly", "true");
    }
    let mut request = url.as_str().into_client_request()?;
    request
        .headers_mut()
        .insert("Authorization", format!("Bearer {token}").parse()?);
    let setup = async {
        let (mut socket, _) = tokio_tungstenite::connect_async(request).await?;
        loop {
            match socket
                .next()
                .await
                .ok_or("Bastion disconnected before ready")??
            {
                Message::Text(text) => match serde_json::from_str::<Control>(&text)? {
                    Control::Ready {
                        version: 1,
                        session_id,
                    } if !session_id.is_empty() => {
                        let reported = serde_json::from_str::<serde_json::Value>(&text)?
                            .get("sudo_readonly")
                            .and_then(|v| v.as_bool())
                            .unwrap_or(false);
                        if reported != sudo_readonly {
                            return Err("Bastion did not confirm the requested file mode; upgrade the daemon".into());
                        }
                        break;
                    }
                    Control::Error { message } => return Err(label(&message).into()),
                    _ => return Err("Invalid SFTP ready message".into()),
                },
                Message::Ping(b) => socket.send(Message::Pong(b)).await?,
                Message::Pong(_) => {}
                _ => return Err("Unexpected SFTP setup data".into()),
            }
        }
        Ok::<_, Box<dyn std::error::Error + Send + Sync>>(socket)
    };
    let mut socket = tokio::time::timeout(Duration::from_secs(45), setup).await??;
    let (stream, bridge) = tokio::io::duplex(131072);
    let (mut reader, mut writer) = tokio::io::split(bridge);
    let task = Task(tokio::spawn(async move {
        let mut buffer = vec![0; 32768];
        loop {
            tokio::select! {
                count = reader.read(&mut buffer) => match count {
                    Ok(0) | Err(_) => break,
                    Ok(n) => if !matches!(tokio::time::timeout(Duration::from_secs(15), socket.send(Message::Binary(buffer[..n].to_vec().into()))).await, Ok(Ok(()))) { break; },
                },
                message = socket.next() => match message {
                    Some(Ok(Message::Binary(bytes))) => if !matches!(tokio::time::timeout(Duration::from_secs(15),writer.write_all(&bytes)).await, Ok(Ok(()))) { break; },
                    Some(Ok(Message::Ping(b))) => if socket.send(Message::Pong(b)).await.is_err() { break; },
                    Some(Ok(Message::Pong(_))) => {},
                    _ => break,
                }
            }
        }
        let _ = tokio::time::timeout(Duration::from_secs(2), socket.close(None)).await;
    }));
    let sftp = SftpSession::new(stream).await.map_err(|e| {
        if sudo_readonly {
            format!(
                "Root read-only SFTP failed: check sudoers NOPASSWD rule and sftp-server path ({e})"
            )
        } else {
            e.to_string()
        }
    })?;
    Ok((sftp, task))
}

#[derive(Clone, Debug, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
#[serde(tag = "side", content = "path", rename_all = "lowercase")]
pub(crate) enum Location {
    Local(PathBuf),
    Remote(String),
}
impl Location {
    pub(crate) fn display(&self) -> String {
        label(&match self {
            Self::Local(p) => p.to_string_lossy().into_owned(),
            Self::Remote(p) => p.clone(),
        })
    }
    pub(crate) fn child(&self, name: &OsString) -> Self {
        match self {
            Self::Local(p) => Self::Local(p.join(name)),
            Self::Remote(p) => Self::Remote(format!(
                "{}/{}",
                p.trim_end_matches('/'),
                name.to_string_lossy()
            )),
        }
    }
    pub(crate) fn name(&self) -> Option<OsString> {
        match self {
            Self::Local(path) => path.file_name().map(OsString::from),
            Self::Remote(path) => path
                .trim_end_matches('/')
                .rsplit('/')
                .next()
                .filter(|name| !name.is_empty())
                .map(OsString::from),
        }
    }
    pub(crate) fn parent(&self) -> Self {
        match self {
            Self::Local(p) => Self::Local(p.parent().unwrap_or(p).to_path_buf()),
            Self::Remote(p) => Self::Remote(
                p.rsplit_once('/')
                    .map(|(parent, _)| if parent.is_empty() { "/" } else { parent })
                    .unwrap_or("/")
                    .into(),
            ),
        }
    }
}
#[derive(Clone)]
pub(crate) struct Entry {
    pub(crate) name: OsString,
    pub(crate) kind: FileType,
    pub(crate) size: u64,
}
impl Entry {
    pub(crate) fn display(&self) -> String {
        let mut s = label(&self.name.to_string_lossy());
        if self.kind.is_dir() {
            s.push('/');
        } else if self.kind.is_symlink() {
            s.push_str(" →");
        }
        s
    }
}
#[derive(Clone, Copy)]
pub(crate) enum InspectKind {
    Hash,
    Preview,
}
pub(crate) fn error(e: impl std::fmt::Display) -> String {
    e.to_string()
}
pub(crate) fn valid_name(name: &str) -> bool {
    !name.is_empty()
        && name != "."
        && name != ".."
        && !name.contains(['/', '\\', '\0'])
        && !name.chars().any(char::is_control)
}

pub(crate) async fn list(sftp: &SftpSession, path: &Location) -> WorkResult<Vec<Entry>> {
    let mut entries = vec![Entry {
        name: "..".into(),
        kind: FileType::Dir,
        size: 0,
    }];
    match path {
        Location::Local(p) => {
            let mut dir = tokio::fs::read_dir(p).await.map_err(error)?;
            while let Some(e) = dir.next_entry().await.map_err(error)? {
                let m = tokio::fs::symlink_metadata(e.path()).await.map_err(error)?;
                entries.push(Entry {
                    name: e.file_name(),
                    kind: if m.is_dir() {
                        FileType::Dir
                    } else if m.is_file() {
                        FileType::File
                    } else if m.is_symlink() {
                        FileType::Symlink
                    } else {
                        FileType::Other
                    },
                    size: m.len(),
                });
            }
        }
        Location::Remote(p) => {
            for e in sftp.read_dir(p.clone()).await.map_err(error)? {
                let name = e.file_name();
                if name.contains('/') || name.contains('\0') {
                    return Err("Server returned an invalid filename".into());
                }
                entries.push(Entry {
                    name: name.into(),
                    kind: e.file_type(),
                    size: e.metadata().size.unwrap_or(0),
                });
            }
        }
    }
    entries[1..].sort_by(|a, b| {
        (!a.kind.is_dir(), a.name.to_string_lossy().to_lowercase())
            .cmp(&(!b.kind.is_dir(), b.name.to_string_lossy().to_lowercase()))
    });
    Ok(entries)
}
pub(crate) async fn exists(sftp: &SftpSession, path: &Location) -> WorkResult<bool> {
    match path {
        Location::Local(p) => match tokio::fs::symlink_metadata(p).await {
            Ok(_) => Ok(true),
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(false),
            Err(e) => Err(error(e)),
        },
        Location::Remote(p) => match sftp.symlink_metadata(p.clone()).await {
            Ok(_) => Ok(true),
            Err(russh_sftp::client::error::Error::Status(s))
                if s.status_code == russh_sftp::protocol::StatusCode::NoSuchFile =>
            {
                Ok(false)
            }
            Err(e) => Err(error(e)),
        },
    }
}
pub(crate) async fn rename(
    sftp: &SftpSession,
    source: &Location,
    dest: &Location,
) -> WorkResult<()> {
    match (source, dest) {
        (Location::Local(a), Location::Local(b)) => tokio::fs::rename(a, b).await.map_err(error),
        (Location::Remote(a), Location::Remote(b)) => {
            sftp.rename(a.clone(), b.clone()).await.map_err(error)
        }
        _ => Err("Cross-panel move is not supported; use copy".into()),
    }
}
pub(crate) async fn remove(sftp: &SftpSession, path: &Location, directory: bool) -> WorkResult<()> {
    match path {
        Location::Local(p) => {
            if directory {
                tokio::fs::remove_dir(p).await.map_err(error)
            } else {
                tokio::fs::remove_file(p).await.map_err(error)
            }
        }
        Location::Remote(p) => {
            if directory {
                sftp.remove_dir(p.clone()).await.map_err(error)
            } else {
                sftp.remove_file(p.clone()).await.map_err(error)
            }
        }
    }
}

pub(crate) async fn open_regular(
    sftp: &SftpSession,
    source: &Location,
) -> WorkResult<(Box<dyn AsyncRead + Unpin + Send>, u64)> {
    match source {
        Location::Local(p) => {
            let m = tokio::fs::symlink_metadata(p).await.map_err(error)?;
            if !m.is_file() {
                return Err("This operation supports regular files only".into());
            }
            Ok((
                Box::new(tokio::fs::File::open(p).await.map_err(error)?),
                m.len(),
            ))
        }
        Location::Remote(p) => {
            let m = sftp.symlink_metadata(p.clone()).await.map_err(error)?;
            if !m.file_type().is_file() {
                return Err("This operation supports regular files only".into());
            }
            Ok((
                Box::new(sftp.open(p.clone()).await.map_err(error)?),
                m.size.unwrap_or(0),
            ))
        }
    }
}

pub(crate) const PREVIEW_LIMIT: usize = 64 * 1024;
pub(crate) fn preview_lines(bytes: &[u8], truncated: bool) -> (String, Vec<String>) {
    let text = match std::str::from_utf8(bytes) {
        Ok(text) => Some(text),
        Err(e) if truncated && e.error_len().is_none() => {
            std::str::from_utf8(&bytes[..e.valid_up_to()]).ok()
        }
        _ => None,
    }
    .filter(|text| {
        text.chars()
            .all(|c| !c.is_control() || matches!(c, '\n' | '\r' | '\t'))
    });
    let (kind, mut lines) = if let Some(text) = text {
        (
            "Text".to_string(),
            text.replace("\r\n", "\n")
                .replace('\r', "\\r")
                .replace('\t', "    ")
                .split('\n')
                .map(str::to_owned)
                .collect::<Vec<_>>(),
        )
    } else {
        (
            "Hex".to_string(),
            bytes
                .chunks(16)
                .enumerate()
                .map(|(i, chunk)| {
                    let hex = chunk
                        .iter()
                        .map(|b| format!("{b:02x} "))
                        .collect::<String>();
                    let ascii = chunk
                        .iter()
                        .map(|b| {
                            if b.is_ascii_graphic() || *b == b' ' {
                                *b as char
                            } else {
                                '.'
                            }
                        })
                        .collect::<String>();
                    format!("{:08x}  {:48} |{}|", i * 16, hex, ascii)
                })
                .collect::<Vec<_>>(),
        )
    };
    if truncated {
        lines.push(format!(
            "[Preview limited to the first {} KiB]",
            PREVIEW_LIMIT / 1024
        ));
    }
    (kind, lines)
}
pub(crate) async fn inspect(
    sftp: &SftpSession,
    path: &Location,
    kind: InspectKind,
    cancel: &AtomicBool,
    progress: &(dyn Fn(u64, u64) + Send + Sync),
) -> WorkResult<Inspection> {
    let (mut reader, total) = open_regular(sftp, path).await?;
    let reading = async {
        let mut bytes = Vec::new();
        let mut digest = Sha256::new();
        let mut buffer = [0; 32768];
        let mut done = 0u64;
        let mut last = Instant::now();
        progress(0, total);
        loop {
            if cancel.load(Ordering::Relaxed) {
                return Err("Operation cancelled".into());
            }
            let limit = if matches!(kind, InspectKind::Preview) {
                (PREVIEW_LIMIT + 1 - bytes.len()).min(buffer.len())
            } else {
                buffer.len()
            };
            let count = reader.read(&mut buffer[..limit]).await.map_err(error)?;
            if count == 0 {
                break;
            }
            done += count as u64;
            match kind {
                InspectKind::Hash => digest.update(&buffer[..count]),
                InspectKind::Preview => bytes.extend_from_slice(&buffer[..count]),
            }
            if last.elapsed() >= Duration::from_millis(100) {
                progress(done, total);
                last = Instant::now();
            }
            if matches!(kind, InspectKind::Preview) && bytes.len() > PREVIEW_LIMIT {
                break;
            }
        }
        progress(done, total);
        let (title, lines) = match kind {
            InspectKind::Hash => (
                "SHA-256".to_string(),
                vec![
                    path.display(),
                    String::new(),
                    format!("{:x}", digest.finalize()),
                    String::new(),
                    format!("Read {} bytes", done),
                ],
            ),
            InspectKind::Preview => {
                let truncated = bytes.len() > PREVIEW_LIMIT;
                bytes.truncate(PREVIEW_LIMIT);
                preview_lines(&bytes, truncated)
            }
        };
        Ok(Inspection {
            title: format!("{} · {}", title, path.display()),
            lines,
        })
    };
    tokio::select! {
        result = reading => result,
        _ = async { while !cancel.load(Ordering::Relaxed) { tokio::time::sleep(Duration::from_millis(50)).await; } } => Err("Operation cancelled".into()),
    }
}

pub(crate) async fn copy(
    sftp: &SftpSession,
    source: &Location,
    dest: &Location,
    overwrite: bool,
    cancel: &AtomicBool,
    progress: &(dyn Fn(u64, u64) + Send + Sync),
) -> WorkResult<()> {
    let (mut input, total) = open_regular(sftp, source).await?;
    progress(0, total);
    let temp = dest
        .parent()
        .child(&format!(".simple-idm-{}.part", uuid::Uuid::new_v4()).into());
    let mut output: Box<dyn AsyncWrite + Unpin + Send> = match &temp {
        Location::Local(p) => Box::new(
            tokio::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(p)
                .await
                .map_err(error)?,
        ),
        Location::Remote(p) => Box::new(
            sftp.open_with_flags(
                p.clone(),
                OpenFlags::WRITE | OpenFlags::CREATE | OpenFlags::EXCLUDE,
            )
            .await
            .map_err(error)?,
        ),
    };
    let result = async {
        let mut done = 0;
        let streaming = async {
        let mut buffer = vec![0; 32768];
        let mut last = Instant::now();
        loop {
            if cancel.load(Ordering::Relaxed) {
                return Err("Transfer cancelled".into());
            }
            let count = input.read(&mut buffer).await.map_err(error)?;
            if count == 0 {
                break;
            }
            output.write_all(&buffer[..count]).await.map_err(error)?;
            done += count as u64;
            if last.elapsed() >= Duration::from_millis(100) {
                progress(done, total);
                last = Instant::now();
            }
        }
        Ok::<(), String>(())
        };
        tokio::select! {
            result = streaming => result?,
            _ = async { while !cancel.load(Ordering::Relaxed) { tokio::time::sleep(Duration::from_millis(50)).await; } } => return Err("Transfer cancelled".into()),
        }
        output.flush().await.map_err(error)?;
        output.shutdown().await.map_err(error)?;
        if cancel.load(Ordering::Relaxed) {
            return Err("Transfer cancelled".into());
        }
        if exists(sftp, dest).await? {
            if !overwrite {
                return Err("Destination appeared during transfer; original was preserved".into());
            }
            let regular = match dest {
                Location::Local(p) => tokio::fs::symlink_metadata(p).await.map_err(error)?.is_file(),
                Location::Remote(p) => sftp.symlink_metadata(p.clone()).await.map_err(error)?.file_type().is_file(),
            };
            if !regular { return Err("Overwrite supports regular files only; destination preserved".into()); }
            // SFTP v3 rename cannot replace an existing file. Keep a recoverable
            // backup until publishing succeeds; never unlink the original first.
            let backup = dest
                .parent()
                .child(&format!(".simple-idm-{}.backup", uuid::Uuid::new_v4()).into());
            rename(sftp, dest, &backup).await?;
            if let Err(e) = rename(sftp, &temp, dest).await {
                if let Err(restore) = rename(sftp, &backup, dest).await {
                    return Err(format!(
                        "{e}; restore failed: {restore}. Original remains at {}",
                        backup.display()
                    ));
                }
                return Err(e);
            }
            remove(sftp, &backup, false).await.map_err(|e| {
                format!(
                    "Copy completed; backup retained at {}: {e}",
                    backup.display()
                )
            })?;
        } else {
            if let (Location::Local(temp_path), Location::Local(dest_path)) = (&temp, dest) {
                tokio::fs::hard_link(temp_path, dest_path).await.map_err(error)?;
                tokio::fs::remove_file(temp_path).await.map_err(error)?;
            } else { rename(sftp, &temp, dest).await?; }
        }
        progress(done, total);
        Ok(())
    }
    .await;
    drop(output);
    if result.is_err() {
        let _ = remove(sftp, &temp, false).await;
    }
    result
}
