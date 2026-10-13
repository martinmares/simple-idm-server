//! Binary SFTP relay. OpenSSH and all session credentials stay on the bastion.
use crate::{
    config::Host,
    server::{App, ServerMessage, TerminalQuery, control, send},
    ssh::Prepared,
};
use anyhow::{Result, ensure};
use axum::extract::ws::{Message, WebSocket};
use std::time::{Duration, Instant};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

#[allow(clippy::too_many_arguments)]
pub async fn run(
    app: &App,
    socket: &mut WebSocket,
    id: &str,
    query: &TerminalQuery,
    host: &Host,
    token: &str,
    started: &mut Option<Instant>,
) -> Result<(Option<i32>, &'static str)> {
    let prepared = Prepared::new(&app.config, host, id, token, &app.secret, &app.http).await?;
    app.audit.certificate(id, &prepared.certificate_id).await?;
    let mut child = prepared.spawn_files(&app.config, host, &query.login, query.sudo_readonly)?;
    let mut sent = 0u64;
    let mut received = 0u64;
    let result = async {
        let marker = prepared.marker();
        tokio::pin!(marker);
        let deadline = tokio::time::sleep(Duration::from_secs(30));
        tokio::pin!(deadline);
        let mut poll = tokio::time::interval(Duration::from_millis(100));
        loop {
            tokio::select! {
                marker = &mut marker => {
                    let stream = marker?;
                    app.audit.connected(id).await?;
                    *started = Some(Instant::now());
                    crate::ssh::release(stream).await?;
                    control(socket, ServerMessage::Ready { version: 1, session_id: id, sudo_readonly: query.sudo_readonly }).await?;
                    break;
                }
                _ = &mut deadline => anyhow::bail!("SFTP authentication timed out"),
                _ = poll.tick() => ensure!(child.try_wait()?.is_none(), "SFTP SSH process exited before ready"),
                message = socket.recv() => match message {
                    None | Some(Ok(Message::Close(_))) => return Ok((None, "client_disconnected")),
                    Some(Ok(Message::Ping(b))) => send(socket, Message::Pong(b)).await?,
                    Some(Ok(Message::Pong(_))) => {},
                    _ => anyhow::bail!("invalid SFTP setup message"),
                }
            }
        }
        let mut input = child.stdin.take().unwrap();
        let mut output = child.stdout.take().unwrap();
        let mut buffer = vec![0; 32768];
        let mut heartbeat = tokio::time::interval(Duration::from_secs(20));
        let mut last_seen = Instant::now();
        loop {
            tokio::select! {
                count = output.read(&mut buffer) => {
                    let count = count?;
                    if count == 0 {
                        let status = tokio::time::timeout(Duration::from_secs(5), child.wait()).await??;
                        return Ok((Some(status.code().unwrap_or(255)), "sftp_exit"));
                    }
                    send(socket, Message::Binary(buffer[..count].to_vec().into())).await?;
                    received = received.saturating_add(count as u64);
                }
                message = socket.recv() => {
                    last_seen = Instant::now();
                    match message {
                        None | Some(Ok(Message::Close(_))) | Some(Err(_)) => return Ok((None,"client_disconnected")),
                        Some(Ok(Message::Binary(bytes))) => {
                            tokio::time::timeout(Duration::from_secs(15), input.write_all(&bytes)).await??;
                            sent = sent.saturating_add(bytes.len() as u64);
                        }
                        Some(Ok(Message::Ping(bytes))) => send(socket, Message::Pong(bytes)).await?,
                        Some(Ok(Message::Pong(_))) => {},
                        _ => anyhow::bail!("unexpected SFTP control message"),
                    }
                }
                _ = heartbeat.tick() => {
                    ensure!(last_seen.elapsed() < Duration::from_secs(65), "SFTP keepalive lost");
                    send(socket, Message::Ping(Vec::new().into())).await?;
                }
            }
        }
    }.await;
    tracing::info!(
        session_id = id,
        sftp_bytes_to_target = sent,
        sftp_bytes_from_target = received,
        "SFTP relay closed"
    );
    let _ = child.start_kill();
    let _ = tokio::time::timeout(Duration::from_secs(5), child.wait()).await;
    result
}
