//! Local port forwarding: a loopback listener per forward, each accepted
//! socket pumped through its own `direct-tcpip` channel on the bound
//! session. The backend owns every listener; the page asks for a handle and
//! never sees a socket or an address it made up.
//!
//! Destinations are confined by core to loopback or to address:port pairs
//! the target itself reported as listeners — the LISTEN table is read at
//! plan time through the fixed core command, so a page cannot turn this
//! into an arbitrary network pivot. Forwards are never persisted and die
//! with the binding.

use std::{
    collections::HashMap,
    fmt,
    net::Ipv4Addr,
    sync::{
        Arc, Mutex, MutexGuard,
        atomic::{AtomicU32, AtomicU64, Ordering},
    },
    time::Duration,
};

use chrono::Utc;
use lovelyhawk_core::{
    CoreError,
    operations::{JournalPhase, OperationJournal, OperationJournalEntry},
    port_forward::{
        ForwardDestination, LISTEN_TABLE_COMMAND, MAX_FORWARD_CONNECTIONS,
        MAX_FORWARDS_PER_BINDING, destination_allowed, parse_destination_host, parse_listen_table,
        validate_destination_port, validate_local_port,
    },
    services::BackendServices,
    ssh::{BoundSshSession, SftpTransferCancel},
    target::TargetGuard,
};
use serde::Serialize;
use tokio::{io::AsyncWriteExt, net::TcpListener, sync::Semaphore, time::timeout};
use uuid::Uuid;

use crate::ssh_api::SshApi;

const MAX_HANDLE_BYTES: usize = 128;
/// The LISTEN-table read and the channel open are bounded the same way.
const LISTEN_DEADLINE: Duration = Duration::from_secs(30);

/// One forward the page sees: its own addresses and counters, never the
/// listener, the session or the sockets.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct PortForwardDto {
    pub forward_handle: String,
    /// e.g. `127.0.0.1:15432` — the address any local process may reach.
    pub local_address: String,
    /// e.g. `127.0.0.1:8080` — the destination on the target.
    pub destination: String,
    pub connections: u32,
    pub bytes_in: String,
    pub bytes_out: String,
    pub last_error: Option<String>,
}

struct PortForward {
    forward_handle: String,
    local_address: String,
    destination: ForwardDestination,
    cancel: SftpTransferCancel,
    connections: AtomicU32,
    bytes_in: AtomicU64,
    bytes_out: AtomicU64,
    last_error: Mutex<Option<String>>,
}

impl PortForward {
    fn snapshot(&self) -> PortForwardDto {
        PortForwardDto {
            forward_handle: self.forward_handle.clone(),
            local_address: self.local_address.clone(),
            destination: format!("{}:{}", self.destination.host, self.destination.port),
            connections: self.connections.load(Ordering::Relaxed),
            bytes_in: self.bytes_in.load(Ordering::Relaxed).to_string(),
            bytes_out: self.bytes_out.load(Ordering::Relaxed).to_string(),
            last_error: self.last_error.lock().ok().and_then(|error| error.clone()),
        }
    }
}

#[derive(Default)]
struct PortForwardRegistry {
    /// Forwards per binding handle; dropped and cancelled together when the
    /// binding closes.
    forwards: HashMap<String, Vec<Arc<PortForward>>>,
}

pub(crate) enum PortForwardApiError {
    Core(CoreError),
    BindingUnavailable,
    InvalidRequest,
    /// The destination is not loopback and not in the target's LISTEN table.
    DestinationRefused,
    /// The local port is already bound by another process.
    PortTaken,
    /// Eight forwards per binding; the ninth is refused.
    Capacity,
    NotFound,
    RegistryUnavailable,
}

impl fmt::Debug for PortForwardApiError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Core(_) => "Core([REDACTED])",
            Self::BindingUnavailable => "BindingUnavailable",
            Self::InvalidRequest => "InvalidRequest",
            Self::DestinationRefused => "DestinationRefused",
            Self::PortTaken => "PortTaken",
            Self::Capacity => "Capacity",
            Self::NotFound => "NotFound",
            Self::RegistryUnavailable => "RegistryUnavailable",
        })
    }
}

pub(crate) struct PortForwardApi {
    services: BackendServices,
    ssh_api: Arc<SshApi>,
    registry: Arc<Mutex<PortForwardRegistry>>,
}

impl fmt::Debug for PortForwardApi {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("PortForwardApi")
    }
}

impl PortForwardApi {
    pub(crate) fn new(services: BackendServices, ssh_api: Arc<SshApi>) -> Self {
        Self {
            services,
            ssh_api,
            registry: Arc::new(Mutex::new(PortForwardRegistry::default())),
        }
    }

    fn lock_registry(&self) -> Result<MutexGuard<'_, PortForwardRegistry>, PortForwardApiError> {
        self.registry
            .lock()
            .map_err(|_| PortForwardApiError::RegistryUnavailable)
    }

    fn capture_binding(
        &self,
        binding_handle: &str,
    ) -> Result<BoundSshSession, PortForwardApiError> {
        if binding_handle.is_empty()
            || binding_handle.len() > MAX_HANDLE_BYTES
            || !binding_handle
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
        {
            return Err(PortForwardApiError::InvalidRequest);
        }
        let session = self
            .ssh_api
            .binding_session_clone(binding_handle)
            .map_err(|_| PortForwardApiError::BindingUnavailable)?;
        self.services
            .target()
            .validate(session.target())
            .map_err(|_| PortForwardApiError::BindingUnavailable)?;
        Ok(session)
    }

    /// The destination check runs before anything binds: read the target's
    /// LISTEN table through the fixed core command and only accept an
    /// address the target itself advertises.
    async fn checked_destination(
        &self,
        session: &BoundSshSession,
        host: &str,
        port: u16,
    ) -> Result<ForwardDestination, PortForwardApiError> {
        let host_addr =
            parse_destination_host(host).map_err(|_| PortForwardApiError::InvalidRequest)?;
        let destination = ForwardDestination {
            host: host_addr,
            port,
        };
        if destination.host.is_loopback() {
            return Ok(destination);
        }
        let output = timeout(
            LISTEN_DEADLINE,
            self.services.ssh().execute_bound(
                session,
                LISTEN_TABLE_COMMAND.to_owned(),
                LISTEN_DEADLINE,
            ),
        )
        .await
        .map_err(|_| PortForwardApiError::DestinationRefused)?
        .map_err(PortForwardApiError::Core)?;
        let table = parse_listen_table(&output.output);
        if !destination_allowed(&destination, &table) {
            return Err(PortForwardApiError::DestinationRefused);
        }
        Ok(destination)
    }

    /// Starts one forward after the UI's own confirmation: bind the loopback
    /// listener, register it against the binding, and spawn the accept loop.
    pub(crate) async fn forward_start(
        &self,
        binding_handle: &str,
        local_port: u16,
        destination_host: &str,
        destination_port: u16,
    ) -> Result<PortForwardDto, PortForwardApiError> {
        validate_local_port(local_port).map_err(|_| PortForwardApiError::InvalidRequest)?;
        validate_destination_port(destination_port)
            .map_err(|_| PortForwardApiError::InvalidRequest)?;
        let session = self.capture_binding(binding_handle)?;
        let destination = self
            .checked_destination(&session, destination_host, destination_port)
            .await?;
        {
            let registry = self.lock_registry()?;
            if registry
                .forwards
                .get(binding_handle)
                .map(|forwards| forwards.len())
                .unwrap_or(0)
                >= MAX_FORWARDS_PER_BINDING
            {
                return Err(PortForwardApiError::Capacity);
            }
        }
        let listener = match TcpListener::bind((Ipv4Addr::LOCALHOST, local_port)).await {
            Ok(listener) => listener,
            Err(source) if source.kind() == std::io::ErrorKind::AddrInUse => {
                return Err(PortForwardApiError::PortTaken);
            }
            Err(_) => {
                return Err(PortForwardApiError::Core(CoreError::Validation {
                    subject: "local forward listener",
                    message: "the local listener could not be bound".to_owned(),
                }));
            }
        };
        let bound = listener
            .local_addr()
            .map_err(|_| PortForwardApiError::RegistryUnavailable)?;
        let forward = Arc::new(PortForward {
            forward_handle: Uuid::new_v4().to_string(),
            local_address: bound.to_string(),
            destination,
            cancel: SftpTransferCancel::new(),
            connections: AtomicU32::new(0),
            bytes_in: AtomicU64::new(0),
            bytes_out: AtomicU64::new(0),
            last_error: Mutex::new(None),
        });
        {
            let mut registry = self.lock_registry()?;
            registry
                .forwards
                .entry(binding_handle.to_owned())
                .or_default()
                .push(Arc::clone(&forward));
        }
        self.journal(
            session.target(),
            &forward,
            &format!(
                "端口转发开始：本机 {} 经 SSH 转发到目标 {}:{}",
                forward.local_address, destination.host, destination.port,
            ),
        );
        tokio::spawn(accept_loop(
            listener,
            Arc::clone(&forward),
            session,
            self.services.ssh().clone(),
        ));
        Ok(forward.snapshot())
    }

    /// Lists this binding's live forwards with their counters.
    pub(crate) fn forward_list(
        &self,
        binding_handle: &str,
    ) -> Result<Vec<PortForwardDto>, PortForwardApiError> {
        self.capture_binding(binding_handle)?;
        let registry = self.lock_registry()?;
        Ok(registry
            .forwards
            .get(binding_handle)
            .map(|forwards| forwards.iter().map(|forward| forward.snapshot()).collect())
            .unwrap_or_default())
    }

    /// Stops one forward: the listener goes away and every live connection is
    /// cancelled; the entry leaves the registry.
    pub(crate) fn forward_stop(
        &self,
        binding_handle: &str,
        forward_handle: &str,
    ) -> Result<PortForwardDto, PortForwardApiError> {
        let session = self.capture_binding(binding_handle)?;
        let forward = {
            let mut registry = self.lock_registry()?;
            let forwards = registry
                .forwards
                .get_mut(binding_handle)
                .ok_or(PortForwardApiError::NotFound)?;
            let index = forwards
                .iter()
                .position(|forward| forward.forward_handle == forward_handle)
                .ok_or(PortForwardApiError::NotFound)?;
            forwards.remove(index)
        };
        forward.cancel.cancel();
        self.journal(
            session.target(),
            &forward,
            &format!(
                "端口转发停止：本机 {} 到目标 {}:{}",
                forward.local_address, forward.destination.host, forward.destination.port,
            ),
        );
        Ok(forward.snapshot())
    }

    /// A closing binding throws the switch on every one of its forwards and
    /// drops the registry entry: the listeners and live channels die with it.
    pub(crate) fn close_binding(&self, binding_handle: &str) {
        let forwards = self
            .registry
            .lock()
            .ok()
            .and_then(|mut registry| registry.forwards.remove(binding_handle))
            .unwrap_or_default();
        for forward in forwards {
            forward.cancel.cancel();
        }
    }

    fn journal(&self, target: &TargetGuard, forward: &PortForward, summary: &str) {
        let _ = self
            .services
            .operation_journal()
            .append(OperationJournalEntry {
                entry_id: Uuid::new_v4().to_string(),
                operation_id: forward.forward_handle.clone(),
                target: target.clone(),
                summary: summary.to_owned(),
                dangerous: false,
                source: "port-forward".to_owned(),
                restore_description: None,
                phase: JournalPhase::Executed,
                detail: format!(
                    "本机 {} → 目标 {}:{}；连接 {} 条，入 {} 字节，出 {} 字节",
                    forward.local_address,
                    forward.destination.host,
                    forward.destination.port,
                    forward.connections.load(Ordering::Relaxed),
                    forward.bytes_in.load(Ordering::Relaxed),
                    forward.bytes_out.load(Ordering::Relaxed),
                ),
                occurred_at: Utc::now(),
            });
    }
}

/// The accept loop for one forward. Each accepted socket takes a semaphore
/// slot (32 per forward), opens a `direct-tcpip` channel on the bound
/// session, and copies bytes both ways until either side closes or the
/// forward is cancelled.
async fn accept_loop(
    listener: TcpListener,
    forward: Arc<PortForward>,
    session: BoundSshSession,
    ssh: lovelyhawk_core::ssh::SshService,
) {
    let slots = Arc::new(Semaphore::new(MAX_FORWARD_CONNECTIONS));
    loop {
        tokio::select! {
            () = forward.cancel.cancelled() => break,
            accepted = listener.accept() => {
                match accepted {
                    Ok((socket, peer)) => {
                        let permit = match slots.clone().try_acquire_owned() {
                            Ok(permit) => permit,
                            Err(_) => {
                                set_error(&forward, "连接数已达上限".to_owned());
                                drop(socket);
                                continue;
                            }
                        };
                        forward.connections.fetch_add(1, Ordering::Relaxed);
                        let forward = Arc::clone(&forward);
                        let session = session.clone();
                        let ssh = ssh.clone();
                        tokio::spawn(async move {
                            let _permit = permit;
                            pump_connection(socket, peer.port(), &forward, &session, &ssh).await;
                            forward.connections.fetch_sub(1, Ordering::Relaxed);
                        });
                    }
                    Err(_) => {
                        set_error(&forward, "本机监听出错".to_owned());
                        break;
                    }
                }
            }
        }
    }
}

/// Channel opens run one at a time: a burst of concurrent
/// `channel_open_direct_tcpip` calls on one russh session can hand a channel
/// that closes with no data to the opener. Serializing just the open keeps
/// the connections themselves concurrent.
static CHANNEL_OPEN_LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

async fn pump_connection(
    socket: tokio::net::TcpStream,
    originator_port: u16,
    forward: &Arc<PortForward>,
    session: &BoundSshSession,
    ssh: &lovelyhawk_core::ssh::SshService,
) {
    let opened = {
        let _open_slot = CHANNEL_OPEN_LOCK.lock().await;
        ssh.open_direct_tcpip_bound(session, forward.destination, originator_port)
            .await
    };
    let channel = match opened {
        Ok(channel) => channel,
        Err(error) => {
            tracing::debug!(%originator_port, %error, "forward channel open failed");
            set_error(forward, format!("目标拒绝了这次通道：{error}"));
            return;
        }
    };
    let stream = channel.into_stream();
    let _ = socket.set_nodelay(true);
    let (mut socket_read, mut socket_write) = socket.into_split();
    let (mut channel_read, mut channel_write) = tokio::io::split(stream);
    // Each direction is its own task: when a copy sees EOF it shuts down the
    // writer it owns, so the peer on that side gets the same half-close —
    // FIN to the client when the channel dies, channel EOF when the client
    // half-closes. tokio::io::copy does not shut down the writer itself.
    // The halves come back so the socket is not closed until the settle
    // below: dropping the socket the instant the copies join lets the
    // client's last ACK land on a dead socket, and the RST it earns discards
    // bytes the client has not read yet.
    let mut to_channel = tokio::spawn(async move {
        let result = tokio::io::copy(&mut socket_read, &mut channel_write).await;
        let _ = channel_write.shutdown().await;
        tracing::debug!(%originator_port, ?result, "client->channel copy ended");
        // The halves are boxed so they come back without naming russh types.
        (
            result,
            Box::new((socket_read, channel_write)) as Box<dyn std::any::Any + Send>,
        )
    });
    let mut to_socket = tokio::spawn(async move {
        let result = tokio::io::copy(&mut channel_read, &mut socket_write).await;
        let _ = socket_write.shutdown().await;
        tracing::debug!(%originator_port, ?result, "channel->client copy ended");
        (
            result,
            Box::new((socket_write, channel_read)) as Box<dyn std::any::Any + Send>,
        )
    });
    let mut halves = None;
    tokio::select! {
        () = forward.cancel.cancelled() => {
            to_channel.abort();
            to_socket.abort();
        }
        result = pump_joined(&mut to_channel, &mut to_socket) => {
            match result {
                // socket→channel is out, channel→socket is in.
                Ok(((outgoing, incoming), pair)) => {
                    tracing::debug!(%originator_port, outgoing, incoming, "forward connection closed");
                    forward.bytes_out.fetch_add(outgoing, Ordering::Relaxed);
                    forward.bytes_in.fetch_add(incoming, Ordering::Relaxed);
                    halves = Some(pair);
                }
                Err(error) => {
                    tracing::debug!(%originator_port, %error, "forward copy failed");
                    set_error(forward, format!("转发连接中断：{error}"));
                }
            }
        }
    }
    // Let the FIN handshake settle before the socket can close: the client's
    // final ACK and half-close answer arrive on loopback inside a fraction of
    // this, and an already-dead socket would answer them with RST.
    if halves.is_some() {
        tokio::time::sleep(CLOSE_SETTLE).await;
    }
    drop(halves);
}

/// How long a connection may outlive the direction that ended first. The
/// bound keeps a silent client from pinning a slot; the joined tasks are
/// aborted rather than left copying after the forward moved on.
const CLOSE_DRAIN: Duration = Duration::from_secs(2);

/// How long the socket halves are held after both copies finish so the
/// client's half-close answer lands on a live socket.
const CLOSE_SETTLE: Duration = Duration::from_millis(200);

type PumpHalves = (Box<dyn std::any::Any + Send>, Box<dyn std::any::Any + Send>);
type PumpTask = tokio::task::JoinHandle<(std::io::Result<u64>, Box<dyn std::any::Any + Send>)>;

/// Waits for both copy directions to finish, bounded, and hands the socket
/// and channel halves back so the caller owns the final close. On the bound
/// the tasks are aborted and the halves die with them — the close is already
/// an abnormal end.
async fn pump_joined(
    to_channel: &mut PumpTask,
    to_socket: &mut PumpTask,
) -> std::io::Result<((u64, u64), Option<PumpHalves>)> {
    let waited = timeout(CLOSE_DRAIN, async {
        tokio::join!(&mut *to_channel, &mut *to_socket)
    })
    .await;
    let (outgoing, incoming) = match waited {
        Ok(pair) => pair,
        Err(_) => {
            to_channel.abort();
            to_socket.abort();
            return Ok(((0, 0), None));
        }
    };
    let task_failed = || std::io::Error::other("forward pump task failed");
    let (outgoing_result, outgoing_halves) = outgoing.map_err(|_| task_failed())?;
    let (incoming_result, incoming_halves) = incoming.map_err(|_| task_failed())?;
    Ok((
        (outgoing_result?, incoming_result?),
        Some((outgoing_halves, incoming_halves)),
    ))
}

fn set_error(forward: &Arc<PortForward>, message: String) {
    if let Ok(mut error) = forward.last_error.lock() {
        *error = Some(message);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dto_serializes_exact_fields() {
        let dto = PortForwardDto {
            forward_handle: "h".to_owned(),
            local_address: "127.0.0.1:15432".to_owned(),
            destination: "127.0.0.1:8080".to_owned(),
            connections: 2,
            bytes_in: "100".to_owned(),
            bytes_out: "200".to_owned(),
            last_error: Some("通道中断".to_owned()),
        };
        let value = serde_json::to_value(&dto).unwrap();
        let mut keys: Vec<&str> = value
            .as_object()
            .unwrap()
            .keys()
            .map(String::as_str)
            .collect();
        keys.sort_unstable();
        assert_eq!(
            keys,
            [
                "bytesIn",
                "bytesOut",
                "connections",
                "destination",
                "forwardHandle",
                "lastError",
                "localAddress",
            ]
        );
        assert_eq!(value["connections"], 2);
        assert_eq!(value["lastError"], "通道中断");
    }
}
