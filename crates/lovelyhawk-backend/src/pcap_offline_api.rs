//! Offline pcap analysis. The analysis runs host-side in a blocking task with
//! byte progress and cancellation. Local paths enter only through host
//! commands (import) or the retained evidence job record — the page never
//! sends or receives a path.

use std::{
    fs::File,
    io::Read,
    path::{Path, PathBuf},
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicU64, Ordering},
    },
};

use parking_lot::Mutex;

use lovelyhawk_core::pcap_offline::{
    CaidaoEcho, FlowSummary, HttpTransaction, PcapAlert, PcapAnalysis, PcapObjectInfo, PcapSummary,
    analyze_pcap,
};
use serde::Serialize;

use crate::packet_capture_evidence_api::PacketCaptureEvidenceApi;

const MAX_IMPORT_BYTES: u64 = 256 * 1024 * 1024;
const READ_CHUNK: usize = 1024 * 1024;
const MAX_LIST: usize = 2_000;

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct PcapAnalysisDto {
    summary: PcapSummary,
    flows: Vec<FlowSummary>,
    http: Vec<HttpTransaction>,
    objects: Vec<PcapObjectInfo>,
    alerts: Vec<PcapAlert>,
    echoes: Vec<CaidaoEcho>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct PcapOfflineStatusDto {
    state: String,
    /// "import" | "evidence" — which source produced this run.
    source: String,
    bytes_read: u64,
    total_bytes: u64,
    detail: String,
    result: Option<PcapAnalysisDto>,
}

struct Job {
    state: &'static str,
    source: &'static str,
    bytes_read: Arc<AtomicU64>,
    total_bytes: u64,
    detail: String,
    cancel: Arc<AtomicBool>,
    analysis: Option<PcapAnalysis>,
    abort: Option<tokio::task::AbortHandle>,
}

impl Job {
    fn dto(&self) -> PcapOfflineStatusDto {
        PcapOfflineStatusDto {
            state: self.state.to_owned(),
            source: self.source.to_owned(),
            bytes_read: self.bytes_read.load(Ordering::Relaxed),
            total_bytes: self.total_bytes,
            detail: self.detail.clone(),
            result: self.analysis.as_ref().map(|a| PcapAnalysisDto {
                summary: a.summary.clone(),
                flows: a.flows.iter().take(MAX_LIST).cloned().collect(),
                http: a.http.iter().take(MAX_LIST).cloned().collect(),
                objects: a.objects.iter().take(MAX_LIST).cloned().collect(),
                alerts: a.alerts.iter().take(MAX_LIST).cloned().collect(),
                echoes: a.echoes.iter().take(MAX_LIST).cloned().collect(),
            }),
        }
    }
}

#[derive(Debug)]
pub(crate) enum PcapOfflineError {
    Invalid,
    EvidenceGone,
    Busy,
    TooLarge,
    Unavailable,
    NotFound,
    Exists,
}

impl std::fmt::Debug for PcapOfflineApi {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PcapOfflineApi")
            .field("running", &self.job.lock().is_some())
            .finish()
    }
}

#[derive(Clone)]
pub(crate) struct PcapOfflineApi {
    packet_evidence: PacketCaptureEvidenceApi,
    job: Arc<Mutex<Option<Job>>>,
}

impl PcapOfflineApi {
    pub(crate) fn new(packet_evidence: PacketCaptureEvidenceApi) -> Self {
        Self {
            packet_evidence,
            job: Arc::new(Mutex::new(None)),
        }
    }

    /// Host command path: the desktop dialog already picked the file.
    pub(crate) fn begin_path(&self, path: &Path) -> Result<(), PcapOfflineError> {
        let metadata = std::fs::metadata(path).map_err(|_| PcapOfflineError::Invalid)?;
        if !metadata.is_file() {
            return Err(PcapOfflineError::Invalid);
        }
        if metadata.len() > MAX_IMPORT_BYTES {
            return Err(PcapOfflineError::TooLarge);
        }
        self.spawn(path.to_path_buf(), "import")
    }

    /// Page path: an opaque evidence job handle resolves to the local pcap.
    pub(crate) fn begin_evidence(&self, job_handle: &str) -> Result<(), PcapOfflineError> {
        if job_handle.trim().is_empty() || job_handle.len() > 128 {
            return Err(PcapOfflineError::Invalid);
        }
        let path = self
            .packet_evidence
            .saved_pcap_path(job_handle)
            .ok_or(PcapOfflineError::EvidenceGone)?;
        self.spawn(path, "evidence")
    }

    fn spawn(&self, path: PathBuf, source: &'static str) -> Result<(), PcapOfflineError> {
        let mut guard = self.job.lock();
        if let Some(existing) = guard.as_ref()
            && matches!(existing.state, "reading" | "analyzing")
        {
            return Err(PcapOfflineError::Busy);
        }
        let total = std::fs::metadata(&path).map(|m| m.len()).unwrap_or(0);
        let bytes_read = Arc::new(AtomicU64::new(0));
        let cancel = Arc::new(AtomicBool::new(false));
        *guard = Some(Job {
            state: "reading",
            source,
            bytes_read: Arc::clone(&bytes_read),
            total_bytes: total,
            detail: "正在读取抓包文件…".to_owned(),
            cancel: Arc::clone(&cancel),
            analysis: None,
            abort: None,
        });
        let job = Arc::clone(&self.job);
        let read = bytes_read;
        let flag = cancel;
        drop(guard);
        let task = tokio::spawn(async move {
            let mut file = match File::open(&path) {
                Ok(f) => f,
                Err(_) => {
                    finish(&job, "failed", "无法打开抓包文件。", None);
                    return;
                }
            };
            let mut data = Vec::with_capacity(total.min(MAX_IMPORT_BYTES) as usize);
            let mut buf = vec![0u8; READ_CHUNK];
            loop {
                if flag.load(Ordering::Relaxed) {
                    finish(&job, "cancelled", "已取消。", None);
                    return;
                }
                match file.read(&mut buf) {
                    Ok(0) => break,
                    Ok(n) => {
                        data.extend_from_slice(&buf[..n]);
                        read.fetch_add(n as u64, Ordering::Relaxed);
                    }
                    Err(_) => {
                        finish(&job, "failed", "读取抓包文件失败。", None);
                        return;
                    }
                }
            }
            if let Some(j) = job.lock().as_mut() {
                j.state = "analyzing";
                j.detail = "正在解析抓包…".to_owned();
            }
            let flag2 = Arc::clone(&flag);
            let progress = move |off: u64| {
                read.store(off, Ordering::Relaxed);
            };
            let analyzed =
                tokio::task::spawn_blocking(move || analyze_pcap(&data, &progress, &flag2)).await;
            match analyzed {
                Ok(Ok(analysis)) => finish(&job, "done", "分析完成。", Some(analysis)),
                Ok(Err(e)) if e == "cancelled" => finish(&job, "cancelled", "已取消。", None),
                Ok(Err(_)) => finish(&job, "failed", "解析失败：文件损坏或超出限制。", None),
                Err(_) => finish(&job, "cancelled", "已取消。", None),
            }
        });
        if let Some(j) = self.job.lock().as_mut() {
            j.abort = Some(task.abort_handle());
        }
        Ok(())
    }

    pub(crate) fn status(&self) -> PcapOfflineStatusDto {
        match self.job.lock().as_ref() {
            Some(job) => job.dto(),
            None => PcapOfflineStatusDto {
                state: "idle".to_owned(),
                source: String::new(),
                bytes_read: 0,
                total_bytes: 0,
                detail: "尚未开始分析。".to_owned(),
                result: None,
            },
        }
    }

    pub(crate) fn cancel(&self) -> Result<(), PcapOfflineError> {
        let mut guard = self.job.lock();
        let Some(job) = guard.as_mut() else {
            return Err(PcapOfflineError::NotFound);
        };
        if !matches!(job.state, "reading" | "analyzing") {
            return Err(PcapOfflineError::Invalid);
        }
        job.cancel.store(true, Ordering::Relaxed);
        if let Some(abort) = job.abort.take() {
            abort.abort();
        }
        job.state = "cancelled";
        job.detail = "已取消。".to_owned();
        Ok(())
    }

    /// Host command path: export one object's raw bytes to a dialog-chosen file.
    pub(crate) fn export_object(
        &self,
        object_id: &str,
        dest: &Path,
    ) -> Result<u64, PcapOfflineError> {
        if !object_id.starts_with("obj-") || object_id.len() > 24 {
            return Err(PcapOfflineError::Invalid);
        }
        let guard = self.job.lock();
        let Some(job) = guard.as_ref() else {
            return Err(PcapOfflineError::NotFound);
        };
        let Some(analysis) = job.analysis.as_ref() else {
            return Err(PcapOfflineError::NotFound);
        };
        let bytes = analysis
            .object_bytes
            .get(object_id)
            .ok_or(PcapOfflineError::NotFound)?;
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(dest)
            .map_err(|e| {
                if e.kind() == std::io::ErrorKind::AlreadyExists {
                    PcapOfflineError::Exists
                } else {
                    PcapOfflineError::Unavailable
                }
            })?;
        use std::io::Write;
        file.write_all(bytes)
            .map_err(|_| PcapOfflineError::Unavailable)?;
        Ok(bytes.len() as u64)
    }
}

fn finish(
    job: &Arc<Mutex<Option<Job>>>,
    state: &'static str,
    detail: &str,
    analysis: Option<PcapAnalysis>,
) {
    if let Some(j) = job.lock().as_mut() {
        j.state = state;
        j.detail = detail.to_owned();
        j.analysis = analysis;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dto_is_camel_case_and_hides_bytes() {
        let dto = PcapOfflineStatusDto {
            state: "idle".into(),
            source: "import".into(),
            bytes_read: 3,
            total_bytes: 9,
            detail: "x".into(),
            result: None,
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
            vec![
                "bytesRead",
                "detail",
                "result",
                "source",
                "state",
                "totalBytes"
            ]
        );
        assert!(!serde_json::to_string(&dto).unwrap().contains("path"));
    }
}
