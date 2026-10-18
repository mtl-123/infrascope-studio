use crate::{
    config::{Config, Kind, RemoteConfig},
    protocol::{Ack, Envelope, MAX_BODY},
};
use anyhow::{bail, Context, Result};
use base64::{engine::general_purpose::STANDARD, Engine};
use ed25519_dalek::SigningKey;
use fs2::FileExt;
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};
use std::{
    fs::{self, File, OpenOptions},
    io::Write,
    path::{Path, PathBuf},
};

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct State {
    pub format: u32,
    pub kind: Kind,
    pub protected_seed: String,
    pub agent_id: Option<String>,
    pub asset_id: Option<String>,
    pub sequence: u64,
    pub remote_config: Option<RemoteConfig>,
}

pub struct Store {
    pub state: State,
    pub key: SigningKey,
    dir: PathBuf,
    queue: PathBuf,
    max_bytes: u64,
    max_files: usize,
    _lock: File,
}

fn reject_link(path: &Path) -> Result<()> {
    if let Ok(meta) = fs::symlink_metadata(path) {
        if meta.file_type().is_symlink() {
            bail!("state paths must not be symbolic links");
        }
    }
    Ok(())
}

fn private_dir(path: &Path) -> Result<()> {
    reject_link(path)?;
    fs::create_dir_all(path).context("create private state directory")?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(0o700))?;
    }
    Ok(())
}

pub fn atomic_write(path: &Path, bytes: &[u8]) -> Result<()> {
    reject_link(path)?;
    let parent = path.parent().context("state file has no parent")?;
    let temp = parent.join(format!(".{}.tmp", uuid::Uuid::new_v4()));
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let result = (|| {
        let mut file = options.open(&temp)?;
        file.write_all(bytes)?;
        file.sync_all()?;
        drop(file);
        #[cfg(not(windows))]
        fs::rename(&temp, path)?;
        #[cfg(windows)]
        {
            use std::os::windows::ffi::OsStrExt;
            use windows_sys::Win32::Storage::FileSystem::{
                MoveFileExW, MOVEFILE_REPLACE_EXISTING, MOVEFILE_WRITE_THROUGH,
            };
            let from: Vec<u16> = temp.as_os_str().encode_wide().chain(Some(0)).collect();
            let to: Vec<u16> = path.as_os_str().encode_wide().chain(Some(0)).collect();
            if unsafe {
                MoveFileExW(
                    from.as_ptr(),
                    to.as_ptr(),
                    MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH,
                )
            } == 0
            {
                return Err(std::io::Error::last_os_error().into());
            }
        }
        #[cfg(unix)]
        File::open(parent)?.sync_all()?;
        Ok(())
    })();
    if result.is_err() {
        let _ = fs::remove_file(&temp);
    }
    result
}

#[cfg(not(windows))]
fn protect(bytes: &[u8]) -> Result<Vec<u8>> {
    Ok(bytes.to_vec())
}
#[cfg(not(windows))]
fn unprotect(bytes: &[u8]) -> Result<Vec<u8>> {
    Ok(bytes.to_vec())
}

#[cfg(windows)]
fn dpapi(bytes: &[u8], encrypt: bool) -> Result<Vec<u8>> {
    use windows_sys::Win32::{
        Foundation::LocalFree,
        Security::Cryptography::{
            CryptProtectData, CryptUnprotectData, CRYPTPROTECT_UI_FORBIDDEN, CRYPT_INTEGER_BLOB,
        },
    };
    let input = CRYPT_INTEGER_BLOB {
        cbData: bytes.len().try_into()?,
        pbData: bytes.as_ptr() as *mut u8,
    };
    let mut output = CRYPT_INTEGER_BLOB {
        cbData: 0,
        pbData: std::ptr::null_mut(),
    };
    let result = unsafe {
        if encrypt {
            CryptProtectData(
                &input,
                std::ptr::null(),
                std::ptr::null(),
                std::ptr::null_mut(),
                std::ptr::null(),
                CRYPTPROTECT_UI_FORBIDDEN,
                &mut output,
            )
        } else {
            CryptUnprotectData(
                &input,
                std::ptr::null_mut(),
                std::ptr::null(),
                std::ptr::null_mut(),
                std::ptr::null(),
                CRYPTPROTECT_UI_FORBIDDEN,
                &mut output,
            )
        }
    };
    if result == 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    let decrypted =
        unsafe { std::slice::from_raw_parts(output.pbData, output.cbData as usize).to_vec() };
    unsafe {
        LocalFree(output.pbData as *mut core::ffi::c_void);
    }
    Ok(decrypted)
}
#[cfg(windows)]
fn protect(bytes: &[u8]) -> Result<Vec<u8>> {
    dpapi(bytes, true)
}
#[cfg(windows)]
fn unprotect(bytes: &[u8]) -> Result<Vec<u8>> {
    dpapi(bytes, false)
}

impl Store {
    pub fn open(config: &Config, kind: Kind) -> Result<Self> {
        config.validate()?;
        private_dir(&config.state_dir)?;
        let queue = config.state_dir.join("queue");
        private_dir(&queue)?;
        let lock_path = config.state_dir.join("agent.lock");
        reject_link(&lock_path)?;
        let mut options = OpenOptions::new();
        options.read(true).write(true).create(true).truncate(false);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let lock = options.open(lock_path)?;
        lock.try_lock_exclusive()
            .context("another collector is already using this state directory")?;
        let path = config.state_dir.join("identity.json");
        reject_link(&path)?;
        let (state, key) = if path.exists() {
            let bytes = fs::read(&path)?;
            if bytes.len() > 64 * 1024 {
                bail!("identity file is too large");
            }
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                if fs::metadata(&path)?.permissions().mode() & 0o077 != 0 {
                    bail!("identity file permissions must be 0600");
                }
            }
            let state: State = serde_json::from_slice(&bytes)
                .context("read existing identity; refusing to replace it")?;
            if state.format != 1 || state.kind != kind {
                bail!("identity format or collector kind mismatch; use a separate state_dir per collector");
            }
            let seed = unprotect(
                &STANDARD
                    .decode(&state.protected_seed)
                    .context("decode protected identity")?,
            )?;
            let raw: [u8; 32] = seed
                .try_into()
                .map_err(|_| anyhow::anyhow!("invalid identity seed length"))?;
            let key = SigningKey::from_bytes(&raw);
            if state.agent_id.is_some() != state.asset_id.is_some() {
                bail!("incomplete identity enrollment");
            }
            if let Some(remote) = &state.remote_config {
                remote.validate(kind)?;
            }
            (state, key)
        } else {
            let key = SigningKey::generate(&mut OsRng);
            let state = State {
                format: 1,
                kind,
                protected_seed: STANDARD.encode(protect(&key.to_bytes())?),
                agent_id: None,
                asset_id: None,
                sequence: 0,
                remote_config: None,
            };
            atomic_write(&path, &serde_json::to_vec(&state)?)?;
            (state, key)
        };
        let store = Self {
            state,
            key,
            dir: config.state_dir.clone(),
            queue,
            max_bytes: config.max_queue_bytes,
            max_files: config.max_queue_files,
            _lock: lock,
        };
        store.pending()?;
        Ok(store)
    }

    pub fn save(&self) -> Result<()> {
        atomic_write(
            &self.dir.join("identity.json"),
            &serde_json::to_vec(&self.state)?,
        )
    }

    pub fn reserve_sequence(&mut self) -> Result<u64> {
        self.state.sequence = self
            .state
            .sequence
            .checked_add(1)
            .context("sequence exhausted")?;
        self.save()?;
        Ok(self.state.sequence)
    }

    pub fn pending(&self) -> Result<Vec<PathBuf>> {
        let mut entries = Vec::new();
        for entry in fs::read_dir(&self.queue)? {
            let entry = entry?;
            if entry.file_name().to_string_lossy().starts_with('.')
                && entry.path().extension().is_some_and(|x| x == "tmp")
            {
                continue;
            }
            if !entry.file_type()?.is_file() || entry.path().extension().is_none_or(|x| x != "json")
            {
                bail!("unexpected entry in persistent queue; manual inspection required");
            }
            entries.push(entry.path());
        }
        entries.sort();
        Ok(entries)
    }

    pub fn enqueue(&self, envelope: &Envelope) -> Result<()> {
        let bytes = serde_json::to_vec(envelope)?;
        if bytes.len() > MAX_BODY {
            bail!("sample exceeds server's 1 MiB limit; not queued");
        }
        let entries = self.pending()?;
        let used = entries
            .iter()
            .try_fold(0_u64, |sum, entry| -> Result<u64> {
                Ok(sum
                    .checked_add(fs::metadata(entry)?.len())
                    .context("queue byte count overflow")?)
            })?;
        if entries.len() >= self.max_files
            || used.saturating_add(bytes.len() as u64) > self.max_bytes
        {
            bail!("queue full; new sample dropped, unacknowledged data retained");
        }
        let sequence: u64 = envelope
            .sequence
            .parse()
            .context("invalid sample sequence")?;
        let id = uuid::Uuid::parse_str(&envelope.batch_id).context("invalid batch ID")?;
        let path = self.queue.join(format!("{sequence:020}-{id}.json"));
        if path.exists() {
            bail!("refusing to overwrite existing queued sample");
        }
        atomic_write(&path, &bytes)
    }

    pub fn read(&self, path: &Path) -> Result<(Vec<u8>, Envelope)> {
        if path.parent() != Some(self.queue.as_path()) {
            bail!("invalid queue entry path");
        }
        reject_link(path)?;
        if fs::metadata(path)?.len() > MAX_BODY as u64 {
            bail!("queue entry exceeds 1 MiB");
        }
        let bytes = fs::read(path)?;
        let envelope: Envelope =
            serde_json::from_slice(&bytes).context("corrupt queued sample; not deleted")?;
        if Some(&envelope.agent_id) != self.state.agent_id.as_ref()
            || Some(&envelope.asset_id) != self.state.asset_id.as_ref()
            || envelope.kind != self.state.kind
        {
            bail!("queued sample belongs to a different enrollment; not deleted");
        }
        Ok((bytes, envelope))
    }

    pub fn acknowledge(&self, path: &Path, expected: &Envelope, ack: &Ack) -> Result<()> {
        if !ack.accepted || ack.batch_id != expected.batch_id {
            bail!("invalid or mismatched acknowledgement; sample retained");
        }
        let (_, actual) = self.read(path)?;
        if actual.batch_id != expected.batch_id {
            bail!("queued sample changed before acknowledgement");
        }
        fs::remove_file(path)?;
        #[cfg(unix)]
        File::open(&self.queue)?.sync_all()?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn setup(dir: &Path) -> Store {
        let mut config = Config::default();
        config.state_dir = dir.into();
        config.max_queue_files = 1;
        let mut store = Store::open(&config, Kind::Host).unwrap();
        store.state.agent_id = Some("agent".into());
        store.state.asset_id = Some("asset".into());
        store.save().unwrap();
        store
    }
    fn sample() -> Envelope {
        Envelope {
            schema_version: 1,
            batch_id: uuid::Uuid::new_v4().to_string(),
            agent_id: "agent".into(),
            asset_id: "asset".into(),
            sequence: "9007199254740993".into(),
            observed_at: chrono::Utc::now().to_rfc3339(),
            config_version: 1,
            kind: Kind::Host,
            metrics: serde_json::json!({}),
            health: serde_json::json!({}),
        }
    }
    #[test]
    fn queue_ack_must_match_and_full_queue_keeps_old_sample() {
        let temp = tempfile::tempdir().unwrap();
        let store = setup(temp.path());
        let sample = sample();
        store.enqueue(&sample).unwrap();
        assert!(store.enqueue(&sample).is_err());
        let entries = store.pending().unwrap();
        assert_eq!(entries.len(), 1);
        let wrong = Ack {
            accepted: true,
            batch_id: "wrong".into(),
            duplicate: false,
        };
        assert!(store.acknowledge(&entries[0], &sample, &wrong).is_err());
        assert_eq!(store.pending().unwrap().len(), 1);
        let right = Ack {
            accepted: true,
            batch_id: sample.batch_id.clone(),
            duplicate: true,
        };
        store.acknowledge(&entries[0], &sample, &right).unwrap();
        assert!(store.pending().unwrap().is_empty());
    }
    #[test]
    fn state_lock_restart_sequence_and_key_are_persistent() {
        let temp = tempfile::tempdir().unwrap();
        let mut store = setup(temp.path());
        let mut config = Config::default();
        config.state_dir = temp.path().into();
        assert!(Store::open(&config, Kind::Host).is_err());
        let key = store.key.verifying_key();
        assert_eq!(store.reserve_sequence().unwrap(), 1);
        store.enqueue(&sample()).unwrap();
        drop(store);
        let mut restarted = Store::open(&config, Kind::Host).unwrap();
        assert_eq!(restarted.key.verifying_key(), key);
        assert_eq!(restarted.reserve_sequence().unwrap(), 2);
        assert_eq!(restarted.pending().unwrap().len(), 1);
        drop(restarted);
        assert!(Store::open(&config, Kind::Pve).is_err());
    }
}
