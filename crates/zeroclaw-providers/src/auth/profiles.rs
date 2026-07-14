use anyhow::{Context, Result};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::time::Duration;
use tokio::fs;
use tokio::time::sleep;
use zeroclaw_config::secrets::SecretStore;

const CURRENT_SCHEMA_VERSION: u32 = 1;
const PROFILES_FILENAME: &str = "auth-profiles.json";
const LOCK_FILENAME: &str = "auth-profiles.lock";
const LOCK_WAIT_MS: u64 = 50;
const LOCK_TIMEOUT_MS: u64 = 10_000;
// Dedicated cross-process refresh lock (flock(2)) lives next to the REAL
// (symlink-resolved) store file so every daemon flocks the same inode.
const REFRESH_LOCK_FILENAME: &str = "auth-profiles.refresh.lock";
// > store LOCK_TIMEOUT_MS: must outlast a queue of 2-3 daemons each holding the
// lock for one bounded HTTP refresh.
const REFRESH_LOCK_TIMEOUT_MS: u64 = 20_000;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum AuthProfileKind {
    OAuth,
    Token,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TokenSet {
    pub access_token: String,
    #[serde(default)]
    pub refresh_token: Option<String>,
    #[serde(default)]
    pub id_token: Option<String>,
    #[serde(default)]
    pub expires_at: Option<DateTime<Utc>>,
    #[serde(default)]
    pub token_type: Option<String>,
    #[serde(default)]
    pub scope: Option<String>,
}

impl TokenSet {
    pub fn is_expiring_within(&self, skew: Duration) -> bool {
        match self.expires_at {
            Some(expires_at) => {
                let now_plus_skew =
                    Utc::now() + chrono::Duration::from_std(skew).unwrap_or_default();
                expires_at <= now_plus_skew
            }
            None => false,
        }
    }
}

#[derive(Clone, Serialize, Deserialize)]
pub struct AuthProfile {
    pub id: String,
    pub model_provider: String,
    pub profile_name: String,
    pub kind: AuthProfileKind,
    #[serde(default)]
    pub account_id: Option<String>,
    #[serde(default)]
    pub workspace_id: Option<String>,
    #[serde(default)]
    pub token_set: Option<TokenSet>,
    #[serde(default)]
    pub token: Option<String>,
    #[serde(default)]
    pub metadata: BTreeMap<String, String>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

impl std::fmt::Debug for AuthProfile {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AuthProfile")
            .field("id", &self.id)
            .field("model_provider", &self.model_provider)
            .field("profile_name", &self.profile_name)
            .field("kind", &self.kind)
            .field("workspace_id", &self.workspace_id)
            .field("metadata", &self.metadata)
            .field("created_at", &self.created_at)
            .field("updated_at", &self.updated_at)
            .finish_non_exhaustive()
    }
}

impl AuthProfile {
    pub fn new_oauth(model_provider: &str, profile_name: &str, token_set: TokenSet) -> Self {
        let now = Utc::now();
        let id = profile_id(model_provider, profile_name);
        Self {
            id,
            model_provider: model_provider.to_string(),
            profile_name: profile_name.to_string(),
            kind: AuthProfileKind::OAuth,
            account_id: None,
            workspace_id: None,
            token_set: Some(token_set),
            token: None,
            metadata: BTreeMap::new(),
            created_at: now,
            updated_at: now,
        }
    }

    pub fn new_token(model_provider: &str, profile_name: &str, token: String) -> Self {
        let now = Utc::now();
        let id = profile_id(model_provider, profile_name);
        Self {
            id,
            model_provider: model_provider.to_string(),
            profile_name: profile_name.to_string(),
            kind: AuthProfileKind::Token,
            account_id: None,
            workspace_id: None,
            token_set: None,
            token: Some(token),
            metadata: BTreeMap::new(),
            created_at: now,
            updated_at: now,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthProfilesData {
    pub schema_version: u32,
    pub updated_at: DateTime<Utc>,
    pub active_profiles: BTreeMap<String, String>,
    pub profiles: BTreeMap<String, AuthProfile>,
}

impl Default for AuthProfilesData {
    fn default() -> Self {
        Self {
            schema_version: CURRENT_SCHEMA_VERSION,
            updated_at: Utc::now(),
            active_profiles: BTreeMap::new(),
            profiles: BTreeMap::new(),
        }
    }
}

#[derive(Debug, Clone)]
pub struct AuthProfilesStore {
    path: PathBuf,
    secret_store: SecretStore,
}

impl AuthProfilesStore {
    pub fn new(state_dir: &Path, encrypt_secrets: bool) -> Self {
        Self {
            path: state_dir.join(PROFILES_FILENAME),
            secret_store: SecretStore::new(state_dir, encrypt_secrets),
        }
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Resolve `self.path` through a symlink to the real backing file so that
    /// tmp+rename and lock files land in the SHARED directory, not the per-user
    /// symlink directory. Falls back to `self.path` when not a symlink or
    /// unresolvable (local single-user case => no-op).
    fn real_path(&self) -> PathBuf {
        match std::fs::canonicalize(&self.path) {
            Ok(p) => p,
            Err(_) => match std::fs::read_link(&self.path) {
                Ok(target) if target.is_absolute() => target,
                Ok(target) => self
                    .path
                    .parent()
                    .map_or(target.clone(), |d| d.join(&target)),
                Err(_) => self.path.clone(),
            },
        }
    }

    /// Path of the cross-process refresh lock, anchored next to the REAL store
    /// file so all daemons sharing it via symlink flock the same inode.
    fn refresh_lock_path(&self) -> PathBuf {
        self.real_path().with_file_name(REFRESH_LOCK_FILENAME)
    }

    /// Path of the cross-process store lock, anchored next to the REAL store
    /// file so every daemon sharing it via symlink flocks the same inode
    /// (matches `refresh_lock_path`; the pre-2026-07-14 per-user O_EXCL lock was
    /// neither shared nor death-safe — see `acquire_lock`).
    fn store_lock_path(&self) -> PathBuf {
        self.real_path().with_file_name(LOCK_FILENAME)
    }

    pub async fn load(&self) -> Result<AuthProfilesData> {
        let _lock = self.acquire_lock().await?;
        self.load_locked().await
    }

    pub async fn upsert_profile(&self, mut profile: AuthProfile, set_active: bool) -> Result<()> {
        let _lock = self.acquire_lock().await?;
        let mut data = self.load_locked().await?;

        profile.updated_at = Utc::now();
        if let Some(existing) = data.profiles.get(&profile.id) {
            profile.created_at = existing.created_at;
        }

        if set_active {
            data.active_profiles
                .insert(profile.model_provider.clone(), profile.id.clone());
        }

        data.profiles.insert(profile.id.clone(), profile);
        data.updated_at = Utc::now();

        self.save_locked(&data).await
    }

    pub async fn remove_profile(&self, profile_id: &str) -> Result<bool> {
        let _lock = self.acquire_lock().await?;
        let mut data = self.load_locked().await?;

        let removed = data.profiles.remove(profile_id).is_some();
        if !removed {
            return Ok(false);
        }

        data.active_profiles
            .retain(|_, active| active != profile_id);
        data.updated_at = Utc::now();
        self.save_locked(&data).await?;
        Ok(true)
    }

    pub async fn set_active_profile(&self, model_provider: &str, profile_id: &str) -> Result<()> {
        let _lock = self.acquire_lock().await?;
        let mut data = self.load_locked().await?;

        if !data.profiles.contains_key(profile_id) {
            anyhow::bail!("Auth profile not found: {profile_id}");
        }

        data.active_profiles
            .insert(model_provider.to_string(), profile_id.to_string());
        data.updated_at = Utc::now();
        self.save_locked(&data).await
    }

    pub async fn clear_active_profile(&self, model_provider: &str) -> Result<()> {
        let _lock = self.acquire_lock().await?;
        let mut data = self.load_locked().await?;
        data.active_profiles.remove(model_provider);
        data.updated_at = Utc::now();
        self.save_locked(&data).await
    }

    pub async fn update_profile<F>(&self, profile_id: &str, mut updater: F) -> Result<AuthProfile>
    where
        F: FnMut(&mut AuthProfile) -> Result<()>,
    {
        let _lock = self.acquire_lock().await?;
        let mut data = self.load_locked().await?;

        let profile = data.profiles.get_mut(profile_id).ok_or_else(|| {
            ::zeroclaw_log::record!(
                WARN,
                ::zeroclaw_log::Event::new(module_path!(), ::zeroclaw_log::Action::Reject)
                    .with_outcome(::zeroclaw_log::EventOutcome::Failure)
                    .with_attrs(::serde_json::json!({"profile_id": profile_id})),
                "auth_profiles: profile not found for update"
            );
            anyhow::Error::msg(format!("Auth profile not found: {profile_id}"))
        })?;

        updater(profile)?;
        profile.updated_at = Utc::now();
        let updated_profile = profile.clone();
        data.updated_at = Utc::now();
        self.save_locked(&data).await?;
        Ok(updated_profile)
    }

    async fn load_locked(&self) -> Result<AuthProfilesData> {
        let mut persisted = self.read_persisted_locked().await?;
        let mut migrated = false;

        let mut profiles = BTreeMap::new();
        for (id, p) in &mut persisted.profiles {
            let (access_token, access_migrated) =
                self.decrypt_optional(p.access_token.as_deref())?;
            let (refresh_token, refresh_migrated) =
                self.decrypt_optional(p.refresh_token.as_deref())?;
            let (id_token, id_migrated) = self.decrypt_optional(p.id_token.as_deref())?;
            let (token, token_migrated) = self.decrypt_optional(p.token.as_deref())?;

            if let Some(value) = access_migrated {
                p.access_token = Some(value);
                migrated = true;
            }
            if let Some(value) = refresh_migrated {
                p.refresh_token = Some(value);
                migrated = true;
            }
            if let Some(value) = id_migrated {
                p.id_token = Some(value);
                migrated = true;
            }
            if let Some(value) = token_migrated {
                p.token = Some(value);
                migrated = true;
            }

            let kind = parse_profile_kind(&p.kind)?;
            let token_set = match kind {
                AuthProfileKind::OAuth => {
                    let access = access_token.ok_or_else(|| {
                        ::zeroclaw_log::record!(
                            ERROR,
                            ::zeroclaw_log::Event::new(
                                module_path!(),
                                ::zeroclaw_log::Action::Reject
                            )
                            .with_outcome(::zeroclaw_log::EventOutcome::Failure)
                            .with_attrs(::serde_json::json!({
                                "profile_id": id,
                                "missing": "access_token",
                            })),
                            "auth_profiles: OAuth profile missing access_token"
                        );
                        anyhow::Error::msg(format!("OAuth profile missing access_token: {id}"))
                    })?;
                    Some(TokenSet {
                        access_token: access,
                        refresh_token,
                        id_token,
                        expires_at: parse_optional_datetime(p.expires_at.as_deref())?,
                        token_type: p.token_type.clone(),
                        scope: p.scope.clone(),
                    })
                }
                AuthProfileKind::Token => None,
            };

            profiles.insert(
                id.clone(),
                AuthProfile {
                    id: id.clone(),
                    model_provider: p.model_provider.clone(),
                    profile_name: p.profile_name.clone(),
                    kind,
                    account_id: p.account_id.clone(),
                    workspace_id: p.workspace_id.clone(),
                    token_set,
                    token,
                    metadata: p.metadata.clone(),
                    created_at: parse_datetime_with_fallback(&p.created_at),
                    updated_at: parse_datetime_with_fallback(&p.updated_at),
                },
            );
        }

        if migrated {
            self.write_persisted_locked(&persisted).await?;
        }

        Ok(AuthProfilesData {
            schema_version: persisted.schema_version,
            updated_at: parse_datetime_with_fallback(&persisted.updated_at),
            active_profiles: persisted.active_profiles,
            profiles,
        })
    }

    async fn save_locked(&self, data: &AuthProfilesData) -> Result<()> {
        let mut persisted = PersistedAuthProfiles {
            schema_version: CURRENT_SCHEMA_VERSION,
            updated_at: data.updated_at.to_rfc3339(),
            active_profiles: data.active_profiles.clone(),
            profiles: BTreeMap::new(),
        };

        for (id, profile) in &data.profiles {
            let (access_token, refresh_token, id_token, expires_at, token_type, scope) =
                match (&profile.kind, &profile.token_set) {
                    (AuthProfileKind::OAuth, Some(token_set)) => (
                        self.encrypt_optional(Some(&token_set.access_token))?,
                        self.encrypt_optional(token_set.refresh_token.as_deref())?,
                        self.encrypt_optional(token_set.id_token.as_deref())?,
                        token_set.expires_at.as_ref().map(DateTime::to_rfc3339),
                        token_set.token_type.clone(),
                        token_set.scope.clone(),
                    ),
                    _ => (None, None, None, None, None, None),
                };

            let token = self.encrypt_optional(profile.token.as_deref())?;

            persisted.profiles.insert(
                id.clone(),
                PersistedAuthProfile {
                    model_provider: profile.model_provider.clone(),
                    profile_name: profile.profile_name.clone(),
                    kind: profile_kind_to_string(profile.kind).to_string(),
                    account_id: profile.account_id.clone(),
                    workspace_id: profile.workspace_id.clone(),
                    access_token,
                    refresh_token,
                    id_token,
                    token,
                    expires_at,
                    token_type,
                    scope,
                    metadata: profile.metadata.clone(),
                    created_at: profile.created_at.to_rfc3339(),
                    updated_at: profile.updated_at.to_rfc3339(),
                },
            );
        }

        self.write_persisted_locked(&persisted).await
    }

    async fn read_persisted_locked(&self) -> Result<PersistedAuthProfiles> {
        if !self.path.exists() {
            return Ok(PersistedAuthProfiles::default());
        }

        let bytes = fs::read(&self.path).await.with_context(|| {
            format!(
                "Failed to read auth profile store at {}",
                self.path.display()
            )
        })?;

        if bytes.is_empty() {
            return Ok(PersistedAuthProfiles::default());
        }

        let mut persisted: PersistedAuthProfiles =
            serde_json::from_slice(&bytes).with_context(|| {
                format!(
                    "Failed to parse auth profile store at {}",
                    self.path.display()
                )
            })?;

        if persisted.schema_version == 0 {
            persisted.schema_version = CURRENT_SCHEMA_VERSION;
        }

        if persisted.schema_version > CURRENT_SCHEMA_VERSION {
            anyhow::bail!(
                "Unsupported auth profile schema version {} (max supported: {})",
                persisted.schema_version,
                CURRENT_SCHEMA_VERSION
            );
        }

        Ok(persisted)
    }

    async fn write_persisted_locked(&self, persisted: &PersistedAuthProfiles) -> Result<()> {
        // Resolve through a per-user symlink so tmp+rename land on the SHARED
        // backing file. A bare rename onto a symlink path replaces the symlink
        // with a regular file, stranding the write in the per-user dir (Bug B).
        let real = self.real_path();
        if let Some(parent) = real.parent() {
            fs::create_dir_all(parent).await.with_context(|| {
                format!(
                    "Failed to create auth profile directory at {}",
                    parent.display()
                )
            })?;
        }

        let json =
            serde_json::to_vec_pretty(persisted).context("Failed to serialize auth profiles")?;
        let tmp_name = format!(
            "{}.tmp.{}.{}",
            PROFILES_FILENAME,
            std::process::id(),
            Utc::now().timestamp_nanos_opt().unwrap_or_default()
        );
        let tmp_path = real.with_file_name(tmp_name);

        fs::write(&tmp_path, &json).await.with_context(|| {
            format!(
                "Failed to write temporary auth profile file at {}",
                tmp_path.display()
            )
        })?;

        fs::rename(&tmp_path, &real).await.with_context(|| {
            format!("Failed to replace auth profile store at {}", real.display())
        })?;

        Ok(())
    }

    fn encrypt_optional(&self, value: Option<&str>) -> Result<Option<String>> {
        match value {
            Some(value) if !value.is_empty() => self.secret_store.encrypt(value).map(Some),
            Some(_) | None => Ok(None),
        }
    }

    fn decrypt_optional(&self, value: Option<&str>) -> Result<(Option<String>, Option<String>)> {
        match value {
            Some(value) if !value.is_empty() => {
                let (plaintext, migrated) = self.secret_store.decrypt_and_migrate(value)?;
                Ok((Some(plaintext), migrated))
            }
            Some(_) | None => Ok((None, None)),
        }
    }

    /// Cross-process exclusive lock around the profile-store read/modify/write
    /// critical section. Uses flock(2) on the SHARED (symlink-resolved) lock
    /// file, so every daemon sharing the store flocks the same inode and the
    /// kernel releases it on fd close / process death. A daemon killed while
    /// holding it (SIGKILL/OOM/deploy) therefore cannot brick auth with a stale
    /// lock file — the previous per-user O_EXCL implementation could, and did:
    /// an orphaned `auth-profiles.lock` bricked codex auth for ~6h (DV-34312,
    /// 2026-07-14). The store lock is held only for brief file reads/writes,
    /// never across the HTTP refresh (that is `acquire_refresh_lock`).
    #[cfg(unix)]
    async fn acquire_lock(&self) -> Result<StoreLockGuard> {
        let path = self.store_lock_path();
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).await.with_context(|| {
                format!("Failed to create lock directory at {}", parent.display())
            })?;
        }

        let mut waited = 0_u64;
        loop {
            let file = std::fs::OpenOptions::new()
                .create(true)
                .write(true)
                .truncate(false)
                .open(&path)
                .with_context(|| {
                    format!("Failed to open auth profile lock at {}", path.display())
                })?;

            match nix::fcntl::Flock::lock(file, nix::fcntl::FlockArg::LockExclusiveNonblock) {
                Ok(flock) => return Ok(StoreLockGuard(flock)),
                // On Linux/macOS EWOULDBLOCK aliases EAGAIN; flock(LOCK_NB)
                // contention surfaces as EAGAIN here.
                Err((_, nix::errno::Errno::EAGAIN)) => {
                    if waited >= LOCK_TIMEOUT_MS {
                        anyhow::bail!(
                            "Timed out waiting for auth profile lock at {}",
                            path.display()
                        );
                    }
                    sleep(Duration::from_millis(LOCK_WAIT_MS)).await;
                    waited = waited.saturating_add(LOCK_WAIT_MS);
                }
                Err((_, e)) => {
                    return Err(anyhow::Error::new(e).context(format!(
                        "Failed to acquire auth profile lock at {}",
                        path.display()
                    )));
                }
            }
        }
    }

    /// Non-Unix fallback: `nix` flock(2) is Unix-only and the daemon only runs
    /// on Linux (Fly) / macOS (local). Windows is a CI compile target only.
    #[cfg(not(unix))]
    async fn acquire_lock(&self) -> Result<StoreLockGuard> {
        let path = self.store_lock_path();
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).await.with_context(|| {
                format!("Failed to create lock directory at {}", parent.display())
            })?;
        }
        let file = std::fs::OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(false)
            .open(&path)
            .with_context(|| format!("Failed to open auth profile lock at {}", path.display()))?;
        Ok(StoreLockGuard(file))
    }

    /// Cross-process exclusive lock around the token-refresh critical section.
    /// Uses flock(2): the kernel releases it on fd close / process death, so a
    /// daemon killed mid-refresh (SIGKILL/OOM/deploy) cannot brick auth with a
    /// stale lock file.
    #[cfg(unix)]
    pub(crate) async fn acquire_refresh_lock(&self) -> Result<RefreshLockGuard> {
        let path = self.refresh_lock_path();
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).await.with_context(|| {
                format!(
                    "Failed to create refresh lock directory at {}",
                    parent.display()
                )
            })?;
        }

        let mut waited = 0_u64;
        loop {
            let file = std::fs::OpenOptions::new()
                .create(true)
                .write(true)
                .truncate(false)
                .open(&path)
                .with_context(|| format!("Failed to open refresh lock at {}", path.display()))?;

            match nix::fcntl::Flock::lock(file, nix::fcntl::FlockArg::LockExclusiveNonblock) {
                Ok(flock) => return Ok(RefreshLockGuard(flock)),
                // On Linux/macOS EWOULDBLOCK aliases EAGAIN; flock(LOCK_NB)
                // contention surfaces as EAGAIN here.
                Err((_, nix::errno::Errno::EAGAIN)) => {
                    if waited >= REFRESH_LOCK_TIMEOUT_MS {
                        ::zeroclaw_log::record!(
                            WARN,
                            ::zeroclaw_log::Event::new(
                                module_path!(),
                                ::zeroclaw_log::Action::Note
                            )
                            .with_outcome(::zeroclaw_log::EventOutcome::Unknown)
                            .with_attrs(::serde_json::json!({
                                "path": path.display().to_string()
                            })),
                            "Timed out waiting for auth refresh lock"
                        );
                        anyhow::bail!(
                            "Timed out waiting for auth refresh lock at {}",
                            path.display()
                        );
                    }
                    sleep(Duration::from_millis(LOCK_WAIT_MS)).await;
                    waited = waited.saturating_add(LOCK_WAIT_MS);
                }
                Err((_, e)) => {
                    return Err(anyhow::Error::new(e).context(format!(
                        "Failed to acquire refresh lock at {}",
                        path.display()
                    )));
                }
            }
        }
    }

    /// Non-Unix fallback: `nix` flock(2) is Unix-only and the daemon only runs
    /// on Linux (Fly) / macOS (local). Windows is a CI compile target only —
    /// open the lock file so the path stays valid and return a guard without
    /// kernel-level locking (no concurrent daemons exist on that target).
    #[cfg(not(unix))]
    pub(crate) async fn acquire_refresh_lock(&self) -> Result<RefreshLockGuard> {
        let path = self.refresh_lock_path();
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).await.with_context(|| {
                format!(
                    "Failed to create refresh lock directory at {}",
                    parent.display()
                )
            })?;
        }
        let file = std::fs::OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(false)
            .open(&path)
            .with_context(|| format!("Failed to open refresh lock at {}", path.display()))?;
        Ok(RefreshLockGuard(file))
    }
}

/// RAII guard for the cross-process refresh flock. Dropping it (or process
/// death) closes the fd and releases the kernel advisory lock.
#[cfg(unix)]
pub(crate) struct RefreshLockGuard(#[allow(dead_code)] nix::fcntl::Flock<std::fs::File>);

/// Non-Unix fallback guard: holds the open lock file (no kernel lock; Windows
/// is a compile-only target, the daemon never runs there).
#[cfg(not(unix))]
pub(crate) struct RefreshLockGuard(#[allow(dead_code)] std::fs::File);

/// RAII guard for the cross-process profile-store flock. Dropping it (or
/// process death) closes the fd and releases the kernel advisory lock — no
/// stale lock file is left behind (unlike the old O_EXCL guard).
#[cfg(unix)]
struct StoreLockGuard(#[allow(dead_code)] nix::fcntl::Flock<std::fs::File>);

/// Non-Unix fallback guard: holds the open lock file (no kernel lock; Windows
/// is a compile-only target, the daemon never runs there).
#[cfg(not(unix))]
struct StoreLockGuard(#[allow(dead_code)] std::fs::File);

#[derive(Debug, Clone, Serialize, Deserialize)]
struct PersistedAuthProfiles {
    #[serde(default = "default_schema_version")]
    schema_version: u32,
    #[serde(default = "default_now_rfc3339")]
    updated_at: String,
    #[serde(default)]
    active_profiles: BTreeMap<String, String>,
    #[serde(default)]
    profiles: BTreeMap<String, PersistedAuthProfile>,
}

impl Default for PersistedAuthProfiles {
    fn default() -> Self {
        Self {
            schema_version: CURRENT_SCHEMA_VERSION,
            updated_at: default_now_rfc3339(),
            active_profiles: BTreeMap::new(),
            profiles: BTreeMap::new(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
struct PersistedAuthProfile {
    // fork: pre-v0.8.0 stores spell this field "provider"; the alias keeps
    // existing volume data readable after the upstream rename (patch #12).
    #[serde(alias = "provider")]
    model_provider: String,
    profile_name: String,
    kind: String,
    #[serde(default)]
    account_id: Option<String>,
    #[serde(default)]
    workspace_id: Option<String>,
    #[serde(default)]
    access_token: Option<String>,
    #[serde(default)]
    refresh_token: Option<String>,
    #[serde(default)]
    id_token: Option<String>,
    #[serde(default)]
    token: Option<String>,
    #[serde(default)]
    expires_at: Option<String>,
    #[serde(default)]
    token_type: Option<String>,
    #[serde(default)]
    scope: Option<String>,
    #[serde(default = "default_now_rfc3339")]
    created_at: String,
    #[serde(default = "default_now_rfc3339")]
    updated_at: String,
    #[serde(default)]
    metadata: BTreeMap<String, String>,
}

fn default_schema_version() -> u32 {
    CURRENT_SCHEMA_VERSION
}

fn default_now_rfc3339() -> String {
    Utc::now().to_rfc3339()
}

fn parse_profile_kind(value: &str) -> Result<AuthProfileKind> {
    match value {
        "oauth" => Ok(AuthProfileKind::OAuth),
        "token" => Ok(AuthProfileKind::Token),
        other => anyhow::bail!("Unsupported auth profile kind: {other}"),
    }
}

fn profile_kind_to_string(kind: AuthProfileKind) -> &'static str {
    match kind {
        AuthProfileKind::OAuth => "oauth",
        AuthProfileKind::Token => "token",
    }
}

fn parse_optional_datetime(value: Option<&str>) -> Result<Option<DateTime<Utc>>> {
    value.map(parse_datetime).transpose()
}

fn parse_datetime(value: &str) -> Result<DateTime<Utc>> {
    DateTime::parse_from_rfc3339(value)
        .map(|dt| dt.with_timezone(&Utc))
        .with_context(|| format!("Invalid RFC3339 timestamp: {value}"))
}

fn parse_datetime_with_fallback(value: &str) -> DateTime<Utc> {
    parse_datetime(value).unwrap_or_else(|_| Utc::now())
}

pub fn profile_id(model_provider: &str, profile_name: &str) -> String {
    format!("{}:{}", model_provider.trim(), profile_name.trim())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[cfg(unix)]
    #[test]
    fn real_path_resolves_absolute_symlink_to_shared_target() {
        let shared = tempfile::tempdir().unwrap();
        let user = tempfile::tempdir().unwrap();
        let shared_file = shared.path().join("auth-profiles.json");
        std::fs::write(&shared_file, b"{}").unwrap();
        std::os::unix::fs::symlink(&shared_file, user.path().join("auth-profiles.json")).unwrap();

        let store = AuthProfilesStore::new(user.path(), false);
        assert_eq!(
            store.real_path(),
            std::fs::canonicalize(&shared_file).unwrap()
        );
    }

    #[cfg(unix)]
    #[test]
    fn real_path_resolves_relative_symlink() {
        let base = tempfile::tempdir().unwrap();
        let shared = base.path().join("shared");
        let user = base.path().join("user");
        std::fs::create_dir_all(&shared).unwrap();
        std::fs::create_dir_all(&user).unwrap();
        let shared_file = shared.join("auth-profiles.json");
        std::fs::write(&shared_file, b"{}").unwrap();
        std::os::unix::fs::symlink(
            "../shared/auth-profiles.json",
            user.join("auth-profiles.json"),
        )
        .unwrap();

        let store = AuthProfilesStore::new(&user, false);
        assert_eq!(
            store.real_path(),
            std::fs::canonicalize(&shared_file).unwrap()
        );
    }

    #[test]
    fn real_path_noop_for_existing_regular_file() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("auth-profiles.json"), b"{}").unwrap();
        let store = AuthProfilesStore::new(dir.path(), false);
        assert_eq!(
            store.real_path(),
            std::fs::canonicalize(dir.path().join("auth-profiles.json")).unwrap()
        );
    }

    #[test]
    fn real_path_noop_when_missing() {
        let dir = tempfile::tempdir().unwrap();
        let store = AuthProfilesStore::new(dir.path(), false);
        assert_eq!(store.real_path(), dir.path().join("auth-profiles.json"));
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn refresh_lock_shared_contended_and_released() {
        let shared = tempfile::tempdir().unwrap();
        let u1 = tempfile::tempdir().unwrap();
        let u2 = tempfile::tempdir().unwrap();
        let shared_file = shared.path().join("auth-profiles.json");
        std::fs::write(&shared_file, b"{}").unwrap();
        std::os::unix::fs::symlink(&shared_file, u1.path().join("auth-profiles.json")).unwrap();
        std::os::unix::fs::symlink(&shared_file, u2.path().join("auth-profiles.json")).unwrap();

        let s1 = AuthProfilesStore::new(u1.path(), false);
        let s2 = AuthProfilesStore::new(u2.path(), false);
        // both daemons resolve to the SAME lock inode
        assert_eq!(s1.refresh_lock_path(), s2.refresh_lock_path());

        let g = s1.acquire_refresh_lock().await.unwrap();
        // While s1 holds it, s2 cannot acquire. acquire_refresh_lock's OWN timeout
        // is 20s, so we bound the wait with an EXTERNAL tokio::time::timeout — Err
        // here comes from that outer timeout, proving s2 is blocked.
        let blocked = tokio::time::timeout(
            std::time::Duration::from_millis(300),
            s2.acquire_refresh_lock(),
        )
        .await;
        assert!(blocked.is_err(), "s2 must block while s1 holds the flock");

        // After s1 releases (Drop closes fd → kernel releases flock), s2 acquires fast.
        drop(g);
        let g2 = tokio::time::timeout(std::time::Duration::from_secs(2), s2.acquire_refresh_lock())
            .await
            .expect("must not time out")
            .expect("must acquire after release");
        drop(g2);
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn store_lock_shared_contended_and_released() {
        let shared = tempfile::tempdir().unwrap();
        let u1 = tempfile::tempdir().unwrap();
        let u2 = tempfile::tempdir().unwrap();
        let shared_file = shared.path().join("auth-profiles.json");
        std::fs::write(&shared_file, b"{}").unwrap();
        std::os::unix::fs::symlink(&shared_file, u1.path().join("auth-profiles.json")).unwrap();
        std::os::unix::fs::symlink(&shared_file, u2.path().join("auth-profiles.json")).unwrap();

        let s1 = AuthProfilesStore::new(u1.path(), false);
        let s2 = AuthProfilesStore::new(u2.path(), false);
        // both daemons resolve to the SAME store-lock inode
        assert_eq!(s1.store_lock_path(), s2.store_lock_path());

        let g = s1.acquire_lock().await.unwrap();
        // While s1 holds it, s2 blocks. Bound the wait with an EXTERNAL timeout;
        // Err here proves s2 is blocked (acquire_lock's own timeout is 10s).
        let blocked =
            tokio::time::timeout(std::time::Duration::from_millis(300), s2.acquire_lock()).await;
        assert!(blocked.is_err(), "s2 must block while s1 holds the store flock");

        // After s1 releases (Drop closes fd → kernel releases flock), s2 acquires fast.
        drop(g);
        let g2 = tokio::time::timeout(std::time::Duration::from_secs(2), s2.acquire_lock())
            .await
            .expect("must not time out")
            .expect("must acquire after release");
        drop(g2);
    }

    // Regression for DV-34312 (2026-07-14): the old O_EXCL lock left an orphaned
    // `auth-profiles.lock` FILE behind on process death, bricking every
    // subsequent acquire for ~6h. flock keys on kernel advisory state, not file
    // existence, so a leftover lock file must NOT block acquisition.
    #[cfg(unix)]
    #[tokio::test]
    async fn store_lock_not_bricked_by_leftover_lock_file() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("auth-profiles.json"), b"{}").unwrap();
        let store = AuthProfilesStore::new(dir.path(), false);
        // Simulate the orphan: a 0-byte lock file left by a dead holder.
        std::fs::write(store.store_lock_path(), b"").unwrap();

        let g = tokio::time::timeout(std::time::Duration::from_secs(1), store.acquire_lock())
            .await
            .expect("must not brick on a leftover lock file")
            .expect("must acquire despite leftover file");
        drop(g);
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn upsert_through_symlink_preserves_link_and_updates_shared() {
        let shared = tempfile::tempdir().unwrap();
        let user = tempfile::tempdir().unwrap();
        let shared_file = shared.path().join("auth-profiles.json");
        std::fs::write(&shared_file, b"{\"schema_version\":1,\"profiles\":{}}").unwrap();
        std::os::unix::fs::symlink(&shared_file, user.path().join("auth-profiles.json")).unwrap();

        let store = AuthProfilesStore::new(user.path(), false);
        let profile = AuthProfile::new_token("openai-codex", "default", "tok123".into());
        store.upsert_profile(profile, true).await.unwrap();

        // per-user path STILL a symlink
        assert!(
            std::fs::symlink_metadata(user.path().join("auth-profiles.json"))
                .unwrap()
                .file_type()
                .is_symlink()
        );
        // shared file actually updated (contains the profile)
        let body = std::fs::read_to_string(&shared_file).unwrap();
        assert!(body.contains("openai-codex"));
    }

    #[test]
    fn profile_id_format() {
        assert_eq!(
            profile_id("openai-codex", "default"),
            "openai-codex:default"
        );
    }

    #[test]
    fn token_expiry_math() {
        let token_set = TokenSet {
            access_token: "token".into(),
            refresh_token: Some("refresh".into()),
            id_token: None,
            expires_at: Some(Utc::now() + chrono::Duration::seconds(10)),
            token_type: Some("Bearer".into()),
            scope: None,
        };

        assert!(token_set.is_expiring_within(Duration::from_secs(15)));
        assert!(!token_set.is_expiring_within(Duration::from_secs(1)));
    }

    #[tokio::test]
    async fn store_roundtrip_with_encryption() {
        let tmp = TempDir::new().unwrap();
        let store = AuthProfilesStore::new(tmp.path(), true);

        let mut profile = AuthProfile::new_oauth(
            "openai-codex",
            "default",
            TokenSet {
                access_token: "access-123".into(),
                refresh_token: Some("refresh-123".into()),
                id_token: None,
                expires_at: Some(Utc::now() + chrono::Duration::hours(1)),
                token_type: Some("Bearer".into()),
                scope: Some("openid offline_access".into()),
            },
        );
        profile.account_id = Some("acct_123".into());

        store.upsert_profile(profile.clone(), true).await.unwrap();

        let data = store.load().await.unwrap();
        let loaded = data.profiles.get(&profile.id).unwrap();

        assert_eq!(loaded.model_provider, "openai-codex");
        assert_eq!(loaded.profile_name, "default");
        assert_eq!(loaded.account_id.as_deref(), Some("acct_123"));
        assert_eq!(
            loaded
                .token_set
                .as_ref()
                .and_then(|t| t.refresh_token.as_deref()),
            Some("refresh-123")
        );

        let raw = tokio::fs::read_to_string(store.path()).await.unwrap();
        assert!(raw.contains("enc2:"));
        assert!(!raw.contains("refresh-123"));
        assert!(!raw.contains("access-123"));
    }

    #[tokio::test]
    async fn loads_pre_v080_store_with_legacy_provider_field() {
        // fork regression (patch #12): stores written before the upstream
        // v0.8.0 `provider` → `model_provider` rename must keep loading.
        let tmp = TempDir::new().unwrap();
        let legacy = r#"{
  "schema_version": 1,
  "updated_at": "2026-05-29T16:05:01Z",
  "active_profiles": { "openai-codex": "openai-codex:default" },
  "profiles": {
    "openai-codex:default": {
      "provider": "openai-codex",
      "profile_name": "default",
      "kind": "oauth",
      "access_token": "plain-access",
      "refresh_token": "plain-refresh",
      "expires_at": "2026-06-08T16:05:00Z",
      "token_type": "bearer",
      "scope": "openid offline_access",
      "created_at": "2026-05-29T16:05:01Z",
      "updated_at": "2026-05-29T16:05:01Z",
      "metadata": {}
    }
  }
}"#;
        tokio::fs::write(tmp.path().join("auth-profiles.json"), legacy)
            .await
            .unwrap();

        let store = AuthProfilesStore::new(tmp.path(), false);
        let data = store.load().await.unwrap();
        let loaded = data.profiles.get("openai-codex:default").unwrap();
        assert_eq!(loaded.model_provider, "openai-codex");
        assert_eq!(
            loaded
                .token_set
                .as_ref()
                .and_then(|t| t.refresh_token.as_deref()),
            Some("plain-refresh")
        );
    }

    #[tokio::test]
    async fn atomic_write_replaces_file() {
        let tmp = TempDir::new().unwrap();
        let store = AuthProfilesStore::new(tmp.path(), false);

        let profile = AuthProfile::new_token("anthropic", "default", "token-abc".into());
        store.upsert_profile(profile, true).await.unwrap();

        let path = store.path().to_path_buf();
        assert!(path.exists());

        let contents = tokio::fs::read_to_string(path).await.unwrap();
        assert!(contents.contains("\"schema_version\": 1"));
    }
}
