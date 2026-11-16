use std::collections::HashMap;
use std::fs::{FileTimes, Permissions};
use std::io;
use std::os::unix::fs::{FileExt, MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::string::{String, ToString};
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use std::vec::Vec;

use cap_fs_ext::{DirExt, SystemTimeSpec};
use cap_std::fs::Dir;
use russh_sftp::protocol::{
    Attrs, Data, File, FileAttributes, Handle, Name, OpenFlags, Packet, Status, StatusCode, Version,
};
use russh_sftp::server::StatusReply;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::sync::oneshot;

const READDIR_BATCH: usize = 100;
const HARDLINK_EXTENSION: &str = "hardlink@openssh.com";

/// What a rooted SFTP file service lets clients do.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum FileServeMode {
    /// Clients can list, stat and download files, but not modify anything.
    #[default]
    ReadOnly,
    ReadWrite,
    /// A flat drop box. Each upload is stored under a new, server-chosen
    /// name, so clients cannot use name collisions to discover existing
    /// files. Clients cannot make directories, list, or read anything back.
    WriteOnly,
    /// A recursive drop box. Clients can make and stat directories, which
    /// reveals whether some paths exist. An upload keeps its requested name
    /// when that is free and is stored under a server-chosen name otherwise.
    WriteOnlyPlus,
}

/// A rooted SFTP file service. Every client path resolves inside `dir`, so
/// neither `..` nor a symlink can escape it.
#[derive(Clone, Debug)]
pub struct FileService {
    pub dir: PathBuf,
    pub mode: FileServeMode,
}

enum Root {
    Rooted(Dir),
    Full(PathBuf),
}

pub(crate) struct Files {
    root: Root,
    mode: FileServeMode,
}

struct Metadata {
    attrs: FileAttributes,
    is_dir: bool,
}

fn to_attrs(m: &impl MetadataLike) -> Metadata {
    Metadata {
        attrs: FileAttributes {
            size: Some(m.size()),
            uid: Some(m.uid()),
            user: None,
            gid: Some(m.gid()),
            group: None,
            permissions: Some(m.mode()),
            atime: Some(u32::try_from(m.atime()).unwrap_or(0)),
            mtime: Some(u32::try_from(m.mtime()).unwrap_or(0)),
        },
        is_dir: m.mode() & 0o170_000 == 0o040_000,
    }
}

trait MetadataLike {
    fn size(&self) -> u64;
    fn uid(&self) -> u32;
    fn gid(&self) -> u32;
    fn mode(&self) -> u32;
    fn atime(&self) -> i64;
    fn mtime(&self) -> i64;
}

macro_rules! metadata_like {
    ($ty:ty, $ext:path) => {
        impl MetadataLike for $ty {
            fn size(&self) -> u64 {
                <$ty as $ext>::size(self)
            }
            fn uid(&self) -> u32 {
                <$ty as $ext>::uid(self)
            }
            fn gid(&self) -> u32 {
                <$ty as $ext>::gid(self)
            }
            fn mode(&self) -> u32 {
                <$ty as $ext>::mode(self)
            }
            fn atime(&self) -> i64 {
                <$ty as $ext>::atime(self)
            }
            fn mtime(&self) -> i64 {
                <$ty as $ext>::mtime(self)
            }
        }
    };
}

metadata_like!(std::fs::Metadata, MetadataExt);
metadata_like!(cap_std::fs::Metadata, cap_std::fs::MetadataExt);

impl Files {
    pub(crate) fn open(service: Option<&FileService>) -> io::Result<Files> {
        Ok(match service {
            Some(s) => Files {
                root: Root::Rooted(Dir::open_ambient_dir(&s.dir, cap_std::ambient_authority())?),
                mode: s.mode,
            },
            None => Files {
                root: Root::Full(std::env::home_dir().unwrap_or_else(|| PathBuf::from("/"))),
                mode: FileServeMode::ReadWrite,
            },
        })
    }

    fn write_only(&self) -> bool {
        matches!(
            self.mode,
            FileServeMode::WriteOnly | FileServeMode::WriteOnlyPlus
        )
    }

    fn full(home: &Path, p: &str) -> PathBuf {
        home.join(p)
    }

    fn open_file(&self, p: &str, m: OpenFlags) -> io::Result<std::fs::File> {
        match &self.root {
            Root::Rooted(dir) => {
                let mut o = cap_std::fs::OpenOptions::new();
                o.read(m.contains(OpenFlags::READ))
                    .write(m.contains(OpenFlags::WRITE))
                    .append(m.contains(OpenFlags::APPEND))
                    .truncate(m.contains(OpenFlags::TRUNCATE));
                if m.contains(OpenFlags::EXCLUDE) {
                    o.create_new(true);
                } else {
                    o.create(m.contains(OpenFlags::CREATE));
                }
                cap_std::fs::OpenOptionsExt::mode(&mut o, 0o644);
                Ok(dir.open_with(p, &o)?.into_std())
            }
            Root::Full(home) => {
                let mut o = std::fs::OpenOptions::new();
                o.read(m.contains(OpenFlags::READ))
                    .write(m.contains(OpenFlags::WRITE))
                    .append(m.contains(OpenFlags::APPEND))
                    .truncate(m.contains(OpenFlags::TRUNCATE))
                    .mode(0o644);
                if m.contains(OpenFlags::EXCLUDE) {
                    o.create_new(true);
                } else {
                    o.create(m.contains(OpenFlags::CREATE));
                }
                o.open(Self::full(home, p))
            }
        }
    }

    fn metadata(&self, p: &str, follow: bool) -> io::Result<Metadata> {
        match &self.root {
            Root::Rooted(dir) if follow => dir.metadata(p).map(|m| to_attrs(&m)),
            Root::Rooted(dir) => dir.symlink_metadata(p).map(|m| to_attrs(&m)),
            Root::Full(home) if follow => {
                std::fs::metadata(Self::full(home, p)).map(|m| to_attrs(&m))
            }
            Root::Full(home) => {
                std::fs::symlink_metadata(Self::full(home, p)).map(|m| to_attrs(&m))
            }
        }
    }

    fn read_dir(&self, p: &str) -> io::Result<Vec<File>> {
        let mut files = Vec::new();
        match &self.root {
            Root::Rooted(dir) => {
                for entry in dir.read_dir(p)? {
                    let entry = entry?;
                    let meta = to_attrs(&entry.metadata()?);
                    files.push(File::new(entry.file_name().to_string_lossy(), meta.attrs));
                }
            }
            Root::Full(home) => {
                for entry in std::fs::read_dir(Self::full(home, p))? {
                    let entry = entry?;
                    let meta = to_attrs(&entry.metadata()?);
                    files.push(File::new(entry.file_name().to_string_lossy(), meta.attrs));
                }
            }
        }
        Ok(files)
    }

    fn mkdir(&self, p: &str) -> io::Result<()> {
        match &self.root {
            Root::Rooted(dir) => {
                let mut b = cap_std::fs::DirBuilder::new();
                cap_std::fs::DirBuilderExt::mode(&mut b, 0o755);
                dir.create_dir_with(p, &b)
            }
            Root::Full(home) => {
                let mut b = std::fs::DirBuilder::new();
                std::os::unix::fs::DirBuilderExt::mode(&mut b, 0o755);
                b.create(Self::full(home, p))
            }
        }
    }

    fn remove(&self, p: &str) -> io::Result<()> {
        let (file, dir) = match &self.root {
            Root::Rooted(d) => (d.remove_file(p), d.remove_dir(p)),
            Root::Full(home) => (
                std::fs::remove_file(Self::full(home, p)),
                std::fs::remove_dir(Self::full(home, p)),
            ),
        };
        match (file, dir) {
            (Ok(()), _) | (_, Ok(())) => Ok(()),
            (Err(e), Err(d)) if d.kind() == io::ErrorKind::NotADirectory => Err(e),
            (_, Err(d)) => Err(d),
        }
    }

    fn rename(&self, from: &str, to: &str) -> io::Result<()> {
        match &self.root {
            Root::Rooted(dir) => dir.rename(from, dir, to),
            Root::Full(home) => std::fs::rename(Self::full(home, from), Self::full(home, to)),
        }
    }

    fn symlink(&self, target: &str, link: &str) -> io::Result<()> {
        match &self.root {
            Root::Rooted(dir) => dir.symlink_contents(target, link),
            Root::Full(home) => std::os::unix::fs::symlink(target, Self::full(home, link)),
        }
    }

    fn hard_link(&self, from: &str, to: &str) -> io::Result<()> {
        match &self.root {
            Root::Rooted(dir) => dir.hard_link(from, dir, to),
            Root::Full(home) => std::fs::hard_link(Self::full(home, from), Self::full(home, to)),
        }
    }

    fn read_link(&self, p: &str) -> io::Result<String> {
        let target = match &self.root {
            Root::Rooted(dir) => dir.read_link_contents(p)?,
            Root::Full(home) => std::fs::read_link(Self::full(home, p))?,
        };
        Ok(target.to_string_lossy().into_owned())
    }

    fn setstat(&self, p: &str, attrs: &FileAttributes) -> io::Result<()> {
        if let Some(mode) = attrs.permissions {
            let perm = Permissions::from_mode(mode & 0o777);
            match &self.root {
                Root::Rooted(dir) => {
                    dir.set_permissions(p, cap_std::fs::Permissions::from_std(perm))?;
                }
                Root::Full(home) => std::fs::set_permissions(Self::full(home, p), perm)?,
            }
        }
        if let (Some(atime), Some(mtime)) = (attrs.atime, attrs.mtime) {
            let atime = UNIX_EPOCH + Duration::from_secs(atime.into());
            let mtime = UNIX_EPOCH + Duration::from_secs(mtime.into());
            match &self.root {
                Root::Rooted(dir) => dir.set_times(
                    p,
                    Some(SystemTimeSpec::Absolute(
                        cap_std::time::SystemTime::from_std(atime),
                    )),
                    Some(SystemTimeSpec::Absolute(
                        cap_std::time::SystemTime::from_std(mtime),
                    )),
                )?,
                Root::Full(home) => std::fs::File::open(Self::full(home, p))?
                    .set_times(FileTimes::new().set_accessed(atime).set_modified(mtime))?,
            }
        }
        if let Some(size) = attrs.size {
            self.open_file(p, OpenFlags::WRITE)?.set_len(size)?;
        }
        Ok(())
    }
}

/// Converts a request path to one relative to the root, the way an SFTP
/// request server does: relative to `/`, cleaned lexically so `..` stops at
/// the root, and `.` for the root itself.
fn rel(request: &str) -> String {
    let mut parts: Vec<&str> = Vec::new();
    for part in request.split('/') {
        match part {
            "" | "." => {}
            ".." => {
                parts.pop();
            }
            p => parts.push(p),
        }
    }
    if parts.is_empty() {
        ".".into()
    } else {
        parts.join("/")
    }
}

fn utc_stamp(now: SystemTime) -> String {
    let secs = now.duration_since(UNIX_EPOCH).unwrap_or_default().as_secs();
    let days = i64::try_from(secs / 86_400).unwrap_or(0);
    let rem = secs % 86_400;
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = yoe + era * 400 + i64::from(month <= 2);
    std::format!(
        "{year:04}{month:02}{day:02}{:02}{:02}{:02}",
        rem / 3_600,
        rem % 3_600 / 60,
        rem % 60
    )
}

fn unique_upload_path(requested: &str) -> String {
    let random: [u8; 8] = rand::random();
    let (dir, base) = match requested.rsplit_once('/') {
        Some((d, b)) => (Some(d), b),
        None => (None, requested),
    };
    let (stem, ext) = match base.rfind('.') {
        Some(i) => base.split_at(i),
        None => (base, ""),
    };
    let unique = std::format!(
        "{stem}.{}.{}{ext}",
        utc_stamp(SystemTime::now()),
        hex::encode(random)
    );
    match dir {
        Some(d) => std::format!("{d}/{unique}"),
        None => unique,
    }
}

fn status(e: &io::Error) -> StatusReply {
    let code = match e.kind() {
        io::ErrorKind::NotFound => StatusCode::NoSuchFile,
        io::ErrorKind::PermissionDenied => StatusCode::PermissionDenied,
        _ => StatusCode::Failure,
    };
    code.with_message(e.to_string())
}

fn ok(id: u32) -> Status {
    Status {
        id,
        status_code: StatusCode::Ok,
        error_message: "Ok".into(),
        language_tag: "en-US".into(),
    }
}

async fn blocking<T, F>(files: &Arc<Files>, f: F) -> Result<T, StatusReply>
where
    T: Send + 'static,
    F: FnOnce(&Files) -> io::Result<T> + Send + 'static,
{
    let files = files.clone();
    tokio::task::spawn_blocking(move || f(&files))
        .await
        .map_err(|e| StatusCode::Failure.with_message(e.to_string()))?
        .map_err(|e| status(&e))
}

enum OpenHandle {
    File {
        file: Arc<std::fs::File>,
        path: String,
    },
    Dir {
        path: String,
        listed: Option<std::vec::IntoIter<File>>,
    },
}

struct Session {
    files: Arc<Files>,
    handles: HashMap<String, OpenHandle>,
    next_handle: u64,
    wrote: HashMap<String, String>,
    _done: oneshot::Sender<()>,
}

impl Session {
    fn own_path(&self, p: &str) -> Option<String> {
        self.wrote.get(p).cloned()
    }

    async fn visible_stat(&self, p: String, follow: bool) -> Result<FileAttributes, StatusReply> {
        if !self.files.write_only() {
            return blocking(&self.files, move |f| f.metadata(&p, follow))
                .await
                .map(|m| m.attrs);
        }
        if let Some(actual) = self.own_path(&p) {
            return blocking(&self.files, move |f| f.metadata(&actual, follow))
                .await
                .map(|m| m.attrs);
        }
        if self.files.mode == FileServeMode::WriteOnly && p != "." {
            return Err(StatusCode::NoSuchFile.into());
        }
        match blocking(&self.files, move |f| f.metadata(&p, follow)).await {
            Ok(m) if m.is_dir => Ok(m.attrs),
            _ => Err(StatusCode::NoSuchFile.into()),
        }
    }

    fn add_handle(&mut self, h: OpenHandle) -> String {
        self.next_handle += 1;
        let name = self.next_handle.to_string();
        self.handles.insert(name.clone(), h);
        name
    }

    async fn open_write(
        &mut self,
        p: String,
        flags: OpenFlags,
    ) -> Result<std::fs::File, StatusReply> {
        let mode = self.files.mode;
        if mode == FileServeMode::ReadOnly {
            return Err(StatusCode::PermissionDenied.into());
        }
        if !self.files.write_only() {
            let m = flags | OpenFlags::WRITE;
            return blocking(&self.files, move |f| f.open_file(&p, m)).await;
        }
        if flags.contains(OpenFlags::READ)
            || !flags.contains(OpenFlags::WRITE)
            || !flags.contains(OpenFlags::CREATE)
        {
            return Err(StatusCode::PermissionDenied.into());
        }
        if mode == FileServeMode::WriteOnly && (p == "." || p.contains('/')) {
            return Err(StatusCode::PermissionDenied.into());
        }
        let requested = p.clone();
        let (file, actual) = blocking(&self.files, move |f| {
            let m = OpenFlags::WRITE | OpenFlags::CREATE | OpenFlags::EXCLUDE;
            let first = if mode == FileServeMode::WriteOnly {
                unique_upload_path(&p)
            } else {
                p.clone()
            };
            match f.open_file(&first, m) {
                Err(e)
                    if mode == FileServeMode::WriteOnlyPlus
                        && e.kind() == io::ErrorKind::AlreadyExists =>
                {
                    let actual = unique_upload_path(&p);
                    Ok((f.open_file(&actual, m)?, actual))
                }
                r => Ok((r?, first)),
            }
        })
        .await?;
        self.wrote.insert(requested, actual);
        Ok(file)
    }

    async fn setstat_path(&self, p: String, attrs: FileAttributes) -> Result<(), StatusReply> {
        let target = match self.files.mode {
            FileServeMode::ReadOnly => return Err(StatusCode::PermissionDenied.into()),
            FileServeMode::ReadWrite => p,
            FileServeMode::WriteOnly | FileServeMode::WriteOnlyPlus => {
                self.own_path(&p).ok_or(StatusCode::PermissionDenied)?
            }
        };
        blocking(&self.files, move |f| f.setstat(&target, &attrs)).await
    }

    fn require_rw(&self) -> Result<(), StatusReply> {
        if self.files.mode == FileServeMode::ReadWrite {
            Ok(())
        } else {
            Err(StatusCode::PermissionDenied.into())
        }
    }

    fn path(&self, request: &str) -> String {
        match &self.files.root {
            Root::Rooted(_) => rel(request),
            Root::Full(_) if request.is_empty() => ".".into(),
            Root::Full(_) => request.into(),
        }
    }
}

fn read_strings(mut data: &[u8]) -> Option<Vec<String>> {
    let mut out = Vec::new();
    while !data.is_empty() {
        let (len, rest) = data.split_first_chunk::<4>()?;
        let len = usize::try_from(u32::from_be_bytes(*len)).ok()?;
        if rest.len() < len {
            return None;
        }
        out.push(String::from_utf8_lossy(&rest[..len]).into_owned());
        data = &rest[len..];
    }
    Some(out)
}

impl russh_sftp::server::Handler for Session {
    type Error = StatusReply;

    fn unimplemented(&self) -> StatusReply {
        StatusCode::OpUnsupported.into()
    }

    async fn init(
        &mut self,
        _version: u32,
        _extensions: HashMap<String, String>,
    ) -> Result<Version, StatusReply> {
        let mut v = Version::new();
        v.extensions.insert(HARDLINK_EXTENSION.into(), "1".into());
        Ok(v)
    }

    async fn open(
        &mut self,
        id: u32,
        filename: String,
        pflags: OpenFlags,
        _attrs: FileAttributes,
    ) -> Result<Handle, StatusReply> {
        let p = self.path(&filename);
        let file = if pflags.intersects(OpenFlags::WRITE | OpenFlags::APPEND) {
            self.open_write(p.clone(), pflags).await?
        } else {
            if self.files.write_only() {
                return Err(StatusCode::PermissionDenied.into());
            }
            let q = p.clone();
            blocking(&self.files, move |f| f.open_file(&q, OpenFlags::READ)).await?
        };
        let handle = self.add_handle(OpenHandle::File {
            file: Arc::new(file),
            path: p,
        });
        Ok(Handle { id, handle })
    }

    async fn close(&mut self, id: u32, handle: String) -> Result<Status, StatusReply> {
        self.handles.remove(&handle).ok_or(StatusCode::Failure)?;
        Ok(ok(id))
    }

    async fn read(
        &mut self,
        id: u32,
        handle: String,
        offset: u64,
        len: u32,
    ) -> Result<Data, StatusReply> {
        let Some(OpenHandle::File { file, .. }) = self.handles.get(&handle) else {
            return Err(StatusCode::Failure.into());
        };
        let file = file.clone();
        let data = blocking(&self.files, move |_| {
            let mut buf = std::vec![0; len.min(1 << 20) as usize];
            let n = file.read_at(&mut buf, offset)?;
            buf.truncate(n);
            Ok(buf)
        })
        .await?;
        if data.is_empty() {
            return Err(StatusCode::Eof.into());
        }
        Ok(Data { id, data })
    }

    async fn write(
        &mut self,
        id: u32,
        handle: String,
        offset: u64,
        data: Vec<u8>,
    ) -> Result<Status, StatusReply> {
        let Some(OpenHandle::File { file, .. }) = self.handles.get(&handle) else {
            return Err(StatusCode::Failure.into());
        };
        let file = file.clone();
        blocking(&self.files, move |_| file.write_all_at(&data, offset)).await?;
        Ok(ok(id))
    }

    async fn lstat(&mut self, id: u32, path: String) -> Result<Attrs, StatusReply> {
        let attrs = self.visible_stat(self.path(&path), false).await?;
        Ok(Attrs { id, attrs })
    }

    async fn stat(&mut self, id: u32, path: String) -> Result<Attrs, StatusReply> {
        let attrs = self.visible_stat(self.path(&path), true).await?;
        Ok(Attrs { id, attrs })
    }

    async fn fstat(&mut self, id: u32, handle: String) -> Result<Attrs, StatusReply> {
        let Some(OpenHandle::File { file, .. }) = self.handles.get(&handle) else {
            return Err(StatusCode::Failure.into());
        };
        let file = file.clone();
        let meta = blocking(&self.files, move |_| file.metadata().map(|m| to_attrs(&m))).await?;
        Ok(Attrs {
            id,
            attrs: meta.attrs,
        })
    }

    async fn setstat(
        &mut self,
        id: u32,
        path: String,
        attrs: FileAttributes,
    ) -> Result<Status, StatusReply> {
        self.setstat_path(self.path(&path), attrs).await?;
        Ok(ok(id))
    }

    async fn fsetstat(
        &mut self,
        id: u32,
        handle: String,
        attrs: FileAttributes,
    ) -> Result<Status, StatusReply> {
        let path = match self.handles.get(&handle) {
            Some(OpenHandle::File { path, .. } | OpenHandle::Dir { path, .. }) => path.clone(),
            None => return Err(StatusCode::Failure.into()),
        };
        self.setstat_path(path, attrs).await?;
        Ok(ok(id))
    }

    async fn opendir(&mut self, id: u32, path: String) -> Result<Handle, StatusReply> {
        let p = self.path(&path);
        let attrs = self.visible_stat(p.clone(), true).await?;
        if !attrs.is_dir() {
            return Err(StatusCode::Failure.with_message("not a directory"));
        }
        let handle = self.add_handle(OpenHandle::Dir {
            path: p,
            listed: None,
        });
        Ok(Handle { id, handle })
    }

    async fn readdir(&mut self, id: u32, handle: String) -> Result<Name, StatusReply> {
        let write_only = self.files.write_only();
        let files = self.files.clone();
        let Some(OpenHandle::Dir { path, listed }) = self.handles.get_mut(&handle) else {
            return Err(StatusCode::Failure.into());
        };
        if write_only {
            return Err(StatusCode::PermissionDenied.into());
        }
        if listed.is_none() {
            let p = path.clone();
            *listed = Some(blocking(&files, move |f| f.read_dir(&p)).await?.into_iter());
        }
        let batch: Vec<File> = listed
            .as_mut()
            .into_iter()
            .flatten()
            .take(READDIR_BATCH)
            .collect();
        if batch.is_empty() {
            return Err(StatusCode::Eof.into());
        }
        Ok(Name { id, files: batch })
    }

    async fn remove(&mut self, id: u32, filename: String) -> Result<Status, StatusReply> {
        self.require_rw()?;
        let p = self.path(&filename);
        blocking(&self.files, move |f| f.remove(&p)).await?;
        Ok(ok(id))
    }

    async fn rmdir(&mut self, id: u32, path: String) -> Result<Status, StatusReply> {
        self.remove(id, path).await
    }

    async fn mkdir(
        &mut self,
        id: u32,
        path: String,
        _attrs: FileAttributes,
    ) -> Result<Status, StatusReply> {
        let p = self.path(&path);
        match self.files.mode {
            FileServeMode::ReadOnly | FileServeMode::WriteOnly => {
                return Err(StatusCode::PermissionDenied.into());
            }
            FileServeMode::ReadWrite | FileServeMode::WriteOnlyPlus => {}
        }
        let q = p.clone();
        blocking(&self.files, move |f| f.mkdir(&q)).await?;
        if self.files.mode == FileServeMode::WriteOnlyPlus {
            self.wrote.insert(p.clone(), p);
        }
        Ok(ok(id))
    }

    async fn realpath(&mut self, id: u32, path: String) -> Result<Name, StatusReply> {
        let path = match &self.files.root {
            Root::Rooted(_) => path,
            Root::Full(home) => home.join(path).to_string_lossy().into_owned(),
        };
        let resolved = match rel(&path).as_str() {
            "." => "/".into(),
            p => std::format!("/{p}"),
        };
        Ok(Name {
            id,
            files: std::vec![File::dummy(resolved)],
        })
    }

    async fn rename(
        &mut self,
        id: u32,
        oldpath: String,
        newpath: String,
    ) -> Result<Status, StatusReply> {
        self.require_rw()?;
        let (from, to) = (self.path(&oldpath), self.path(&newpath));
        blocking(&self.files, move |f| f.rename(&from, &to)).await?;
        Ok(ok(id))
    }

    async fn readlink(&mut self, id: u32, path: String) -> Result<Name, StatusReply> {
        if self.files.write_only() {
            return Err(StatusCode::PermissionDenied.into());
        }
        let p = self.path(&path);
        let target = blocking(&self.files, move |f| f.read_link(&p)).await?;
        Ok(Name {
            id,
            files: std::vec![File::dummy(target)],
        })
    }

    async fn symlink(
        &mut self,
        id: u32,
        linkpath: String,
        targetpath: String,
    ) -> Result<Status, StatusReply> {
        self.require_rw()?;
        let link = self.path(&targetpath);
        blocking(&self.files, move |f| f.symlink(&linkpath, &link)).await?;
        Ok(ok(id))
    }

    async fn extended(
        &mut self,
        id: u32,
        request: String,
        data: Vec<u8>,
    ) -> Result<Packet, StatusReply> {
        if request != HARDLINK_EXTENSION {
            return Err(StatusCode::OpUnsupported.into());
        }
        self.require_rw()?;
        let Some([from, to]) = read_strings(&data).and_then(|v| <[String; 2]>::try_from(v).ok())
        else {
            return Err(StatusCode::BadMessage.into());
        };
        let (from, to) = (self.path(&from), self.path(&to));
        blocking(&self.files, move |f| f.hard_link(&from, &to)).await?;
        Ok(Packet::Status(ok(id)))
    }
}

/// Serves one SFTP session on `stream` and returns once it ends.
pub(crate) async fn serve<S>(stream: S, files: Files)
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let (done, ended) = oneshot::channel();
    let session = Session {
        files: Arc::new(files),
        handles: HashMap::new(),
        next_handle: 0,
        wrote: HashMap::new(),
        _done: done,
    };
    russh_sftp::server::run(stream, session).await;
    let _ = ended.await;
}

#[cfg(test)]
mod tests {
    use std::fs;

    use russh_sftp::client::SftpSession;
    use russh_sftp::client::error::Error as ClientError;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    use super::*;

    fn serve_dir() -> (tempfile::TempDir, tempfile::TempDir) {
        let dir = tempfile::tempdir().unwrap();
        let outside = tempfile::tempdir().unwrap();
        fs::write(dir.path().join("existing.txt"), "existing content").unwrap();
        fs::create_dir(dir.path().join("sub")).unwrap();
        fs::write(dir.path().join("sub/inner.txt"), "inner").unwrap();
        let secret = outside.path().join("secret.txt");
        fs::write(&secret, "secret").unwrap();
        std::os::unix::fs::symlink(&secret, dir.path().join("escape")).unwrap();
        std::os::unix::fs::symlink(
            "../../../../../../../../etc",
            dir.path().join("relative-escape"),
        )
        .unwrap();
        (dir, outside)
    }

    async fn client(dir: &Path, mode: FileServeMode) -> SftpSession {
        let (a, b) = tokio::io::duplex(1 << 20);
        let files = Files::open(Some(&FileService {
            dir: dir.into(),
            mode,
        }))
        .unwrap();
        tokio::spawn(serve(a, files));
        SftpSession::new(b).await.unwrap()
    }

    async fn read_file(c: &SftpSession, name: &str) -> Result<String, ClientError> {
        let mut f = c.open(name).await?;
        let mut s = String::new();
        f.read_to_string(&mut s)
            .await
            .map_err(|e| ClientError::UnexpectedBehavior(e.to_string()))?;
        Ok(s)
    }

    async fn write_file(c: &SftpSession, name: &str, content: &str) -> Result<(), ClientError> {
        let mut f = c
            .open_with_flags(
                name,
                OpenFlags::WRITE | OpenFlags::CREATE | OpenFlags::TRUNCATE,
            )
            .await?;
        f.write_all(content.as_bytes())
            .await
            .map_err(|e| ClientError::UnexpectedBehavior(e.to_string()))?;
        f.shutdown()
            .await
            .map_err(|e| ClientError::UnexpectedBehavior(e.to_string()))?;
        Ok(())
    }

    fn code(r: Result<impl std::fmt::Debug, ClientError>) -> StatusCode {
        match r {
            Err(ClientError::Status(s)) => s.status_code,
            other => panic!("want a status error, got {other:?}"),
        }
    }

    fn attrs_with_mode(mode: u32) -> FileAttributes {
        FileAttributes {
            permissions: Some(mode),
            ..FileAttributes::empty()
        }
    }

    fn drop_names(dir: &Path, stem: &str, ext: &str) -> Vec<String> {
        fs::read_dir(dir)
            .unwrap()
            .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
            .filter(|n| {
                n.strip_prefix(stem)
                    .and_then(|r| r.strip_suffix(ext))
                    .and_then(|r| r.strip_prefix('.'))
                    .and_then(|r| r.split_once('.'))
                    .is_some_and(|(ts, rnd)| {
                        ts.len() == 14
                            && ts.bytes().all(|b| b.is_ascii_digit())
                            && rnd.len() == 16
                            && rnd.bytes().all(|b| b.is_ascii_hexdigit())
                    })
            })
            .collect()
    }

    #[tokio::test]
    async fn read_only() {
        let (dir, _outside) = serve_dir();
        let c = client(dir.path(), FileServeMode::ReadOnly).await;
        assert_eq!(
            read_file(&c, "existing.txt").await.unwrap(),
            "existing content"
        );
        assert!(c.read_dir("/").await.unwrap().count() >= 2);
        assert_eq!(read_file(&c, "sub/inner.txt").await.unwrap(), "inner");
        c.metadata("existing.txt").await.unwrap();

        assert!(write_file(&c, "new.txt", "x").await.is_err());
        assert!(c.remove_file("existing.txt").await.is_err());
        assert!(c.create_dir("newdir").await.is_err());
        assert!(c.rename("existing.txt", "renamed.txt").await.is_err());
        assert!(
            c.set_metadata("existing.txt", attrs_with_mode(0o600))
                .await
                .is_err()
        );
    }

    #[tokio::test]
    async fn read_write() {
        let (dir, _outside) = serve_dir();
        let c = client(dir.path(), FileServeMode::ReadWrite).await;
        write_file(&c, "new.txt", "hello").await.unwrap();
        assert_eq!(read_file(&c, "new.txt").await.unwrap(), "hello");
        c.create_dir("newdir").await.unwrap();
        c.rename("new.txt", "newdir/moved.txt").await.unwrap();
        c.set_metadata("newdir/moved.txt", attrs_with_mode(0o600))
            .await
            .unwrap();
        let mode = fs::metadata(dir.path().join("newdir/moved.txt"))
            .unwrap()
            .permissions()
            .mode();
        assert_eq!(mode & 0o777, 0o600);
        c.remove_file("newdir/moved.txt").await.unwrap();
        c.remove_dir("newdir").await.unwrap();
    }

    #[tokio::test]
    async fn no_symlink_or_dotdot_escape() {
        let (dir, outside) = serve_dir();
        let c = client(dir.path(), FileServeMode::ReadWrite).await;
        assert!(read_file(&c, "escape").await.is_err());
        assert!(read_file(&c, "relative-escape/hosts").await.is_err());
        assert!(c.read_dir("relative-escape").await.is_err());
        assert!(read_file(&c, "../../../../etc/hosts").await.is_err());
        assert_eq!(
            read_file(&c, "/../existing.txt").await.unwrap(),
            "existing content"
        );
        c.symlink("sub", "via-link").await.unwrap();
        assert_eq!(read_file(&c, "via-link/inner.txt").await.unwrap(), "inner");
        assert!(write_file(&c, "escape", "overwrite").await.is_err());
        assert_eq!(
            fs::read_to_string(outside.path().join("secret.txt")).unwrap(),
            "secret"
        );
    }

    #[tokio::test]
    async fn write_only() {
        let (dir, _outside) = serve_dir();
        let c = client(dir.path(), FileServeMode::WriteOnly).await;
        let original = fs::metadata(dir.path().join("existing.txt"))
            .unwrap()
            .permissions()
            .mode();

        for content in ["first", "second"] {
            write_file(&c, "existing.txt", content).await.unwrap();
        }
        assert_eq!(
            fs::read_to_string(dir.path().join("existing.txt")).unwrap(),
            "existing content"
        );
        let uploaded = drop_names(dir.path(), "existing", ".txt");
        assert_eq!(uploaded.len(), 2, "{uploaded:?}");
        let mut contents: Vec<String> = uploaded
            .iter()
            .map(|n| fs::read_to_string(dir.path().join(n)).unwrap())
            .collect();
        contents.sort();
        assert_eq!(contents, ["first", "second"]);
        c.set_metadata("existing.txt", attrs_with_mode(0o600))
            .await
            .unwrap();
        assert_eq!(
            fs::metadata(dir.path().join("existing.txt"))
                .unwrap()
                .permissions()
                .mode(),
            original
        );

        for name in ["existing.txt", "absent.txt"] {
            assert_eq!(
                code(c.open_with_flags(name, OpenFlags::WRITE).await.map(|_| ())),
                StatusCode::PermissionDenied
            );
        }

        write_file(&c, "drop.txt", "dropped").await.unwrap();
        c.metadata("drop.txt").await.unwrap();
        c.set_metadata("drop.txt", attrs_with_mode(0o600))
            .await
            .unwrap();
        assert!(c.create_dir("newdir").await.is_err());
        c.metadata("/").await.unwrap();
        assert_eq!(code(c.metadata("sub").await), StatusCode::NoSuchFile);
        assert_eq!(
            code(write_file(&c, "sub/nested.txt", "nested").await),
            StatusCode::PermissionDenied
        );

        assert!(read_file(&c, "drop.txt").await.is_err());
        assert!(read_file(&c, "existing.txt").await.is_err());
        assert!(c.read_dir("/").await.is_err());
        assert!(c.remove_file("existing.txt").await.is_err());
        assert!(c.rename("existing.txt", "renamed.txt").await.is_err());

        let c2 = client(dir.path(), FileServeMode::WriteOnly).await;
        assert!(c2.metadata("drop.txt").await.is_err());
    }

    #[tokio::test]
    async fn write_only_plus() {
        let (dir, _outside) = serve_dir();
        let c = client(dir.path(), FileServeMode::WriteOnlyPlus).await;
        write_file(&c, "drop.txt", "first").await.unwrap();
        assert_eq!(
            fs::read_to_string(dir.path().join("drop.txt")).unwrap(),
            "first"
        );
        write_file(&c, "drop.txt", "second").await.unwrap();
        let collisions = drop_names(dir.path(), "drop", ".txt");
        assert_eq!(collisions.len(), 1);
        assert_eq!(
            fs::read_to_string(dir.path().join(&collisions[0])).unwrap(),
            "second"
        );

        c.metadata("sub").await.unwrap();
        c.create_dir("newdir").await.unwrap();
        write_file(&c, "newdir/nested.txt", "nested").await.unwrap();
        assert_eq!(
            fs::read_to_string(dir.path().join("newdir/nested.txt")).unwrap(),
            "nested"
        );

        assert!(c.read_dir("/").await.is_err());
        assert!(read_file(&c, "drop.txt").await.is_err());
    }

    #[test]
    fn paths_are_cleaned_beneath_the_root() {
        assert_eq!(rel("/"), ".");
        assert_eq!(rel(""), ".");
        assert_eq!(rel("."), ".");
        assert_eq!(rel("../../a/./b/../c"), "a/c");
        assert_eq!(rel("/x/../../y"), "y");
    }

    #[test]
    fn upload_names() {
        assert_eq!(
            utc_stamp(UNIX_EPOCH + Duration::from_secs(1_700_000_000)),
            "20231114221320"
        );
        let n = unique_upload_path("dir/archive.tar.gz");
        assert!(
            n.starts_with("dir/archive.tar.") && Path::new(&n).extension() == Some("gz".as_ref()),
            "{n}"
        );
        let n = unique_upload_path("noext");
        assert_eq!(n.len(), "noext".len() + 1 + 14 + 1 + 16);
    }
}
