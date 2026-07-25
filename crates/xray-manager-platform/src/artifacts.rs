use fs2::FileExt;
use std::fs::{self, File};
use std::io::{Cursor, Read};
use std::path::{Path, PathBuf};
use xray_manager_core::{ManagerError, Result};

pub fn validate_asset(bytes: &[u8], max_bytes: usize) -> Result<()> {
    if bytes.is_empty() {
        return Err(ManagerError::Download("asset is empty".into()));
    }
    if bytes.len() > max_bytes {
        return Err(ManagerError::Download("asset size limit exceeded".into()));
    }
    let prefix = String::from_utf8_lossy(&bytes[..bytes.len().min(512)])
        .trim_start()
        .to_ascii_lowercase();
    if prefix.starts_with("<!doctype")
        || prefix.starts_with("<html")
        || prefix.starts_with("<?xml")
        || prefix.starts_with('{')
        || prefix.starts_with('[')
    {
        return Err(ManagerError::Download(
            "asset resembles an error document".into(),
        ));
    }
    Ok(())
}

pub fn extract_xray_zip(
    bytes: &[u8],
    destination: &Path,
    max_extracted_bytes: u64,
) -> Result<PathBuf> {
    let mut archive = zip::ZipArchive::new(Cursor::new(bytes))
        .map_err(|error| ManagerError::Download(format!("invalid ZIP: {error}")))?;
    fs::create_dir_all(destination).map_err(|error| ManagerError::Io(error.to_string()))?;
    let output = destination.join(if cfg!(windows) { "xray.exe" } else { "xray" });
    let mut found = false;
    for index in 0..archive.len() {
        let entry = archive
            .by_index(index)
            .map_err(|error| ManagerError::Download(error.to_string()))?;
        let enclosed = entry
            .enclosed_name()
            .ok_or_else(|| ManagerError::Download("ZIP path traversal detected".into()))?;
        let expected = enclosed
            .file_name()
            .and_then(|name| name.to_str())
            .is_some_and(|name| matches!(name, "xray" | "xray.exe"));
        if !expected || entry.is_dir() {
            continue;
        }
        if entry.size() > max_extracted_bytes {
            return Err(ManagerError::Download(
                "extracted Xray executable exceeds size limit".into(),
            ));
        }
        if found {
            return Err(ManagerError::Download(
                "ZIP contains multiple Xray executables".into(),
            ));
        }
        let mut file =
            File::create(&output).map_err(|error| ManagerError::Io(error.to_string()))?;
        let copied = std::io::copy(
            &mut entry.take(max_extracted_bytes.saturating_add(1)),
            &mut file,
        )
        .map_err(|error| ManagerError::Io(error.to_string()))?;
        if copied > max_extracted_bytes {
            return Err(ManagerError::Download(
                "extracted Xray executable exceeds size limit".into(),
            ));
        }
        file.sync_all()
            .map_err(|error| ManagerError::Io(error.to_string()))?;
        found = true;
    }
    if !found {
        return Err(ManagerError::Download(
            "ZIP does not contain an Xray executable".into(),
        ));
    }
    set_executable(&output)?;
    Ok(output)
}

pub struct OperationLock {
    file: File,
}

impl OperationLock {
    pub fn acquire(path: &Path) -> Result<Self> {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).map_err(|error| ManagerError::Io(error.to_string()))?;
        }
        let file = File::options()
            .create(true)
            .read(true)
            .write(true)
            .truncate(false)
            .open(path)
            .map_err(|error| ManagerError::Io(error.to_string()))?;
        file.try_lock_exclusive()
            .map_err(|_| ManagerError::LockContention)?;
        Ok(Self { file })
    }
}

impl Drop for OperationLock {
    fn drop(&mut self) {
        let _ = FileExt::unlock(&self.file);
    }
}

impl xray_manager_core::ports::FileLockGuard for OperationLock {}

#[cfg(unix)]
fn set_executable(path: &Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(path, fs::Permissions::from_mode(0o755))
        .map_err(|error| ManagerError::Io(error.to_string()))
}

#[cfg(not(unix))]
fn set_executable(_path: &Path) -> Result<()> {
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use zip::write::SimpleFileOptions;

    fn archive(name: &str, body: &[u8]) -> Vec<u8> {
        let mut cursor = Cursor::new(Vec::new());
        {
            let mut writer = zip::ZipWriter::new(&mut cursor);
            writer
                .start_file(name, SimpleFileOptions::default())
                .expect("file should start");
            writer.write_all(body).expect("body should write");
            writer.finish().expect("archive should finish");
        }
        cursor.into_inner()
    }

    #[test]
    fn rejects_html_assets() {
        assert!(validate_asset(b"<!doctype html><h1>error</h1>", 1024).is_err());
    }

    #[test]
    fn accepts_binary_assets() {
        assert!(validate_asset(b"\x00\x01\x02geodata", 1024).is_ok());
    }

    #[test]
    fn extracts_only_expected_xray_file() {
        let temp = tempfile::tempdir().expect("temporary directory");
        let bytes = archive("nested/xray.exe", b"binary");
        let path = extract_xray_zip(&bytes, temp.path(), 1024).expect("archive should extract");
        assert_eq!(fs::read(path).expect("output"), b"binary");
    }

    #[test]
    fn rejects_path_traversal() {
        let temp = tempfile::tempdir().expect("temporary directory");
        let bytes = archive("../xray.exe", b"binary");
        assert!(extract_xray_zip(&bytes, temp.path(), 1024).is_err());
    }

    #[test]
    fn rejects_oversized_extracted_binary() {
        let temp = tempfile::tempdir().expect("temporary directory");
        let bytes = archive("xray.exe", &[0; 17]);
        assert!(extract_xray_zip(&bytes, temp.path(), 16).is_err());
    }

    #[test]
    fn detects_lock_contention() {
        let temp = tempfile::tempdir().expect("temporary directory");
        let path = temp.path().join("manager.lock");
        let first = OperationLock::acquire(&path).expect("first lock");
        assert!(matches!(
            OperationLock::acquire(&path),
            Err(ManagerError::LockContention)
        ));
        drop(first);
        assert!(OperationLock::acquire(&path).is_ok());
    }
}
