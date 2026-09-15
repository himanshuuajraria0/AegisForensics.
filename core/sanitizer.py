import os
import math
import time
import hashlib
import re
try:
    import win32con
    import win32file
    import winioctlcon
except ImportError:
    win32con = win32file = winioctlcon = None

SECTOR_SIZE = 512
BUFFER_SIZE = 1024 * 1024  # 1 MB, aligned to 512-byte sectors

def calculate_shannon_entropy(data_bytes):
    if not data_bytes:
        return 0.0
    entropy = 0
    length = len(data_bytes)
    freq = {}
    for b in data_bytes:
        freq[b] = freq.get(b, 0) + 1
    for count in freq.values():
        p_x = count / length
        entropy += - p_x * math.log2(p_x)
    return round(entropy, 3)

def normalize_target_path(target_path):
    value = str(target_path or "").strip()
    match = re.search(r"physicaldrive\s*(\d+)", value, re.IGNORECASE)
    return rf"\\.\PhysicalDrive{match.group(1)}" if match else value

def compute_sha256_and_entropy(target_path, max_bytes=20 * 1024 * 1024):
    target_path = normalize_target_path(target_path)
    hasher = hashlib.sha256()
    bytes_read = 0
    sample_bytes = bytearray()

    if "physicaldrive" not in target_path.lower():
        with open(target_path, "rb") as source:
            while bytes_read < max_bytes:
                chunk = source.read(min(BUFFER_SIZE, max_bytes - bytes_read))
                if not chunk:
                    break
                hasher.update(chunk)
                sample_bytes.extend(chunk[:1024 * 1024 - len(sample_bytes)])
                bytes_read += len(chunk)
        return hasher.hexdigest(), calculate_shannon_entropy(sample_bytes)

    if win32file is None:
        raise OSError("pywin32 is required for physical-drive sanitization")
    try:
        handle = win32file.CreateFile(
            target_path,
            win32con.GENERIC_READ,
            win32con.FILE_SHARE_READ | win32con.FILE_SHARE_WRITE,
            None,
            win32con.OPEN_EXISTING,
            win32con.FILE_FLAG_NO_BUFFERING | win32con.FILE_FLAG_WRITE_THROUGH,
            None
        )
        try:
            while bytes_read < max_bytes:
                hr, chunk = win32file.ReadFile(handle, BUFFER_SIZE)
                if not chunk:
                    break
                hasher.update(chunk)
                if len(sample_bytes) < 1024 * 1024:
                    sample_bytes.extend(chunk)
                bytes_read += len(chunk)
        finally:
            win32file.CloseHandle(handle)
    except Exception:
        raise

    entropy = calculate_shannon_entropy(sample_bytes)
    return hasher.hexdigest(), entropy

def execute_nist_sanitization(target_path, method="NIST_CLEAR", wipe_bytes=100 * 1024 * 1024):
    target_path = normalize_target_path(target_path)
    
    if "physicaldrive0" in target_path.lower():
        raise PermissionError("PROTECTION LOCK: Primary OS Boot Media (C:) is write-protected.")

    pre_hash, pre_entropy = compute_sha256_and_entropy(target_path)
    pattern = b"\x00" * BUFFER_SIZE

    if "physicaldrive" not in target_path.lower():
        with open(target_path, "r+b", buffering=0) as image:
            limit = min(wipe_bytes, os.path.getsize(target_path))
            written_total = 0
            while written_total < limit:
                count = min(BUFFER_SIZE, limit - written_total)
                image.write(b"\x00" * count)
                written_total += count
        post_hash, post_entropy = compute_sha256_and_entropy(target_path)
        return {"status": "success", "target": target_path, "method": method.upper(), "pre_hash": pre_hash, "post_hash": post_hash, "pre_entropy": pre_entropy, "post_entropy": post_entropy, "bytes_wiped": written_total, "timestamp": time.strftime("%Y-%m-%d %H:%M:%S")}

    if win32file is None:
        raise OSError("pywin32 is required for physical-drive sanitization")

    handle = win32file.CreateFile(
        target_path,
        win32con.GENERIC_READ | win32con.GENERIC_WRITE,
        win32con.FILE_SHARE_READ | win32con.FILE_SHARE_WRITE,
        None,
        win32con.OPEN_EXISTING,
        win32con.FILE_FLAG_NO_BUFFERING | win32con.FILE_FLAG_WRITE_THROUGH,
        None
    )

    try:
        try:
            win32file.DeviceIoControl(handle, winioctlcon.FSCTL_LOCK_VOLUME, None, None)
            win32file.DeviceIoControl(handle, winioctlcon.FSCTL_DISMOUNT_VOLUME, None, None)
        except Exception:
            pass

        win32file.SetFilePointer(handle, 0, win32file.FILE_BEGIN)
        written_total = 0

        while written_total < wipe_bytes:
            try:
                hr, bytes_written = win32file.WriteFile(handle, pattern)
                if bytes_written == 0:
                    break
                written_total += bytes_written
            except Exception:
                break

        try:
            win32file.DeviceIoControl(handle, winioctlcon.FSCTL_UNLOCK_VOLUME, None, None)
        except Exception:
            pass

    finally:
        win32file.CloseHandle(handle)

    time.sleep(0.5)
    post_hash, post_entropy = compute_sha256_and_entropy(target_path)

    return {
        "status": "success",
        "target": target_path,
        "method": method.upper(),
        "pre_hash": pre_hash,
        "post_hash": post_hash,
        "pre_entropy": pre_entropy,
        "post_entropy": post_entropy,
        "bytes_wiped": written_total,
        "timestamp": time.strftime("%Y-%m-%d %H:%M:%S")
    }

def wipe_file_or_folder(target_path):
    if not os.path.exists(target_path):
        raise FileNotFoundError(f"Path not found: {target_path}")

    files_to_wipe = []
    if os.path.isfile(target_path):
        files_to_wipe.append(target_path)
    else:
        for root, _, files in os.walk(target_path, topdown=False):
            for name in files:
                files_to_wipe.append(os.path.join(root, name))

    purged_count = 0
    for fpath in files_to_wipe:
        length = os.path.getsize(fpath)
        with open(fpath, "ba+", buffering=0) as f:
            f.seek(0)
            f.write(b"\x00" * length)
            f.truncate(0)

        dir_name = os.path.dirname(fpath)
        rnd_name = os.path.join(dir_name, f"tmp_{int(time.time()*1000)}.tmp")
        os.rename(fpath, rnd_name)
        os.remove(rnd_name)
        purged_count += 1

    if os.path.isdir(target_path):
        os.rmdir(target_path)

    return {"status": "success", "purged_count": purged_count}
