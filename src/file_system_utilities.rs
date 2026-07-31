use std::io::Read;
use std::path::{Path, PathBuf};

// ==========================================
// 🛠️ 基础算法与通用工具 (Utility Functions)
// ==========================================

/// 使用 64 位 FNV-1a 非加密哈希算法对输入的字符串进行哈希处理。
pub fn calculate_fnv1a_64_bit_hash_of_string(string_slice_to_be_hashed: &str) -> String {
    let mut unsigned_64_bit_hash_value: u64 = 0xcbf29ce484222325;
    for byte_of_character_in_string in string_slice_to_be_hashed.as_bytes() {
        unsigned_64_bit_hash_value ^= *byte_of_character_in_string as u64;
        unsigned_64_bit_hash_value = unsigned_64_bit_hash_value.wrapping_mul(0x100000001b3);
    }
    let string_representing_full_hexadecimal_hash = format!("{:016x}", unsigned_64_bit_hash_value);
    // 截取前 7 位作为人类易读的短哈希
    string_representing_full_hexadecimal_hash[..7].to_string()
}

/// 将输入的文件路径进行特征化提取，过滤掉非字母数字字符，生成美观、人类可读的 Slug 字符串。
pub fn generate_slug_from_absolute_filesystem_path(path_slice_to_be_slugified: &Path) -> String {
    let string_representing_file_name_or_directory_name = path_slice_to_be_slugified
        .file_name()
        .map(|os_str_representing_name| os_str_representing_name.to_string_lossy().into_owned())
        .unwrap_or_else(|| String::from("sandbox"));

    // 若名称是以 .exe 结尾的 Windows 可执行文件，则剔除其后缀名
    let string_representing_cleaned_base_name = if string_representing_file_name_or_directory_name.to_lowercase().ends_with(".exe") {
        string_representing_file_name_or_directory_name[..string_representing_file_name_or_directory_name.len() - 4].to_string()
    } else {
        string_representing_file_name_or_directory_name
    };

    // 移除非字母数字字符，统一替换为横杠
    let mut string_representing_sanitized_slug = String::new();
    for character_in_base_name in string_representing_cleaned_base_name.chars() {
        if character_in_base_name.is_alphanumeric() {
            string_representing_sanitized_slug.push(character_in_base_name);
        } else {
            string_representing_sanitized_slug.push('-');
        }
    }

    // 循环消除连续的多余横杠
    while string_representing_sanitized_slug.contains("--") {
        string_representing_sanitized_slug = string_representing_sanitized_slug.replace("--", "-");
    }

    string_representing_sanitized_slug.trim_matches('-').to_string()
}

/// 内存级波浪号展开器：在配置读取的最前端执行统一替换，确保流入程序内存的配置数据绝对化。
pub fn expand_tilde_in_configuration_value(string_representing_raw_value: String) -> String {
    if string_representing_raw_value == "~" {
        if let Some(os_str_representing_home) = std::env::var_os("HOME") {
            return os_str_representing_home.to_string_lossy().into_owned();
        }
    } else if string_representing_raw_value.starts_with("~/") {
        if let Some(os_str_representing_home) = std::env::var_os("HOME") {
            let string_representing_home = os_str_representing_home.to_string_lossy().into_owned();
            return format!("{}{}", string_representing_home, &string_representing_raw_value[1..]);
        }
    }
    string_representing_raw_value
}

/// 纯粹的绝对路径清洗器 (v0.3.0 精简版)：
/// 仅负责处理波浪号展开、相对路径转绝对路径、以及基础的规范化。
/// 注意：不再混入 $PATH 搜寻逻辑（搜寻逻辑已上移至目标探针引擎，以保持架构纯粹）。
pub fn fs_absolute_path_secure(path_slice_to_be_secured: &Path) -> PathBuf {
    let mut path_buf_representing_resolved_tilde = path_slice_to_be_secured.to_path_buf();

    // 极简波浪号安全自愈器
    if path_slice_to_be_secured.starts_with("~") {
        if let Some(os_str_representing_home) = std::env::var_os("HOME") {
            let path_slice_representing_home = Path::new(&os_str_representing_home);
            if path_slice_to_be_secured == Path::new("~") {
                path_buf_representing_resolved_tilde = path_slice_representing_home.to_path_buf();
            } else if let Ok(path_slice_representing_relative) = path_slice_to_be_secured.strip_prefix("~/") {
                path_buf_representing_resolved_tilde = path_slice_representing_home.join(path_slice_representing_relative);
            }
        }
    }

    // 尝试直接规范化以解析所有符号链接
    if let Ok(path_buf_representing_canonicalized) = std::fs::canonicalize(&path_buf_representing_resolved_tilde) {
        return path_buf_representing_canonicalized;
    } 
    
    // 如果文件不存在，强制进行绝对路径拼接
    if path_buf_representing_resolved_tilde.is_absolute() {
        path_buf_representing_resolved_tilde
    } else {
        if let Ok(path_buf_representing_current_working_directory) = std::env::current_dir() {
            path_buf_representing_current_working_directory.join(&path_buf_representing_resolved_tilde)
        } else {
            path_buf_representing_resolved_tilde
        }
    }
}

/// 安全读取文件头部魔数，判定是否为原生 Linux ELF 二进制文件。
pub fn check_if_file_is_linux_native_elf(path_slice_representing_physical_file: &Path) -> bool {
    if let Ok(mut file_representing_target_executable) = std::fs::File::open(path_slice_representing_physical_file) {
        let mut array_of_bytes_representing_magic_number = [0u8; 4];
        if file_representing_target_executable.read(&mut array_of_bytes_representing_magic_number).is_ok() {
            return array_of_bytes_representing_magic_number == [0x7f, 0x45, 0x4c, 0x46]; // \x7fELF
        }
    }
    false
}

// ==========================================
// 📁 挂载与路径映射相关工具 (Mount Utilities)
// ==========================================

/// 宿主家目录自愈投影：确保挂载桩存在（不错误地把文件挂载源当成文件夹创建）。
pub fn ensure_mount_point_exists_in_sandbox_home(
    path_to_be_mounted: &Path,
    path_buf_representing_host_home_directory: &Path,
    path_buf_representing_sandbox_home_directory: &Path,
) {
    if path_to_be_mounted.starts_with(path_buf_representing_host_home_directory) {
        if let Ok(path_slice_representing_relative_subpath) = path_to_be_mounted.strip_prefix(path_buf_representing_host_home_directory) {
            let path_buf_representing_physical_target_mount_point = path_buf_representing_sandbox_home_directory.join(path_slice_representing_relative_subpath);
            
            // 如果是套接字或常规文件，仅建立其父级目录
            if path_to_be_mounted.exists() && !path_to_be_mounted.is_dir() {
                if let Some(path_slice_representing_parent) = path_buf_representing_physical_target_mount_point.parent() {
                    let _ = std::fs::create_dir_all(path_slice_representing_parent);
                }
            } else {
                let _ = std::fs::create_dir_all(&path_buf_representing_physical_target_mount_point);
            }
        }
    }
}

/// 路径自愈算法核心：解析出容器内目标挂载路径的所有非系统保留级父目录，用于 --dir 构建。
pub fn get_unique_non_system_parent_paths(container_path: &Path) -> Vec<String> {
    let mut vector_of_strings_representing_parent_paths = Vec::new();
    
    // 判定如果是物理套接字或文件，起始分析层级需跳过自身，进入其 parent 目录
    let boolean_flag_indicating_is_directory = container_path.exists() && container_path.is_dir();
    let mut path_buf_representing_current_parent = if !boolean_flag_indicating_is_directory {
        match container_path.parent() {
            Some(parent) => parent.to_path_buf(),
            None => return vector_of_strings_representing_parent_paths,
        }
    } else {
        container_path.to_path_buf()
    };

    while let Some(parent) = path_buf_representing_current_parent.parent() {
        let string_representing_parent_path = path_buf_representing_current_parent.to_string_lossy().into_owned();
        if string_representing_parent_path == "/" || string_representing_parent_path.is_empty() {
            break;
        }

        let string_representing_parent_path_lowercase = string_representing_parent_path.to_lowercase();
        let boolean_flag_indicating_system_directory = 
            string_representing_parent_path_lowercase == "/usr" ||
            string_representing_parent_path_lowercase == "/etc" ||
            string_representing_parent_path_lowercase == "/sys" ||
            string_representing_parent_path_lowercase == "/proc" ||
            string_representing_parent_path_lowercase == "/dev" ||
            string_representing_parent_path_lowercase == "/tmp" ||
            string_representing_parent_path_lowercase == "/run" ||
            string_representing_parent_path_lowercase == "/var" ||
            string_representing_parent_path_lowercase == "/bin" ||
            string_representing_parent_path_lowercase == "/sbin" ||
            string_representing_parent_path_lowercase == "/lib" ||
            string_representing_parent_path_lowercase == "/lib64";

        if !boolean_flag_indicating_system_directory {
            vector_of_strings_representing_parent_paths.push(string_representing_parent_path);
        }
        path_buf_representing_current_parent = parent.to_path_buf();
    }

    vector_of_strings_representing_parent_paths.reverse();
    vector_of_strings_representing_parent_paths
}

/// 探测引擎：执行确定性回溯算法，从指定的 Wine 二进制路径智能推导出运行器(Runner)的根目录结构。
pub fn resolve_wine_runner_root_directory_from_binary_path(
    path_slice_representing_wine_binary: &Path
) -> Option<PathBuf> {
    let path_buf_representing_absolute_binary_path = fs_absolute_path_secure(path_slice_representing_wine_binary);
    let path_slice_representing_binary_directory = path_buf_representing_absolute_binary_path.parent()?;
    let string_representing_directory_name = path_slice_representing_binary_directory.file_name()?.to_string_lossy().to_lowercase();

    // 应对如 "bin" 或 "bin-arm64" 结构
    if string_representing_directory_name.starts_with("bin") {
        let path_slice_representing_candidate_root = path_slice_representing_binary_directory.parent()?;
        let string_representing_candidate_name = path_slice_representing_candidate_root.file_name()?.to_string_lossy().to_lowercase();
        
        // 进一步探测是否为 Proton 的 files 嵌套层
        if string_representing_candidate_name == "files" {
            Some(path_slice_representing_candidate_root.parent()?.to_path_buf())
        } else {
            Some(path_slice_representing_candidate_root.to_path_buf())
        }
    } else {
        // 退化至极简扁平打包布局
        Some(path_slice_representing_binary_directory.to_path_buf())
    }
}
