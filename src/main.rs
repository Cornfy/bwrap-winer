use std::io::Read;
use std::os::unix::process::CommandExt;
use std::path::PathBuf;

// ==========================================
// 🧱 核心结构体定义 (Core Data Structures)
// ==========================================

/// 挂载描述规范实体：用于将所有 X11、Wayland、Fonts、Vulkan、音频、大资产挂载等数据流完全管线化。
struct MountSpecification {
    path_buf_representing_host_source: PathBuf,
    path_buf_representing_container_destination: PathBuf,
    boolean_flag_indicating_readonly: bool,
    boolean_flag_indicating_try_only: bool,
}

/// 配置金字塔实体：安全封装 3 个维度的哈希表，并提供便捷的级联查询接口。
struct ConfigurationPyramid {
    hash_map_representing_sandbox_local_configuration_keys_and_values: std::collections::HashMap<String, String>,
    hash_map_representing_sandbox_specific_user_configuration_keys_and_values: std::collections::HashMap<String, String>,
    hash_map_representing_global_configuration_keys_and_values: std::collections::HashMap<String, String>,
}

impl ConfigurationPyramid {
    /// 利用内部结构体直接调用底层的分层查询逻辑
    fn resolve_configuration_value(&self, string_slice_representing_variable_key: &str, string_slice_representing_hardcoded_default_value: &str) -> String {
        resolve_configuration_value_from_hierarchical_sources(
            string_slice_representing_variable_key,
            &self.hash_map_representing_sandbox_local_configuration_keys_and_values,
            &self.hash_map_representing_sandbox_specific_user_configuration_keys_and_values,
            &self.hash_map_representing_global_configuration_keys_and_values,
            string_slice_representing_hardcoded_default_value,
        )
    }
}

/// 沙箱运行时环境上下文实体：在各个管线阶段流转的不可变静态数据聚合。
struct SandboxContext {
    #[allow(dead_code)]
    string_representing_derived_sandbox_identifier: String,
    path_buf_representing_host_home_directory: PathBuf,
    string_representing_host_username: String,
    path_buf_representing_sandbox_home_directory: PathBuf,
    configuration_pyramid_representing_all_layers: ConfigurationPyramid,
}

/// 目标可执行文件及衍生状态的解析结果实体。
struct TargetSpecification {
    string_representing_raw_path_to_target_executable_file: String,
    path_buf_representing_absolute_path_to_target_executable_file: PathBuf,
    boolean_flag_indicating_wine_prefix_prepending_needed: bool,
    vector_of_strings_representing_remaining_cli_arguments: Vec<String>,
}

// ==========================================
// 🛠️ 基础算法与通用工具函数 (Utility Functions)
// ==========================================

/// 使用 64 位 FNV-1a 非加密哈希算法对输入的字符串进行哈希处理。
/// 这是一个自包含的高效算法，用于避免引入外部 sha2/hex 依赖。
fn calculate_fnv1a_64_bit_hash_of_string(string_slice_to_be_hashed: &str) -> String {
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
fn generate_slug_from_absolute_filesystem_path(path_slice_to_be_slugified: &std::path::Path) -> String {
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

/// 纯标准库实现的高效扁平 TOML/配置文件解析器，支持过滤整行注释、行尾注释及剔除包裹引号。
fn parse_simple_flat_toml_file_into_hash_map(
    path_to_configuration_file: &std::path::Path,
) -> std::collections::HashMap<String, String> {
    let mut hash_map_representing_configuration_keys_and_values = std::collections::HashMap::new();
    if !path_to_configuration_file.exists() {
        return hash_map_representing_configuration_keys_and_values;
    }
    if let Ok(string_representing_file_content) = std::fs::read_to_string(path_to_configuration_file) {
        for string_slice_representing_line in string_representing_file_content.lines() {
            let string_slice_representing_trimmed_line = string_slice_representing_line.trim();
            // 过滤空白行和标准注释行
            if string_slice_representing_trimmed_line.is_empty()
                || string_slice_representing_trimmed_line.starts_with('#')
                || string_slice_representing_trimmed_line.starts_with(';')
            {
                continue;
            }
            if let Some(usize_representing_equals_index) = string_slice_representing_trimmed_line.find('=') {
                let string_representing_key = string_slice_representing_trimmed_line[..usize_representing_equals_index].trim().to_uppercase();
                let string_representing_raw_value = string_slice_representing_trimmed_line[usize_representing_equals_index + 1..].trim();

                // 移除潜在的行尾注释部分（如 value # comment）
                let string_slice_representing_value_without_comment = if let Some(usize_representing_comment_index) = string_representing_raw_value.find('#') {
                    string_representing_raw_value[..usize_representing_comment_index].trim()
                } else if let Some(usize_representing_comment_index) = string_representing_raw_value.find(';') {
                    string_representing_raw_value[..usize_representing_comment_index].trim()
                } else {
                    string_representing_raw_value
                };

                // 移除两侧的单引号或双引号
                let string_representing_cleaned_value = if (string_slice_representing_value_without_comment.starts_with('"')
                    && string_slice_representing_value_without_comment.ends_with('"'))
                    || (string_slice_representing_value_without_comment.starts_with('\'')
                        && string_slice_representing_value_without_comment.ends_with('\''))
                {
                    if string_slice_representing_value_without_comment.len() >= 2 {
                        string_slice_representing_value_without_comment[1..string_slice_representing_value_without_comment.len() - 1].to_string()
                    } else {
                        string_slice_representing_value_without_comment.to_string()
                    }
                } else {
                    string_slice_representing_value_without_comment.to_string()
                };
                hash_map_representing_configuration_keys_and_values.insert(string_representing_key, string_representing_cleaned_value);
            }
        }
    }
    hash_map_representing_configuration_keys_and_values
}

/// 5 层金字塔链式覆盖器：依次从 环境变量 -> 局部沙箱运行时配置 -> 个人 XDG 用户专属沙箱配置 -> 全局默认配置 -> 硬编码保底 级联查询目标值。
fn resolve_configuration_value_from_hierarchical_sources(
    string_slice_representing_variable_key: &str,
    hash_map_representing_sandbox_local_data_config: &std::collections::HashMap<String, String>,
    hash_map_representing_sandbox_specific_user_config: &std::collections::HashMap<String, String>,
    hash_map_representing_global_config: &std::collections::HashMap<String, String>,
    string_slice_representing_hardcoded_default_value: &str,
) -> String {
    // 1. 环境变量 (最高优先级)
    if let Ok(string_representing_env_value) = std::env::var(string_slice_representing_variable_key) {
        return string_representing_env_value;
    }
    // 2. 局部沙箱运行时状态配置 (XDG_DATA_HOME/sandboxes/[ID]/winer_meta.toml)
    if let Some(string_representing_sandbox_value) = hash_map_representing_sandbox_local_data_config.get(string_slice_representing_variable_key) {
        return string_representing_sandbox_value.clone();
    }
    // 3. 用户个人专属沙箱配置 (XDG_CONFIG_HOME/bwrap-winer/[ID].toml)
    if let Some(string_representing_sandbox_user_value) = hash_map_representing_sandbox_specific_user_config.get(string_slice_representing_variable_key) {
        return string_representing_sandbox_user_value.clone();
    }
    // 4. 全局通用配置 (XDG_CONFIG_HOME/bwrap-winer/config.toml)
    if let Some(string_representing_global_value) = hash_map_representing_global_config.get(string_slice_representing_variable_key) {
        return string_representing_global_value.clone();
    }
    // 5. 硬编码保底 (最低优先级)
    string_slice_representing_hardcoded_default_value.to_string()
}

/// 宿主家目录自愈投影：使用 !is_dir() 识别套接字和普通文件，仅在隔离的沙箱 sandbox_home 对应结构下执行物理自愈创建父目录，确保挂载桩存在。
fn ensure_mount_point_exists_in_sandbox_home(
    path_to_be_mounted: &std::path::Path,
    path_buf_representing_host_home_directory: &std::path::Path,
    path_buf_representing_sandbox_home_directory: &std::path::Path,
) {
    if path_to_be_mounted.starts_with(path_buf_representing_host_home_directory) {
        if let Ok(path_slice_representing_relative_subpath) = path_to_be_mounted.strip_prefix(path_buf_representing_host_home_directory) {
            let path_buf_representing_physical_target_mount_point = path_buf_representing_sandbox_home_directory.join(path_slice_representing_relative_subpath);
            
            // 修正判定：如果是套接字或常规文件，仅建立其父级目录
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

/// 路径自愈算法核心（类似于 `add_dir_parents`）：解析出容器内目标挂载路径的所有非系统保留级父目录。
/// 修正判定：使用 !is_dir() 判定非普通文件和套接字，绝不在 `--dir` 队列中建立其自身同名的空文件夹。
fn get_unique_non_system_parent_paths(container_path: &std::path::Path) -> Vec<String> {
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
        // 仅排除 exact 系统保留的基础挂载源
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

fn print_bwrap_winer_help_information() {
    println!("🛠  bwrap-winer - Zero-Flags Transparent Wine Sandbox Proxy");
    println!("===============================================================");
    println!("A lightweight, zero-flag Unix-style sandbox proxy utilizing bubblewrap.");
    println!();
    println!("USAGE:");
    println!("    bwrap-winer <executable.exe> [arguments...]");
    println!("    bwrap-winer /path/to/wine <executable.exe> [arguments...]");
    println!("    WINER_ID=myapp bwrap-winer");
    println!("    bwrap-winer --list");
    println!("    bwrap-winer -h | --help");
    println!();
    println!("CONFIGURATION PYRAMID PRIORITY (Highest to Lowest):");
    println!("    [1] Environment Variables                          (Ephemeral instant override)");
    println!("    [2] Sandbox Runtime Meta (winer_meta.toml)         (Runtime auto-generated states in XDG_DATA_HOME)");
    println!("    [3] User Sandbox Config ([SANDBOX_ID].toml)        (Dotfiles-friendly profiles in XDG_CONFIG_HOME)");
    println!("    [4] Global User Config (config.toml)               (Global engineering configuration)");
    println!("    [5] Hardcoded default values                       (System-wide fallback security)");
    println!();
    println!("COMPLIANT PATHS (XDG BASE DIRECTORY SPECIFICATION):");
    println!("    Global Config  $XDG_CONFIG_HOME/bwrap-winer/config.toml             (Default: ~/.config/...)");
    println!("    User Profile   $XDG_CONFIG_HOME/bwrap-winer/[SANDBOX_ID].toml");
    println!("    Sandbox Root   $XDG_DATA_HOME/bwrap-winer/sandboxes/                (Default: ~/.local/share/...)");
    println!("    Runtime Meta   $XDG_DATA_HOME/bwrap-winer/sandboxes/[SANDBOX_ID]/winer_meta.toml");
    println!();
    println!("SUPPORTED CONFIGURATION KEYS & ENVIRONMENT VARIABLES:");
    println!("    WINER_EXE_PATH   Target executable file path (can substitute CLI argument).");
    println!("    WINER_EXE_ARGS   Arguments to pass to the target executable.");
    println!("    WINER_WINE_PATH  Custom Wine binary path to use instead of system 'wine'.");
    println!("    WINER_ID         Explicit override for the unique sandbox identifier.");
    println!("    WINER_DATA_ROOT  Alternative root directory path for sandboxes storage.");
    println!("    WINER_NET        Network access control: '1' (shared, default) or '0' (disconnected).");
    println!("    WINER_SHARE_PID  PID namespace sharing: '1' (shared, default) or '0' (strict process isolation).");
    println!("    WINER_IPC        IPC namespace sharing: '1' (shared, default) or '0' (isolated with performance warning).");
    println!("    WINER_DEV        Input hardware pass-through: '1' (full /dev bind, default) or '0' (DRI & NVIDIA only).");
    println!("    WINER_PENETRATE  File mounting penetration depth: '0' (file-only), '1' (parent, default), or 'n' (n-th parent).");
    println!("    WINER_GAMEMODE   GameMode high-performance wrapping: '1' (enable gamemoderun) or '0' (disabled, default).");
    println!("    WINER_BIND       Comma-separated read-write paths to mount (e.g., /host_dir:/sandbox_dir).");
    println!("    WINER_RO_BIND    Comma-separated read-only paths to mount (e.g., /host_dir:/sandbox_dir).");
    println!("    WINEPREFIX       Specific Host Wine prefix to automatically pass-through and heal.");
}

// ==========================================
// 🚀 核心管线重构 (Extracted Pipeline Functions)
// ==========================================

fn handle_help_command_if_needed(vector_of_strings_representing_command_line_arguments: &[String]) {
    if vector_of_strings_representing_command_line_arguments.is_empty()
        || vector_of_strings_representing_command_line_arguments[0] == "-h"
        || vector_of_strings_representing_command_line_arguments[0] == "--help"
    {
        // 允许通过环境变量无参启动，仅在既没有参数也没有环境变量时才触发 Help
        if std::env::var("WINER_EXE_PATH").is_err() && std::env::var("WINER_ID").is_err() {
            print_bwrap_winer_help_information();
            std::process::exit(0);
        } else if !vector_of_strings_representing_command_line_arguments.is_empty() && 
                  (vector_of_strings_representing_command_line_arguments[0] == "-h" || vector_of_strings_representing_command_line_arguments[0] == "--help") {
            print_bwrap_winer_help_information();
            std::process::exit(0);
        }
    }
}

fn resolve_host_environment_base_paths() -> (PathBuf, String, PathBuf) {
    let path_buf_representing_host_home_directory = std::env::var_os("HOME")
        .map(PathBuf::from)
        .expect("CRITICAL ERROR: HOME environment variable is not set on the host system");

    let string_representing_host_username = std::env::var("USER")
        .unwrap_or_else(|_| String::from("wineruser"));

    let path_buf_representing_global_config_root = std::env::var_os("XDG_CONFIG_HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|| path_buf_representing_host_home_directory.join(".config"))
        .join("bwrap-winer");

    (path_buf_representing_host_home_directory, string_representing_host_username, path_buf_representing_global_config_root)
}

fn resolve_sandbox_data_root_directory(
    path_buf_representing_host_home_directory: &std::path::Path,
    hash_map_representing_global_configuration_keys_and_values: &std::collections::HashMap<String, String>,
) -> PathBuf {
    let path_buf_representing_default_data_root = std::env::var_os("XDG_DATA_HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|| path_buf_representing_host_home_directory.join(".local/share"))
        .join("bwrap-winer/sandboxes");

    let string_representing_data_root_resolved_value = resolve_configuration_value_from_hierarchical_sources(
        "WINER_DATA_ROOT",
        &std::collections::HashMap::new(),
        &std::collections::HashMap::new(),
        hash_map_representing_global_configuration_keys_and_values,
        &path_buf_representing_default_data_root.to_string_lossy(),
    );
    PathBuf::from(string_representing_data_root_resolved_value)
}

fn handle_list_command_if_needed(
    vector_of_strings_representing_command_line_arguments: &[String],
    path_buf_representing_sandbox_data_root_directory: &std::path::Path,
) {
    if !vector_of_strings_representing_command_line_arguments.is_empty() && vector_of_strings_representing_command_line_arguments[0] == "--list" {
        println!("📦 bwrap-winer - List of active sandboxes:");
        if path_buf_representing_sandbox_data_root_directory.exists() {
            if let Ok(read_dir_representing_sandbox_directories) = std::fs::read_dir(path_buf_representing_sandbox_data_root_directory) {
                let mut count = 0;
                for dir_entry_result in read_dir_representing_sandbox_directories {
                    if let Ok(dir_entry) = dir_entry_result {
                        if let Ok(file_type) = dir_entry.file_type() {
                            if file_type.is_dir() {
                                println!("  - {}", dir_entry.file_name().to_string_lossy());
                                count += 1;
                            }
                        }
                    }
                }
                if count == 0 {
                    println!("  (No sandboxes found)");
                }
            }
        } else {
            println!("  (Data root directory does not exist yet)");
        }
        std::process::exit(0);
    }
}

fn parse_target_executable_and_remaining_arguments_from_cli(
    vector_of_strings_representing_command_line_arguments: &[String]
) -> (Option<String>, Vec<String>) {
    let mut option_representing_raw_target_executable: Option<String> = None;
    let mut vector_of_strings_representing_remaining_cli_arguments: Vec<String> = Vec::new();

    if !vector_of_strings_representing_command_line_arguments.is_empty() {
        let string_representing_first_argument = &vector_of_strings_representing_command_line_arguments[0];
        let string_representing_first_argument_lowercase = string_representing_first_argument.to_lowercase();
        
        if (string_representing_first_argument_lowercase == "wine"
            || string_representing_first_argument_lowercase == "wine64"
            || string_representing_first_argument_lowercase.ends_with("/wine")
            || string_representing_first_argument_lowercase.ends_with("/wine64"))
            && vector_of_strings_representing_command_line_arguments.len() > 1
        {
            option_representing_raw_target_executable = Some(vector_of_strings_representing_command_line_arguments[1].clone());
            vector_of_strings_representing_remaining_cli_arguments = vector_of_strings_representing_command_line_arguments.iter().skip(2).cloned().collect();
        } else {
            option_representing_raw_target_executable = Some(string_representing_first_argument.clone());
            vector_of_strings_representing_remaining_cli_arguments = vector_of_strings_representing_command_line_arguments.iter().skip(1).cloned().collect();
        }
    }

    if option_representing_raw_target_executable.is_none() {
        if let Ok(string_representing_env_exe_path) = std::env::var("WINER_EXE_PATH") {
            option_representing_raw_target_executable = Some(string_representing_env_exe_path);
        }
    }

    (option_representing_raw_target_executable, vector_of_strings_representing_remaining_cli_arguments)
}

fn resolve_sandbox_identity(
    option_representing_raw_target_executable: &Option<String>,
    hash_map_representing_global_configuration_keys_and_values: &std::collections::HashMap<String, String>,
) -> String {
    if let Ok(string_representing_explicit_sandbox_id) = std::env::var("WINER_ID") {
        string_representing_explicit_sandbox_id
    } else if let Some(string_representing_global_sandbox_id) = hash_map_representing_global_configuration_keys_and_values.get("WINER_ID") {
        string_representing_global_sandbox_id.clone()
    } else {
        let string_representing_wine_prefix_resolved_value = resolve_configuration_value_from_hierarchical_sources(
            "WINEPREFIX",
            &std::collections::HashMap::new(),
            &std::collections::HashMap::new(),
            hash_map_representing_global_configuration_keys_and_values,
            "",
        );
        if !string_representing_wine_prefix_resolved_value.is_empty() {
            let path_buf_representing_explicit_wine_prefix = std::fs::canonicalize(&string_representing_wine_prefix_resolved_value)
                .unwrap_or_else(|_| PathBuf::from(&string_representing_wine_prefix_resolved_value));
            let string_representing_prefix_slug = generate_slug_from_absolute_filesystem_path(&path_buf_representing_explicit_wine_prefix);
            let string_representing_prefix_hash = calculate_fnv1a_64_bit_hash_of_string(&path_buf_representing_explicit_wine_prefix.to_string_lossy());
            format!("{}-{}", string_representing_prefix_slug, string_representing_prefix_hash)
        } else if let Some(string_representing_known_exe) = option_representing_raw_target_executable {
            let path_buf_representing_absolute_path_to_target_executable_file = std::fs::canonicalize(string_representing_known_exe)
                .unwrap_or_else(|_| PathBuf::from(string_representing_known_exe));
            let string_representing_executable_slug = generate_slug_from_absolute_filesystem_path(&path_buf_representing_absolute_path_to_target_executable_file);
            let string_representing_executable_hash = calculate_fnv1a_64_bit_hash_of_string(&path_buf_representing_absolute_path_to_target_executable_file.to_string_lossy());
            format!("{}-{}", string_representing_executable_slug, string_representing_executable_hash)
        } else {
            eprintln!("[bwrap-winer] CRITICAL ERROR: Target executable or WINER_ID not specified.");
            eprintln!("[bwrap-winer] Usage: WINER_ID=myapp bwrap-winer OR bwrap-winer /path/to/exe");
            std::process::exit(1);
        }
    }
}

fn load_configuration_hierarchy(
    path_buf_representing_global_config_root: &std::path::Path,
    path_buf_representing_sandbox_data_root_directory: &std::path::Path,
    string_representing_derived_sandbox_identifier: &str,
    hash_map_representing_global_configuration_keys_and_values: std::collections::HashMap<String, String>,
) -> ConfigurationPyramid {
    let path_buf_representing_sandbox_specific_user_config_path = path_buf_representing_global_config_root
        .join(format!("{}.toml", string_representing_derived_sandbox_identifier));
    let hash_map_representing_sandbox_specific_user_configuration_keys_and_values = parse_simple_flat_toml_file_into_hash_map(
        &path_buf_representing_sandbox_specific_user_config_path,
    );

    let path_buf_representing_sandbox_root_directory = path_buf_representing_sandbox_data_root_directory.join(string_representing_derived_sandbox_identifier);
    let path_buf_representing_sandbox_local_configuration_file_path = path_buf_representing_sandbox_root_directory.join("winer_meta.toml");
    let hash_map_representing_sandbox_local_configuration_keys_and_values = parse_simple_flat_toml_file_into_hash_map(
        &path_buf_representing_sandbox_local_configuration_file_path,
    );

    ConfigurationPyramid {
        hash_map_representing_sandbox_local_configuration_keys_and_values,
        hash_map_representing_sandbox_specific_user_configuration_keys_and_values,
        hash_map_representing_global_configuration_keys_and_values,
    }
}

fn ensure_sandbox_root_and_home_directories_exist(sandbox_context_representing_runtime_environment: &SandboxContext) {
    if let Err(error_representing_failed_directory_creation) = std::fs::create_dir_all(&sandbox_context_representing_runtime_environment.path_buf_representing_sandbox_home_directory) {
        eprintln!("CRITICAL ERROR: Failed to create sandbox persistence directory: {:?}", error_representing_failed_directory_creation);
        std::process::exit(1);
    }
}

fn resolve_target_executable_and_validate(
    option_representing_raw_target_executable: Option<String>,
    vector_of_strings_representing_remaining_cli_arguments: Vec<String>,
    sandbox_context_representing_runtime_environment: &SandboxContext,
) -> TargetSpecification {
    let string_representing_raw_path_to_target_executable_file = match option_representing_raw_target_executable {
        Some(string_representing_known_exe) => string_representing_known_exe,
        None => {
            let string_representing_resolved_exe_path = sandbox_context_representing_runtime_environment.configuration_pyramid_representing_all_layers.resolve_configuration_value("WINER_EXE_PATH", "");
            if string_representing_resolved_exe_path.is_empty() {
                eprintln!("[bwrap-winer] CRITICAL ERROR: Target executable could not be resolved from CLI, ENV, or TOML configs.");
                std::process::exit(1);
            }
            string_representing_resolved_exe_path
        }
    };

    let mut boolean_flag_indicating_wine_prefix_prepending_needed = false;
    let string_representing_target_executable_lowercase = string_representing_raw_path_to_target_executable_file.to_lowercase();
    if string_representing_target_executable_lowercase.ends_with(".exe") 
        || string_representing_target_executable_lowercase.ends_with(".bat")
        || string_representing_target_executable_lowercase.ends_with(".cmd") 
        || string_representing_target_executable_lowercase.ends_with(".msi") 
        || string_representing_target_executable_lowercase.ends_with(".reg")
    {
        boolean_flag_indicating_wine_prefix_prepending_needed = true;
    }

    let path_buf_representing_absolute_path_to_target_executable_file = std::fs::canonicalize(&string_representing_raw_path_to_target_executable_file)
        .unwrap_or_else(|_| PathBuf::from(&string_representing_raw_path_to_target_executable_file));

    // 启发式探测拦截
    let array_of_strings_representing_wine_builtins = ["winecfg", "regedit", "control", "uninstaller", "wineconsole", "explorer"];
    if string_representing_raw_path_to_target_executable_file.contains('/') || string_representing_raw_path_to_target_executable_file.contains('\\') {
        if !path_buf_representing_absolute_path_to_target_executable_file.exists() {
            eprintln!("[bwrap-winer] CRITICAL ERROR: Target executable file not found -> {}", string_representing_raw_path_to_target_executable_file);
            std::process::exit(1);
        }
        
        if let Ok(mut file_representing_target_executable) = std::fs::File::open(&path_buf_representing_absolute_path_to_target_executable_file) {
            let mut array_of_bytes_representing_magic_number = [0u8; 4];
            if file_representing_target_executable.read(&mut array_of_bytes_representing_magic_number).is_ok() {
                if array_of_bytes_representing_magic_number == [0x7f, 0x45, 0x4c, 0x46] {
                    eprintln!("[bwrap-winer] SECURITY BLOCK: '{}' is a native Linux ELF binary.", string_representing_raw_path_to_target_executable_file);
                    eprintln!("[bwrap-winer] This tool is strictly a Wine sandbox proxy. Refusing to run native Linux programs.");
                    std::process::exit(1);
                }
            }
        }
    } else if !array_of_strings_representing_wine_builtins.contains(&string_representing_raw_path_to_target_executable_file.as_str()) {
        // 软警告拦截...
    }

    TargetSpecification {
        string_representing_raw_path_to_target_executable_file,
        path_buf_representing_absolute_path_to_target_executable_file,
        boolean_flag_indicating_wine_prefix_prepending_needed,
        vector_of_strings_representing_remaining_cli_arguments,
    }
}

fn collect_mount_specifications(
    sandbox_context_representing_runtime_environment: &SandboxContext,
    target_specification_representing_validated_execution: &TargetSpecification,
) -> Vec<MountSpecification> {
    let mut vector_of_mount_specifications: Vec<MountSpecification> = Vec::new();
    let pyramid = &sandbox_context_representing_runtime_environment.configuration_pyramid_representing_all_layers;

    let string_representing_penetrate_depth_value = pyramid.resolve_configuration_value("WINER_PENETRATE", "1");
    let unsigned_integer_representing_penetrate_depth = string_representing_penetrate_depth_value.parse::<usize>().unwrap_or(1);

    let mut path_buf_representing_current_penetrated_directory = target_specification_representing_validated_execution.path_buf_representing_absolute_path_to_target_executable_file.clone();
    if unsigned_integer_representing_penetrate_depth == 0 {
        vector_of_mount_specifications.push(MountSpecification {
            path_buf_representing_host_source: target_specification_representing_validated_execution.path_buf_representing_absolute_path_to_target_executable_file.clone(),
            path_buf_representing_container_destination: target_specification_representing_validated_execution.path_buf_representing_absolute_path_to_target_executable_file.clone(),
            boolean_flag_indicating_readonly: true,
            boolean_flag_indicating_try_only: false,
        });
    } else {
        for _ in 0..unsigned_integer_representing_penetrate_depth {
            if let Some(path_slice_representing_parent_directory) = path_buf_representing_current_penetrated_directory.parent() {
                path_buf_representing_current_penetrated_directory = path_slice_representing_parent_directory.to_path_buf();
            } else {
                break;
            }
        }
        vector_of_mount_specifications.push(MountSpecification {
            path_buf_representing_host_source: path_buf_representing_current_penetrated_directory.clone(),
            path_buf_representing_container_destination: path_buf_representing_current_penetrated_directory.clone(),
            boolean_flag_indicating_readonly: false,
            boolean_flag_indicating_try_only: false,
        });
    }

    let string_representing_wine_prefix_resolved_value = pyramid.resolve_configuration_value("WINEPREFIX", "");
    if !string_representing_wine_prefix_resolved_value.is_empty() {
        let path_buf_representing_custom_wine_prefix = std::fs::canonicalize(&string_representing_wine_prefix_resolved_value)
            .unwrap_or_else(|_| PathBuf::from(&string_representing_wine_prefix_resolved_value));
        vector_of_mount_specifications.push(MountSpecification {
            path_buf_representing_host_source: path_buf_representing_custom_wine_prefix.clone(),
            path_buf_representing_container_destination: path_buf_representing_custom_wine_prefix,
            boolean_flag_indicating_readonly: false,
            boolean_flag_indicating_try_only: false,
        });
    }

    let string_representing_custom_binds_value = pyramid.resolve_configuration_value("WINER_BIND", "");
    if !string_representing_custom_binds_value.is_empty() {
        for string_slice_representing_bind_pair in string_representing_custom_binds_value.split(',') {
            if !string_slice_representing_bind_pair.is_empty() {
                let vector_of_slices_representing_pair_split: Vec<&str> = string_slice_representing_bind_pair.split(':').collect();
                let string_representing_host_path = vector_of_slices_representing_pair_split[0].to_string();
                let string_representing_container_path = if vector_of_slices_representing_pair_split.len() > 1 {
                    vector_of_slices_representing_pair_split[1].to_string()
                } else {
                    string_representing_host_path.clone()
                };
                vector_of_mount_specifications.push(MountSpecification {
                    path_buf_representing_host_source: PathBuf::from(string_representing_host_path),
                    path_buf_representing_container_destination: PathBuf::from(string_representing_container_path),
                    boolean_flag_indicating_readonly: false,
                    boolean_flag_indicating_try_only: false,
                });
            }
        }
    }

    let string_representing_custom_ro_binds_value = pyramid.resolve_configuration_value("WINER_RO_BIND", "");
    if !string_representing_custom_ro_binds_value.is_empty() {
        for string_slice_representing_ro_bind_pair in string_representing_custom_ro_binds_value.split(',') {
            if !string_slice_representing_ro_bind_pair.is_empty() {
                let vector_of_slices_representing_pair_split: Vec<&str> = string_slice_representing_ro_bind_pair.split(':').collect();
                let string_representing_host_path = vector_of_slices_representing_pair_split[0].to_string();
                let string_representing_container_path = if vector_of_slices_representing_pair_split.len() > 1 {
                    vector_of_slices_representing_pair_split[1].to_string()
                } else {
                    string_representing_host_path.clone()
                };
                vector_of_mount_specifications.push(MountSpecification {
                    path_buf_representing_host_source: PathBuf::from(string_representing_host_path),
                    path_buf_representing_container_destination: PathBuf::from(string_representing_container_path),
                    boolean_flag_indicating_readonly: true,
                    boolean_flag_indicating_try_only: false,
                });
            }
        }
    }

    if let Ok(string_representing_wayland_display_value) = std::env::var("WAYLAND_DISPLAY") {
        if let Ok(string_representing_xdg_runtime_directory_value) = std::env::var("XDG_RUNTIME_DIR") {
            let path_buf_representing_wayland_socket = PathBuf::from(&string_representing_xdg_runtime_directory_value).join(&string_representing_wayland_display_value);
            vector_of_mount_specifications.push(MountSpecification {
                path_buf_representing_host_source: path_buf_representing_wayland_socket.clone(),
                path_buf_representing_container_destination: path_buf_representing_wayland_socket,
                boolean_flag_indicating_readonly: false,
                boolean_flag_indicating_try_only: true,
            });
        }
    }

    vector_of_mount_specifications.push(MountSpecification {
        path_buf_representing_host_source: PathBuf::from("/tmp/.X11-unix"),
        path_buf_representing_container_destination: PathBuf::from("/tmp/.X11-unix"),
        boolean_flag_indicating_readonly: false,
        boolean_flag_indicating_try_only: true,
    });

    if let Ok(string_representing_xdg_runtime_directory_value) = std::env::var("XDG_RUNTIME_DIR") {
        let path_buf_representing_xdg_runtime_directory = PathBuf::from(&string_representing_xdg_runtime_directory_value);
        let array_of_strings_representing_audio_and_dbus_sockets = ["pipewire-0", "pulse", "bus", "at-spi", "gvfs"];
        for string_slice_representing_socket_name in array_of_strings_representing_audio_and_dbus_sockets {
            let path_buf_representing_socket = path_buf_representing_xdg_runtime_directory.join(string_slice_representing_socket_name);
            vector_of_mount_specifications.push(MountSpecification {
                path_buf_representing_host_source: path_buf_representing_socket.clone(),
                path_buf_representing_container_destination: path_buf_representing_socket,
                boolean_flag_indicating_readonly: false,
                boolean_flag_indicating_try_only: true,
            });
        }
    }

    let array_of_strings_representing_vulkan_and_fonts_paths = [
        "/usr/share/vulkan", "/etc/vulkan", "/etc/fonts", "/usr/share/fonts", "/usr/local/share/fonts"
    ];
    for string_slice_representing_path in array_of_strings_representing_vulkan_and_fonts_paths {
        vector_of_mount_specifications.push(MountSpecification {
            path_buf_representing_host_source: PathBuf::from(string_slice_representing_path),
            path_buf_representing_container_destination: PathBuf::from(string_slice_representing_path),
            boolean_flag_indicating_readonly: true,
            boolean_flag_indicating_try_only: true,
        });
    }

    let path_buf_representing_user_fonts_directory = sandbox_context_representing_runtime_environment.path_buf_representing_host_home_directory.join(".local/share/fonts");
    vector_of_mount_specifications.push(MountSpecification {
        path_buf_representing_host_source: path_buf_representing_user_fonts_directory.clone(),
        path_buf_representing_container_destination: path_buf_representing_user_fonts_directory,
        boolean_flag_indicating_readonly: true,
        boolean_flag_indicating_try_only: true,
    });

    let array_of_strings_representing_dns_and_resolved_paths = [
        "/run/systemd/resolve", "/run/NetworkManager", "/run/resolvconf"
    ];
    for string_slice_representing_dns_path in array_of_strings_representing_dns_and_resolved_paths {
        vector_of_mount_specifications.push(MountSpecification {
            path_buf_representing_host_source: PathBuf::from(string_slice_representing_dns_path),
            path_buf_representing_container_destination: PathBuf::from(string_slice_representing_dns_path),
            boolean_flag_indicating_readonly: true,
            boolean_flag_indicating_try_only: true,
        });
    }

    vector_of_mount_specifications
}

fn resolve_and_heal_mounts(
    vector_of_mount_specifications: Vec<MountSpecification>,
    sandbox_context_representing_runtime_environment: &SandboxContext,
) -> (Vec<String>, Vec<MountSpecification>) {
    let mut hash_set_representing_all_needed_container_directories = std::collections::HashSet::new();
    let mut vector_of_verified_mount_specifications: Vec<MountSpecification> = Vec::new();

    for mount_spec in vector_of_mount_specifications {
        if mount_spec.path_buf_representing_host_source.exists() {
            ensure_mount_point_exists_in_sandbox_home(
                &mount_spec.path_buf_representing_host_source,
                &sandbox_context_representing_runtime_environment.path_buf_representing_host_home_directory,
                &sandbox_context_representing_runtime_environment.path_buf_representing_sandbox_home_directory,
            );
            for string_representing_parent_dir in get_unique_non_system_parent_paths(&mount_spec.path_buf_representing_container_destination) {
                hash_set_representing_all_needed_container_directories.insert(string_representing_parent_dir);
            }
            vector_of_verified_mount_specifications.push(mount_spec);
        } else if !mount_spec.boolean_flag_indicating_try_only {
            let _ = std::fs::create_dir_all(&mount_spec.path_buf_representing_host_source);
            if mount_spec.path_buf_representing_host_source.exists() {
                ensure_mount_point_exists_in_sandbox_home(
                    &mount_spec.path_buf_representing_host_source,
                    &sandbox_context_representing_runtime_environment.path_buf_representing_host_home_directory,
                    &sandbox_context_representing_runtime_environment.path_buf_representing_sandbox_home_directory,
                );
                for string_representing_parent_dir in get_unique_non_system_parent_paths(&mount_spec.path_buf_representing_container_destination) {
                    hash_set_representing_all_needed_container_directories.insert(string_representing_parent_dir);
                }
                vector_of_verified_mount_specifications.push(mount_spec);
            }
        }
    }

    let mut vector_of_strings_representing_sorted_directories: Vec<String> = hash_set_representing_all_needed_container_directories.into_iter().collect();
    vector_of_strings_representing_sorted_directories.sort_by_key(|string_representing_path| string_representing_path.len());

    (vector_of_strings_representing_sorted_directories, vector_of_verified_mount_specifications)
}

fn assemble_bubblewrap_arguments_and_execute_process_replacement(
    sandbox_context_representing_runtime_environment: SandboxContext,
    target_specification_representing_validated_execution: TargetSpecification,
    vector_of_strings_representing_sorted_directories_to_create: Vec<String>,
    vector_of_verified_mount_specifications: Vec<MountSpecification>,
) -> ! {
    let mut vector_of_strings_representing_bubblewrap_command_arguments: Vec<String> = Vec::new();
    let pyramid = &sandbox_context_representing_runtime_environment.configuration_pyramid_representing_all_layers;

    // Base System Binds
    let array_of_strings_representing_standard_readonly_bind_mount_paths = ["/usr", "/etc", "/sys", "/proc"];
    for string_slice_representing_path_to_bind in array_of_strings_representing_standard_readonly_bind_mount_paths {
        if std::path::Path::new(string_slice_representing_path_to_bind).exists() {
            vector_of_strings_representing_bubblewrap_command_arguments.push(String::from("--ro-bind"));
            vector_of_strings_representing_bubblewrap_command_arguments.push(String::from(string_slice_representing_path_to_bind));
            vector_of_strings_representing_bubblewrap_command_arguments.push(String::from(string_slice_representing_path_to_bind));
        }
    }
    let array_of_strings_representing_conditional_readonly_bind_mount_paths = ["/bin", "/sbin", "/lib", "/lib64"];
    for string_slice_representing_path_to_bind in array_of_strings_representing_conditional_readonly_bind_mount_paths {
        if std::path::Path::new(string_slice_representing_path_to_bind).exists() {
            vector_of_strings_representing_bubblewrap_command_arguments.push(String::from("--ro-bind-try"));
            vector_of_strings_representing_bubblewrap_command_arguments.push(String::from(string_slice_representing_path_to_bind));
            vector_of_strings_representing_bubblewrap_command_arguments.push(String::from(string_slice_representing_path_to_bind));
        }
    }

    // Tmpfs
    vector_of_strings_representing_bubblewrap_command_arguments.push(String::from("--tmpfs"));
    vector_of_strings_representing_bubblewrap_command_arguments.push(String::from("/tmp"));
    vector_of_strings_representing_bubblewrap_command_arguments.push(String::from("--tmpfs"));
    vector_of_strings_representing_bubblewrap_command_arguments.push(String::from("/var"));
    vector_of_strings_representing_bubblewrap_command_arguments.push(String::from("--tmpfs"));
    vector_of_strings_representing_bubblewrap_command_arguments.push(String::from("/run"));

    // Namespaces
    if pyramid.resolve_configuration_value("WINER_NET", "1") == "0" {
        vector_of_strings_representing_bubblewrap_command_arguments.push(String::from("--unshare-net"));
    }
    if pyramid.resolve_configuration_value("WINER_SHARE_PID", "1") == "0" {
        vector_of_strings_representing_bubblewrap_command_arguments.push(String::from("--unshare-pid"));
    }
    if pyramid.resolve_configuration_value("WINER_IPC", "1") == "0" {
        eprintln!("[bwrap-winer] WARNING: IPC namespace unshared (WINER_IPC=0). Graphics acceleration or Vulkan may be unavailable.");
        vector_of_strings_representing_bubblewrap_command_arguments.push(String::from("--unshare-ipc"));
    }

    // Devices
    if pyramid.resolve_configuration_value("WINER_DEV", "1") == "1" {
        if std::path::Path::new("/dev").exists() {
            vector_of_strings_representing_bubblewrap_command_arguments.push(String::from("--dev-bind"));
            vector_of_strings_representing_bubblewrap_command_arguments.push(String::from("/dev"));
            vector_of_strings_representing_bubblewrap_command_arguments.push(String::from("/dev"));
        }
    } else {
        vector_of_strings_representing_bubblewrap_command_arguments.push(String::from("--dev"));
        vector_of_strings_representing_bubblewrap_command_arguments.push(String::from("/dev"));
        if std::path::Path::new("/dev/dri").exists() {
            vector_of_strings_representing_bubblewrap_command_arguments.push(String::from("--dev-bind"));
            vector_of_strings_representing_bubblewrap_command_arguments.push(String::from("/dev/dri"));
            vector_of_strings_representing_bubblewrap_command_arguments.push(String::from("/dev/dri"));
        }
        for unsigned_integer_index_representing_nvidia_device_node in 0..10 {
            let string_representing_nvidia_node_path = format!("/dev/nvidia{}", unsigned_integer_index_representing_nvidia_device_node);
            if std::path::Path::new(&string_representing_nvidia_node_path).exists() {
                vector_of_strings_representing_bubblewrap_command_arguments.push(String::from("--dev-bind"));
                vector_of_strings_representing_bubblewrap_command_arguments.push(string_representing_nvidia_node_path.clone());
                vector_of_strings_representing_bubblewrap_command_arguments.push(string_representing_nvidia_node_path);
            }
        }
        let array_of_strings_representing_nvidia_control_paths = [
            "/dev/nvidiactl", "/dev/nvidia-modeset", "/dev/nvidia-uvm", "/dev/nvidia-uvm-tools",
        ];
        for string_slice_representing_nvidia_control_path in array_of_strings_representing_nvidia_control_paths {
            if std::path::Path::new(string_slice_representing_nvidia_control_path).exists() {
                vector_of_strings_representing_bubblewrap_command_arguments.push(String::from("--dev-bind"));
                vector_of_strings_representing_bubblewrap_command_arguments.push(String::from(string_slice_representing_nvidia_control_path));
                vector_of_strings_representing_bubblewrap_command_arguments.push(String::from(string_slice_representing_nvidia_control_path));
            }
        }
    }

    // Create Dirs
    for string_representing_directory_to_create in vector_of_strings_representing_sorted_directories_to_create {
        vector_of_strings_representing_bubblewrap_command_arguments.push(String::from("--dir"));
        vector_of_strings_representing_bubblewrap_command_arguments.push(string_representing_directory_to_create);
    }

    // Core Home Mount
    let string_representing_host_home_directory_path = sandbox_context_representing_runtime_environment.path_buf_representing_host_home_directory.to_string_lossy().into_owned();
    let string_representing_sandbox_home_directory_path = sandbox_context_representing_runtime_environment.path_buf_representing_sandbox_home_directory.to_string_lossy().into_owned();
    vector_of_strings_representing_bubblewrap_command_arguments.push(String::from("--bind"));
    vector_of_strings_representing_bubblewrap_command_arguments.push(string_representing_sandbox_home_directory_path);
    vector_of_strings_representing_bubblewrap_command_arguments.push(string_representing_host_home_directory_path.clone());
    vector_of_strings_representing_bubblewrap_command_arguments.push(String::from("--setenv"));
    vector_of_strings_representing_bubblewrap_command_arguments.push(String::from("HOME"));
    vector_of_strings_representing_bubblewrap_command_arguments.push(string_representing_host_home_directory_path);
    vector_of_strings_representing_bubblewrap_command_arguments.push(String::from("--setenv"));
    vector_of_strings_representing_bubblewrap_command_arguments.push(String::from("USER"));
    vector_of_strings_representing_bubblewrap_command_arguments.push(sandbox_context_representing_runtime_environment.string_representing_host_username.clone());
    vector_of_strings_representing_bubblewrap_command_arguments.push(String::from("--setenv"));
    vector_of_strings_representing_bubblewrap_command_arguments.push(String::from("LOGNAME"));
    vector_of_strings_representing_bubblewrap_command_arguments.push(sandbox_context_representing_runtime_environment.string_representing_host_username);

    // Verified Mounts
    for verified_mount_spec in vector_of_verified_mount_specifications {
        let string_representing_host_source_path = verified_mount_spec.path_buf_representing_host_source.to_string_lossy().into_owned();
        let string_representing_container_destination_path = verified_mount_spec.path_buf_representing_container_destination.to_string_lossy().into_owned();
        if verified_mount_spec.boolean_flag_indicating_readonly {
            vector_of_strings_representing_bubblewrap_command_arguments.push(String::from("--ro-bind"));
        } else {
            vector_of_strings_representing_bubblewrap_command_arguments.push(String::from("--bind"));
        }
        vector_of_strings_representing_bubblewrap_command_arguments.push(string_representing_host_source_path);
        vector_of_strings_representing_bubblewrap_command_arguments.push(string_representing_container_destination_path);
    }

    // Custom Environment Variables Injection
    let mut hash_set_representing_all_configuration_keys = std::collections::HashSet::new();
    for string_representing_key in pyramid.hash_map_representing_global_configuration_keys_and_values.keys() {
        hash_set_representing_all_configuration_keys.insert(string_representing_key.clone());
    }
    for string_representing_key in pyramid.hash_map_representing_sandbox_specific_user_configuration_keys_and_values.keys() {
        hash_set_representing_all_configuration_keys.insert(string_representing_key.clone());
    }
    for string_representing_key in pyramid.hash_map_representing_sandbox_local_configuration_keys_and_values.keys() {
        hash_set_representing_all_configuration_keys.insert(string_representing_key.clone());
    }
    for string_representing_key in hash_set_representing_all_configuration_keys {
        if !string_representing_key.starts_with("WINER_") {
            let string_representing_resolved_value = pyramid.resolve_configuration_value(&string_representing_key, "");
            if !string_representing_resolved_value.is_empty() {
                vector_of_strings_representing_bubblewrap_command_arguments.push(String::from("--setenv"));
                vector_of_strings_representing_bubblewrap_command_arguments.push(string_representing_key);
                vector_of_strings_representing_bubblewrap_command_arguments.push(string_representing_resolved_value);
            }
        }
    }

    vector_of_strings_representing_bubblewrap_command_arguments.push(String::from("--unsetenv"));
    vector_of_strings_representing_bubblewrap_command_arguments.push(String::from("LD_PRELOAD"));
    vector_of_strings_representing_bubblewrap_command_arguments.push(String::from("--setenv"));
    vector_of_strings_representing_bubblewrap_command_arguments.push(String::from("GST_PLUGIN_PATH"));
    vector_of_strings_representing_bubblewrap_command_arguments.push(String::from(""));

    let string_representing_custom_wine_binary_path = pyramid.resolve_configuration_value("WINER_WINE_PATH", "wine");

    // LD_LIBRARY_PATH Magic Sniffing
    if pyramid.resolve_configuration_value("LD_LIBRARY_PATH", "").is_empty() {
        let string_representing_wine_path_lowercase = string_representing_custom_wine_binary_path.to_lowercase();
        if string_representing_wine_path_lowercase.ends_with("/wine") || string_representing_wine_path_lowercase.ends_with("/wine64") {
            let path_buf_representing_absolute_wine_path = std::fs::canonicalize(&string_representing_custom_wine_binary_path)
                .unwrap_or_else(|_| PathBuf::from(&string_representing_custom_wine_binary_path));
            if let Some(path_slice_representing_bin_directory) = path_buf_representing_absolute_wine_path.parent() {
                if let Some(path_slice_representing_runner_root_directory) = path_slice_representing_bin_directory.parent() {
                    let string_representing_runner_root_path = path_slice_representing_runner_root_directory.to_string_lossy().into_owned();
                    let string_representing_inferred_ld_library_path = format!(
                        "{}/lib:{}/lib64:{}/lib/wine/x86_64-unix:{}/lib32/wine/x86_64-unix:{}/lib64/wine/x86_64-unix",
                        string_representing_runner_root_path, string_representing_runner_root_path, string_representing_runner_root_path, string_representing_runner_root_path, string_representing_runner_root_path
                    );
                    vector_of_strings_representing_bubblewrap_command_arguments.push(String::from("--setenv"));
                    vector_of_strings_representing_bubblewrap_command_arguments.push(String::from("LD_LIBRARY_PATH"));
                    vector_of_strings_representing_bubblewrap_command_arguments.push(string_representing_inferred_ld_library_path);
                }
            }
        }
    }

    vector_of_strings_representing_bubblewrap_command_arguments.push(String::from("--die-with-parent"));

    let path_buf_representing_target_working_directory = if target_specification_representing_validated_execution.path_buf_representing_absolute_path_to_target_executable_file.is_file() {
        target_specification_representing_validated_execution.path_buf_representing_absolute_path_to_target_executable_file.parent()
            .map(|parent| parent.to_path_buf())
            .unwrap_or_else(|| sandbox_context_representing_runtime_environment.path_buf_representing_host_home_directory.clone())
    } else {
        target_specification_representing_validated_execution.path_buf_representing_absolute_path_to_target_executable_file.clone()
    };
    let string_representing_target_working_directory_path = path_buf_representing_target_working_directory.to_string_lossy().into_owned();
    vector_of_strings_representing_bubblewrap_command_arguments.push(String::from("--chdir"));
    vector_of_strings_representing_bubblewrap_command_arguments.push(string_representing_target_working_directory_path);

    // Inner Command Construction
    let mut vector_of_strings_representing_sandbox_inner_command_execution: Vec<String> = Vec::new();
    if pyramid.resolve_configuration_value("WINER_GAMEMODE", "0") == "1" {
        vector_of_strings_representing_sandbox_inner_command_execution.push(String::from("gamemoderun"));
    }
    if target_specification_representing_validated_execution.boolean_flag_indicating_wine_prefix_prepending_needed {
        vector_of_strings_representing_sandbox_inner_command_execution.push(string_representing_custom_wine_binary_path);
    }
    vector_of_strings_representing_sandbox_inner_command_execution.push(target_specification_representing_validated_execution.string_representing_raw_path_to_target_executable_file);
    
    for string_slice_representing_arg in pyramid.resolve_configuration_value("WINER_EXE_ARGS", "").split_whitespace() {
        if !string_slice_representing_arg.is_empty() {
            vector_of_strings_representing_sandbox_inner_command_execution.push(string_slice_representing_arg.to_string());
        }
    }
    for string_representing_cli_argument in target_specification_representing_validated_execution.vector_of_strings_representing_remaining_cli_arguments {
        vector_of_strings_representing_sandbox_inner_command_execution.push(string_representing_cli_argument);
    }
    for string_representing_inner_argument in vector_of_strings_representing_sandbox_inner_command_execution {
        vector_of_strings_representing_bubblewrap_command_arguments.push(string_representing_inner_argument);
    }

    let mut command_representing_final_process_replacement_invocation = std::process::Command::new("bwrap");
    command_representing_final_process_replacement_invocation.args(&vector_of_strings_representing_bubblewrap_command_arguments);
    let error_indicating_failed_process_replacement = command_representing_final_process_replacement_invocation.exec();

    eprintln!("[bwrap-winer] CRITICAL ERROR: Failed to execute process replacement system call: {:?}", error_indicating_failed_process_replacement);
    std::process::exit(1);
}

// ==========================================
// 🚀 主程序调度 (Application Entry Point)
// ==========================================
fn main() {
    let vector_of_strings_representing_command_line_arguments: Vec<String> = std::env::args().skip(1).collect();

    handle_help_command_if_needed(&vector_of_strings_representing_command_line_arguments);

    let (path_buf_representing_host_home_directory, string_representing_host_username, path_buf_representing_global_config_root) = 
        resolve_host_environment_base_paths();

    let path_buf_representing_global_configuration_file_path = path_buf_representing_global_config_root.join("config.toml");
    let hash_map_representing_global_configuration_keys_and_values = parse_simple_flat_toml_file_into_hash_map(&path_buf_representing_global_configuration_file_path);

    let path_buf_representing_sandbox_data_root_directory = resolve_sandbox_data_root_directory(
        &path_buf_representing_host_home_directory,
        &hash_map_representing_global_configuration_keys_and_values,
    );

    handle_list_command_if_needed(
        &vector_of_strings_representing_command_line_arguments,
        &path_buf_representing_sandbox_data_root_directory,
    );

    let (option_representing_raw_target_executable, vector_of_strings_representing_remaining_cli_arguments) = 
        parse_target_executable_and_remaining_arguments_from_cli(&vector_of_strings_representing_command_line_arguments);

    let string_representing_derived_sandbox_identifier = resolve_sandbox_identity(
        &option_representing_raw_target_executable,
        &hash_map_representing_global_configuration_keys_and_values,
    );

    let configuration_pyramid_representing_all_layers = load_configuration_hierarchy(
        &path_buf_representing_global_config_root,
        &path_buf_representing_sandbox_data_root_directory,
        &string_representing_derived_sandbox_identifier,
        hash_map_representing_global_configuration_keys_and_values,
    );

    let sandbox_context_representing_runtime_environment = SandboxContext {
        string_representing_derived_sandbox_identifier: string_representing_derived_sandbox_identifier.clone(),
        path_buf_representing_host_home_directory,
        string_representing_host_username,
        path_buf_representing_sandbox_home_directory: path_buf_representing_sandbox_data_root_directory.join(&string_representing_derived_sandbox_identifier).join("sandbox_home"),
        configuration_pyramid_representing_all_layers,
    };

    ensure_sandbox_root_and_home_directories_exist(&sandbox_context_representing_runtime_environment);

    let target_specification_representing_validated_execution = resolve_target_executable_and_validate(
        option_representing_raw_target_executable,
        vector_of_strings_representing_remaining_cli_arguments,
        &sandbox_context_representing_runtime_environment,
    );

    let vector_of_mount_specifications = collect_mount_specifications(
        &sandbox_context_representing_runtime_environment,
        &target_specification_representing_validated_execution,
    );

    let (vector_of_strings_representing_sorted_directories_to_create, vector_of_verified_mount_specifications) = 
        resolve_and_heal_mounts(
            vector_of_mount_specifications,
            &sandbox_context_representing_runtime_environment,
        );

    assemble_bubblewrap_arguments_and_execute_process_replacement(
        sandbox_context_representing_runtime_environment,
        target_specification_representing_validated_execution,
        vector_of_strings_representing_sorted_directories_to_create,
        vector_of_verified_mount_specifications,
    );
}
