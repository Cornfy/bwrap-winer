use std::collections::HashMap;
use std::path::{Path, PathBuf};

use crate::file_system_utilities::expand_tilde_in_configuration_value;
use crate::core_data_structures::ConfigurationPyramid;

// ==========================================
// 🛠️ TOML 解析与金字塔配置级联核心
// ==========================================

/// 纯标准库实现的高效扁平 TOML/配置文件解析器，支持过滤整行注释、行尾注释及剔除包裹引号。
pub fn parse_simple_flat_toml_file_into_hash_map(
    path_to_configuration_file: &Path,
) -> HashMap<String, String> {
    let mut hash_map_representing_configuration_keys_and_values = HashMap::new();
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

/// 5 层金字塔链式覆盖器：级联查询目标值。
pub fn resolve_configuration_value_from_hierarchical_sources(
    string_slice_representing_variable_key: &str,
    hash_map_representing_sandbox_local_data_config: &HashMap<String, String>,
    hash_map_representing_sandbox_specific_user_config: &HashMap<String, String>,
    hash_map_representing_global_config: &HashMap<String, String>,
    string_slice_representing_hardcoded_default_value: &str,
) -> String {
    // 1. 环境变量 (最高优先级)
    if let Ok(string_representing_env_value) = std::env::var(string_slice_representing_variable_key) {
        return expand_tilde_in_configuration_value(string_representing_env_value);
    }
    // 2. 局部沙箱运行时状态配置 (XDG_DATA_HOME/sandboxes/[ID]/winer_meta.toml)
    if let Some(string_representing_sandbox_value) = hash_map_representing_sandbox_local_data_config.get(string_slice_representing_variable_key) {
        return expand_tilde_in_configuration_value(string_representing_sandbox_value.clone());
    }
    // 3. 用户个人专属沙箱配置 (XDG_CONFIG_HOME/bwrap-winer/[ID].toml)
    if let Some(string_representing_sandbox_user_value) = hash_map_representing_sandbox_specific_user_config.get(string_slice_representing_variable_key) {
        return expand_tilde_in_configuration_value(string_representing_sandbox_user_value.clone());
    }
    // 4. 全局通用配置 (XDG_CONFIG_HOME/bwrap-winer/config.toml)
    if let Some(string_representing_global_value) = hash_map_representing_global_config.get(string_slice_representing_variable_key) {
        return expand_tilde_in_configuration_value(string_representing_global_value.clone());
    }
    // 5. 硬编码保底 (最低优先级)
    expand_tilde_in_configuration_value(string_slice_representing_hardcoded_default_value.to_string())
}

// ==========================================
// 🚀 XDG 基础路径与持久化目录推导
// ==========================================

/// 获取宿主机环境的最基础变量：Home 目录、当前用户、以及 XDG 配置根目录
pub fn resolve_host_environment_base_paths() -> (PathBuf, String, PathBuf) {
    let path_buf_representing_host_home_directory = std::env::var_os("HOME")
        .map(PathBuf::from)
        .expect("[bwrap-winer] CRITICAL ERROR: HOME environment variable is not set on the host system");

    let string_representing_host_username = std::env::var("USER")
        .unwrap_or_else(|_| String::from("wineruser"));

    let path_buf_representing_global_config_root = std::env::var_os("XDG_CONFIG_HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|| path_buf_representing_host_home_directory.join(".config"))
        .join("bwrap-winer");

    (path_buf_representing_host_home_directory, string_representing_host_username, path_buf_representing_global_config_root)
}

/// 解析数据根目录 (Data Root)。允许在基础全局配置中通过 WINER_DATA_ROOT 覆盖默认位置。
pub fn resolve_sandbox_data_root_directory(
    path_buf_representing_host_home_directory: &Path,
    path_buf_representing_global_config_root: &Path,
) -> PathBuf {
    // 提前单次解析全局 config.toml，仅用于在此处推导数据存储位置被覆盖的情况
    let path_buf_representing_global_configuration_file_path = path_buf_representing_global_config_root.join("config.toml");
    let hash_map_representing_global_configuration_keys_and_values = parse_simple_flat_toml_file_into_hash_map(&path_buf_representing_global_configuration_file_path);

    let path_buf_representing_default_data_root = std::env::var_os("XDG_DATA_HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|| path_buf_representing_host_home_directory.join(".local/share"))
        .join("bwrap-winer/sandboxes");

    let string_representing_data_root_resolved_value = resolve_configuration_value_from_hierarchical_sources(
        "WINER_DATA_ROOT",
        &HashMap::new(),
        &HashMap::new(),
        &hash_map_representing_global_configuration_keys_and_values,
        &path_buf_representing_default_data_root.to_string_lossy(),
    );
    PathBuf::from(string_representing_data_root_resolved_value)
}

/// 一次性加载 3 个维度的 TOML 配置文件并组装成配置金字塔实体
pub fn load_configuration_hierarchy(
    path_buf_representing_global_config_root: &Path,
    path_buf_representing_sandbox_data_root_directory: &Path,
    string_representing_derived_sandbox_identifier: &str,
) -> ConfigurationPyramid {
    let path_buf_representing_global_configuration_file_path = path_buf_representing_global_config_root.join("config.toml");
    let hash_map_representing_global_configuration_keys_and_values = parse_simple_flat_toml_file_into_hash_map(
        &path_buf_representing_global_configuration_file_path,
    );

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
