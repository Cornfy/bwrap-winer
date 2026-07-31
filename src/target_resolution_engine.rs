use std::path::{Path, PathBuf};

use crate::core_data_structures::{TargetCategory, TargetSpecification, SandboxContext};
use crate::file_system_utilities::{
    fs_absolute_path_secure,
    check_if_file_is_linux_native_elf,
    calculate_fnv1a_64_bit_hash_of_string,
    generate_slug_from_absolute_filesystem_path,
};

// ==========================================
// 🚀 阶段 1：基础 CLI 解析与 ID 推导
// ==========================================

/// 从 CLI 提取原始参数，剥离可能的自定义 Wine 引擎声明
pub fn parse_target_executable_and_remaining_arguments_from_cli(
    vector_of_strings_representing_command_line_arguments: &[String]
) -> (Option<String>, Vec<String>) {
    let mut option_representing_cli_custom_wine_path: Option<String> = None;
    let mut vector_of_strings_representing_raw_target_and_arguments: Vec<String> = Vec::new();

    if !vector_of_strings_representing_command_line_arguments.is_empty() {
        let string_representing_first_argument = &vector_of_strings_representing_command_line_arguments[0];
        let string_representing_first_argument_lowercase = string_representing_first_argument.to_lowercase();
        
        if (string_representing_first_argument_lowercase == "wine"
            || string_representing_first_argument_lowercase == "wine64"
            || string_representing_first_argument_lowercase.ends_with("/wine")
            || string_representing_first_argument_lowercase.ends_with("/wine64"))
            && vector_of_strings_representing_command_line_arguments.len() > 1
        {
            option_representing_cli_custom_wine_path = Some(string_representing_first_argument.clone());
            vector_of_strings_representing_raw_target_and_arguments = vector_of_strings_representing_command_line_arguments.iter().skip(1).cloned().collect();
        } else {
            vector_of_strings_representing_raw_target_and_arguments = vector_of_strings_representing_command_line_arguments.to_vec();
        }
    }
    
    // 如果命令行根本没给参数，尝试从环境变量兜底，以保证无参启动支持
    if vector_of_strings_representing_raw_target_and_arguments.is_empty() {
        if let Ok(string_representing_env_exe_path) = std::env::var("WINER_EXE_PATH") {
            vector_of_strings_representing_raw_target_and_arguments.push(string_representing_env_exe_path);
        }
    }

    (option_representing_cli_custom_wine_path, vector_of_strings_representing_raw_target_and_arguments)
}

/// 解析绝对唯一的沙箱身份标识 (WINER_ID)
pub fn resolve_sandbox_identity(
    vector_of_strings_representing_raw_target_and_arguments: &[String],
    path_buf_representing_global_config_root: &Path,
) -> String {
    if let Ok(string_representing_explicit_sandbox_id) = std::env::var("WINER_ID") {
        return string_representing_explicit_sandbox_id;
    } 
    
    // 快速读取全局配置中的 WINER_ID 或 WINEPREFIX
    let path_buf_representing_global_configuration_file_path = path_buf_representing_global_config_root.join("config.toml");
    let hash_map_representing_global_configuration_keys_and_values = crate::configuration_management::parse_simple_flat_toml_file_into_hash_map(&path_buf_representing_global_configuration_file_path);
    
    if let Some(string_representing_global_sandbox_id) = hash_map_representing_global_configuration_keys_and_values.get("WINER_ID") {
        return string_representing_global_sandbox_id.clone();
    }
    
    let string_representing_wine_prefix_resolved_value = crate::configuration_management::resolve_configuration_value_from_hierarchical_sources(
        "WINEPREFIX", &std::collections::HashMap::new(), &std::collections::HashMap::new(), &hash_map_representing_global_configuration_keys_and_values, ""
    );
    
    if !string_representing_wine_prefix_resolved_value.is_empty() {
        let path_buf_representing_explicit_wine_prefix = fs_absolute_path_secure(Path::new(&string_representing_wine_prefix_resolved_value));
        let string_representing_prefix_slug = generate_slug_from_absolute_filesystem_path(&path_buf_representing_explicit_wine_prefix);
        let string_representing_prefix_hash = calculate_fnv1a_64_bit_hash_of_string(&path_buf_representing_explicit_wine_prefix.to_string_lossy());
        return format!("{}-{}", string_representing_prefix_slug, string_representing_prefix_hash);
    }
    
    if !vector_of_strings_representing_raw_target_and_arguments.is_empty() {
        // [极简探测容错] 因为 ID 推导比较早期，为了保证省略 .exe 的参数也能推导一致，做一个最轻量的尝试
        let string_representing_first_arg = &vector_of_strings_representing_raw_target_and_arguments[0];
        let path_buf_representing_first_arg = fs_absolute_path_secure(Path::new(string_representing_first_arg));
        
        let path_buf_representing_final_id_target = if !path_buf_representing_first_arg.exists() && !string_representing_first_arg.to_lowercase().ends_with(".exe") {
            let path_buf_representing_exe_fallback = fs_absolute_path_secure(Path::new(&format!("{}.exe", string_representing_first_arg)));
            if path_buf_representing_exe_fallback.exists() { path_buf_representing_exe_fallback } else { path_buf_representing_first_arg }
        } else {
            path_buf_representing_first_arg
        };

        let string_representing_executable_slug = generate_slug_from_absolute_filesystem_path(&path_buf_representing_final_id_target);
        let string_representing_executable_hash = calculate_fnv1a_64_bit_hash_of_string(&path_buf_representing_final_id_target.to_string_lossy());
        return format!("{}-{}", string_representing_executable_slug, string_representing_executable_hash);
    }

    eprintln!("[bwrap-winer] CRITICAL ERROR: Target executable or WINER_ID not specified.");
    std::process::exit(1);
}

// ==========================================
// 🔬 阶段 2：纯粹宿主物理实体探针
// ==========================================

/// 对目标字符串执行 3 重纯粹物理探测，支持自动附加 ".exe" 以适配 Windows 使用习惯。
/// 不涉及任何 Wine 特定逻辑，只陈述物理磁盘的客观事实。
fn probe_host_physical_entity(string_slice_representing_raw_argument: &str) -> Option<PathBuf> {
    let array_of_strings_representing_candidate_names = if string_slice_representing_raw_argument.to_lowercase().ends_with(".exe") 
        || string_slice_representing_raw_argument.to_lowercase().ends_with(".bat") 
        || string_slice_representing_raw_argument.to_lowercase().ends_with(".msi") 
    {
        vec![string_slice_representing_raw_argument.to_string()]
    } else {
        // .exe 容错探测扩展
        vec![string_slice_representing_raw_argument.to_string(), format!("{}.exe", string_slice_representing_raw_argument)]
    };

    for string_representing_candidate_name in array_of_strings_representing_candidate_names {
        // 1. 显式路径探测（带正反斜杠）
        if string_representing_candidate_name.contains('/') || string_representing_candidate_name.contains('\\') || string_representing_candidate_name.starts_with("~") {
            let path_buf_representing_candidate = fs_absolute_path_secure(Path::new(&string_representing_candidate_name));
            if path_buf_representing_candidate.exists() && path_buf_representing_candidate.is_file() {
                return Some(path_buf_representing_candidate);
            }
        } else {
            // 2. 宿主 Linux PATH 物理搜寻
            if let Ok(string_representing_env_path) = std::env::var("PATH") {
                for string_slice_representing_directory in string_representing_env_path.split(':') {
                    let path_buf_representing_candidate = Path::new(string_slice_representing_directory).join(&string_representing_candidate_name);
                    if path_buf_representing_candidate.exists() && path_buf_representing_candidate.is_file() {
                        return Some(fs_absolute_path_secure(&path_buf_representing_candidate));
                    }
                }
            }

            // 3. 当前工作目录 (CWD) 保底物理探测
            if let Ok(path_buf_representing_cwd) = std::env::current_dir() {
                let path_buf_representing_candidate = path_buf_representing_cwd.join(&string_representing_candidate_name);
                if path_buf_representing_candidate.exists() && path_buf_representing_candidate.is_file() {
                    return Some(fs_absolute_path_secure(&path_buf_representing_candidate));
                }
            }
        }
    }
    None
}

// ==========================================
// 🧠 阶段 3：多参数扫描器与意图结算核心引擎
// ==========================================

/// 多参数物理探针扫描器：执行基于“双轨意图-现实对照”的零白名单解引用与分类算法。
pub fn resolve_target_executable_and_validate_via_multi_arg_scanner(
    vector_of_strings_representing_raw_target_and_arguments: Vec<String>,
    sandbox_context_representing_runtime_environment: &SandboxContext,
    option_representing_cli_custom_wine_path: &Option<String>,
) -> TargetSpecification {
    
    // 如果没有参数，尝试从 TOML 中补齐
    let mut vector_of_strings_representing_all_arguments = vector_of_strings_representing_raw_target_and_arguments.clone();
    if vector_of_strings_representing_all_arguments.is_empty() {
        let string_representing_resolved_exe_path = sandbox_context_representing_runtime_environment.configuration_pyramid_representing_all_layers.resolve_configuration_value("WINER_EXE_PATH", "");
        if string_representing_resolved_exe_path.is_empty() {
            eprintln!("[bwrap-winer] CRITICAL ERROR: Target executable could not be resolved from CLI, ENV, or TOML configs.");
            std::process::exit(1);
        }
        vector_of_strings_representing_all_arguments.push(string_representing_resolved_exe_path);
        
        let string_representing_resolved_exe_args = sandbox_context_representing_runtime_environment.configuration_pyramid_representing_all_layers.resolve_configuration_value("WINER_EXE_ARGS", "");
        for string_slice_representing_arg in string_representing_resolved_exe_args.split_whitespace() {
            vector_of_strings_representing_all_arguments.push(string_slice_representing_arg.to_string());
        }
    }

    let string_representing_custom_wine_binary_path = if let Some(string_representing_cli_wine_path) = option_representing_cli_custom_wine_path {
        string_representing_cli_wine_path.clone()
    } else {
        sandbox_context_representing_runtime_environment.configuration_pyramid_representing_all_layers.resolve_configuration_value("WINER_WINE_PATH", "wine")
    };

    let mut vector_of_strings_representing_launcher_prefix_commands = Vec::new();
    let mut vector_of_path_bufs_representing_secondary_penetration_mount_sources = Vec::new();
    
    let mut option_representing_primary_target_raw_input: Option<String> = None;
    let mut option_representing_absolute_path_to_primary_target_executable: Option<PathBuf> = None;
    let mut vector_of_strings_representing_remaining_cli_arguments = Vec::new();
    
    let mut boolean_flag_indicating_primary_target_found = false;

    // 扫描器核心：从左到右执行探针
    for string_representing_current_argument in vector_of_strings_representing_all_arguments.into_iter() {
        if !boolean_flag_indicating_primary_target_found {
            // 寻找第一个物理实体
            let option_representing_probed_physical_path = probe_host_physical_entity(&string_representing_current_argument);
            
            if let Some(path_buf_representing_physical_absolute_path) = option_representing_probed_physical_path {
                // 命中首个物理实体，锁定为主目标 (Primary Target)
                boolean_flag_indicating_primary_target_found = true;
                option_representing_primary_target_raw_input = Some(string_representing_current_argument);
                option_representing_absolute_path_to_primary_target_executable = Some(path_buf_representing_physical_absolute_path.clone());
            } else {
                // 未命中物理实体，视为前缀指令链的一部分 (Launcher Prefix)
                vector_of_strings_representing_launcher_prefix_commands.push(string_representing_current_argument);
            }
        } else {
            // 主目标已锁定，所有后续参数归入 Target Args
            vector_of_strings_representing_remaining_cli_arguments.push(string_representing_current_argument.clone());
            
            // 自动追加探测后续参数，若为物理文件，加入二次挂载源（完美兼容 Mod/补丁 注入链）
            let option_representing_probed_secondary_physical_path = probe_host_physical_entity(&string_representing_current_argument);
            if let Some(path_buf_representing_secondary_physical_absolute_path) = option_representing_probed_secondary_physical_path {
                if let Some(path_slice_representing_parent) = path_buf_representing_secondary_physical_absolute_path.parent() {
                    vector_of_path_bufs_representing_secondary_penetration_mount_sources.push(path_slice_representing_parent.to_path_buf());
                }
            }
        }
    }

    // 意图结算与分流 (Disambiguation)
    let target_category_enum_representing_execution_type: TargetCategory;
    
    if boolean_flag_indicating_primary_target_found {
        let path_buf_representing_physical_absolute_path = option_representing_absolute_path_to_primary_target_executable.clone().unwrap();
        
        // 核心解引用等价性比对
        let path_buf_representing_secured_engine_path = fs_absolute_path_secure(Path::new(&string_representing_custom_wine_binary_path));
        let mut boolean_flag_indicating_is_wine_multicall_symlink = false;
        
        if let (Ok(path_buf_representing_real_target), Ok(path_buf_representing_real_engine)) = (
            std::fs::canonicalize(&path_buf_representing_physical_absolute_path),
            std::fs::canonicalize(&path_buf_representing_secured_engine_path)
        ) {
            if path_buf_representing_real_target == path_buf_representing_real_engine {
                boolean_flag_indicating_is_wine_multicall_symlink = true;
            }
        }

        if boolean_flag_indicating_is_wine_multicall_symlink {
            // 分支 3A: 确认为 Wine 多路复用工具
            target_category_enum_representing_execution_type = TargetCategory::WineMulticallTool {
                string_representing_subcommand_name: option_representing_primary_target_raw_input.clone().unwrap(),
            };
            // 物理路径重置为空，彻底防范家目录穿透挂载
            option_representing_absolute_path_to_primary_target_executable = None;
        } else {
            // 分支 3B: 宿主机外部物理文件
            if check_if_file_is_linux_native_elf(&path_buf_representing_physical_absolute_path) {
                eprintln!("[bwrap-winer] SECURITY BLOCK: '{:?}' is a native Linux ELF binary.", path_buf_representing_physical_absolute_path);
                eprintln!("[bwrap-winer] Refusing to run native Linux programs to prevent sandbox escape.");
                std::process::exit(1);
            } else {
                target_category_enum_representing_execution_type = TargetCategory::PhysicalWindowsExecutable {
                    path_buf_representing_host_absolute_path: path_buf_representing_physical_absolute_path,
                };
            }
        }
    } else {
        // 分支 4: 扫描全过程均未发现物理文件
        // 原第一参数成为 Virtual Command，其余参数全部移入 remaining args
        if !vector_of_strings_representing_launcher_prefix_commands.is_empty() {
            let string_representing_virtual_command = vector_of_strings_representing_launcher_prefix_commands.remove(0);
            option_representing_primary_target_raw_input = Some(string_representing_virtual_command.clone());
            
            // 将剩余的所有伪前缀倒推回目标参数列表中
            let mut vector_of_strings_representing_new_remaining_args = vector_of_strings_representing_launcher_prefix_commands.clone();
            vector_of_strings_representing_new_remaining_args.append(&mut vector_of_strings_representing_remaining_cli_arguments);
            vector_of_strings_representing_remaining_cli_arguments = vector_of_strings_representing_new_remaining_args;
            
            // 清空前缀链
            vector_of_strings_representing_launcher_prefix_commands.clear();
            
            target_category_enum_representing_execution_type = TargetCategory::VirtualWineCommand {
                string_representing_command_name: string_representing_virtual_command,
            };
        } else {
            eprintln!("[bwrap-winer] CRITICAL ERROR: Execution pipeline failed to establish any target command.");
            std::process::exit(1);
        }
    }

    TargetSpecification {
        string_representing_raw_user_input_target: option_representing_primary_target_raw_input.unwrap(),
        option_representing_absolute_path_to_primary_target_executable,
        vector_of_strings_representing_launcher_prefix_commands,
        vector_of_path_bufs_representing_secondary_penetration_mount_sources,
        target_category_enum_representing_execution_type,
        vector_of_strings_representing_remaining_cli_arguments,
    }
}
