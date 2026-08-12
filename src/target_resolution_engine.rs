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
    
    // 使用 ConfigurationPyramid 临时实例查询 WINEPREFIX，自动支持环境变量覆盖
    let temporary_early_stage_configuration_pyramid = crate::core_data_structures::ConfigurationPyramid::new(
        hash_map_representing_global_configuration_keys_and_values,
        std::collections::HashMap::new(),
        std::collections::HashMap::new(),
    );

    let string_representing_wine_prefix_resolved_value = temporary_early_stage_configuration_pyramid.resolve_configuration_value("WINEPREFIX", "");
    
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

/// 对目标字符串执行多重物理探测，支持自动附加 ".exe" 以适配 Windows 使用习惯。
/// 架构优化：优先在传入的“激活引擎目录”中搜索，从而建立一个专属于当前 Runner 的轻量级虚拟 PATH。
fn probe_host_physical_entity(
    string_slice_representing_raw_argument: &str,
    option_representing_active_engine_bin_dir: Option<&Path>,
) -> Option<PathBuf> {
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
            // 2. 优先搜寻当前激活引擎的 bin 目录
            if let Some(path_slice_representing_engine_bin_dir) = option_representing_active_engine_bin_dir {
                let path_buf_representing_candidate = path_slice_representing_engine_bin_dir.join(&string_representing_candidate_name);
                if path_buf_representing_candidate.exists() && path_buf_representing_candidate.is_file() {
                    return Some(fs_absolute_path_secure(&path_buf_representing_candidate));
                }
            }

            // 3. 宿主 Linux PATH 物理搜寻
            if let Ok(string_representing_env_path) = std::env::var("PATH") {
                for string_slice_representing_directory in string_representing_env_path.split(':') {
                    let path_buf_representing_candidate = Path::new(string_slice_representing_directory).join(&string_representing_candidate_name);
                    if path_buf_representing_candidate.exists() && path_buf_representing_candidate.is_file() {
                        return Some(fs_absolute_path_secure(&path_buf_representing_candidate));
                    }
                }
            }

            // 4. 当前工作目录 (CWD) 保底物理探测
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

/// 解析 Wine 引擎二进制在宿主机上的真实绝对路径（此时无需注入 bin 目录，避免死循环）
pub fn resolve_engine_binary_path(string_slice_representing_wine_path: &str) -> PathBuf {
    if string_slice_representing_wine_path.contains('/')
        || string_slice_representing_wine_path.contains('\\')
        || string_slice_representing_wine_path.starts_with('~')
    {
        fs_absolute_path_secure(Path::new(string_slice_representing_wine_path))
    } else if let Some(path_buf_found_in_path) = probe_host_physical_entity(string_slice_representing_wine_path, None) {
        path_buf_found_in_path
    } else {
        fs_absolute_path_secure(Path::new(string_slice_representing_wine_path))
    }
}


// ==========================================
// 🧠 阶段 3：多参数扫描器与意图结算核心引擎
// ==========================================

/// 内部临时数据结构：用于在扫描器、前缀注入器和结算器之间传递中间状态
struct IntermediateScannedArgumentsCollection {
    option_representing_primary_target_raw_input: Option<String>,
    option_representing_absolute_path_to_primary_target_executable: Option<PathBuf>,
    vector_of_strings_representing_launcher_prefix_commands: Vec<String>,
    vector_of_path_bufs_representing_secondary_penetration_mount_sources: Vec<PathBuf>,
    vector_of_strings_representing_remaining_cli_arguments: Vec<String>,
    boolean_flag_indicating_primary_target_found: bool,
}

/// 子步骤 3.1：执行多参数物理探针扫描，基于模式严格互斥原则处理 CLI 与 TOML
fn scan_and_collect_physical_entities_and_prefixes(
    vector_of_strings_representing_raw_target_and_arguments: Vec<String>,
    sandbox_context_representing_runtime_environment: &SandboxContext,
    option_representing_active_engine_bin_dir: Option<&Path>,
) -> IntermediateScannedArgumentsCollection {
    let pyramid = &sandbox_context_representing_runtime_environment.configuration_pyramid_representing_all_layers;

    let mut collection = IntermediateScannedArgumentsCollection {
        option_representing_primary_target_raw_input: None,
        option_representing_absolute_path_to_primary_target_executable: None,
        vector_of_strings_representing_launcher_prefix_commands: Vec::new(),
        vector_of_path_bufs_representing_secondary_penetration_mount_sources: Vec::new(),
        vector_of_strings_representing_remaining_cli_arguments: Vec::new(),
        boolean_flag_indicating_primary_target_found: false,
    };

    // 模式严格互斥分流：CLI 覆盖模式 vs TOML 默认模式
    if !vector_of_strings_representing_raw_target_and_arguments.is_empty() {
        // =====================================================================
        // 【模式 A：CLI 绝对直通模式】
        // 命令行传了位置参数！完全使用 CLI 传入的参数链跑探针，忽略 TOML/ENV 里的 EXE 变量
        // =====================================================================
        
        // 友好提示：检测 TOML/ENV 中是否存在将被绕过的目标配置，若存在则提醒用户
        let string_representing_ignored_toml_exe_path = pyramid.resolve_configuration_value("WINER_EXE_PATH", "");
        let string_representing_ignored_toml_exe_pre = pyramid.resolve_configuration_value("WINER_EXE_PRE", "");
        let string_representing_ignored_toml_exe_args = pyramid.resolve_configuration_value("WINER_EXE_ARGS", "");

        if !string_representing_ignored_toml_exe_path.is_empty()
            || !string_representing_ignored_toml_exe_pre.is_empty()
            || !string_representing_ignored_toml_exe_args.is_empty()
        {
            eprintln!("[bwrap-winer] NOTICE: Positional CLI arguments detected. Bypassing profile target configurations (WINER_EXE_PATH / WINER_EXE_PRE / WINER_EXE_ARGS) for this session.");
        }

        // 扫描器核心：对 CLI 参数从左到右执行探针
        for string_representing_current_argument in vector_of_strings_representing_raw_target_and_arguments.into_iter() {
            if !collection.boolean_flag_indicating_primary_target_found {
                if let Some(path_buf_representing_physical_absolute_path) = probe_host_physical_entity(&string_representing_current_argument, option_representing_active_engine_bin_dir) {
                    collection.boolean_flag_indicating_primary_target_found = true;
                    collection.option_representing_primary_target_raw_input = Some(string_representing_current_argument);
                    collection.option_representing_absolute_path_to_primary_target_executable = Some(path_buf_representing_physical_absolute_path);
                } else {
                    collection.vector_of_strings_representing_launcher_prefix_commands.push(string_representing_current_argument);
                }
            } else {
                collection.vector_of_strings_representing_remaining_cli_arguments.push(string_representing_current_argument.clone());
                if let Some(path_buf_representing_secondary_physical_absolute_path) = probe_host_physical_entity(&string_representing_current_argument, option_representing_active_engine_bin_dir) {
                    if let Some(path_slice_representing_parent) = path_buf_representing_secondary_physical_absolute_path.parent() {
                        collection.vector_of_path_bufs_representing_secondary_penetration_mount_sources.push(path_slice_representing_parent.to_path_buf());
                    }
                }
            }
        }
    } else {
        // =====================================================================
        // 【模式 B：纯 TOML / ENV 配置模式】
        // 命令行无位置参数！精确绑定 WINER_EXE_PRE、WINER_EXE_PATH 与 WINER_EXE_ARGS
        // =====================================================================
        
        // 1. 锚定主目标 (WINER_EXE_PATH)
        let string_representing_resolved_exe_path = pyramid.resolve_configuration_value("WINER_EXE_PATH", "");
        if string_representing_resolved_exe_path.is_empty() {
            eprintln!("[bwrap-winer] CRITICAL ERROR: Target executable could not be resolved from ENV, or TOML configs.");
            std::process::exit(1);
        }
        
        collection.option_representing_primary_target_raw_input = Some(string_representing_resolved_exe_path.clone());
        if let Some(path_buf_representing_primary_physical_path) = probe_host_physical_entity(&string_representing_resolved_exe_path, option_representing_active_engine_bin_dir) {
            collection.boolean_flag_indicating_primary_target_found = true;
            collection.option_representing_absolute_path_to_primary_target_executable = Some(path_buf_representing_primary_physical_path);
        }

        // 2. 收集前缀 (WINER_EXE_PRE)，若为物理补丁文件，自动追加二次挂载源
        let string_representing_resolved_prefix_cmd = pyramid.resolve_configuration_value("WINER_EXE_PRE", "");
        for string_slice_representing_prefix_token in string_representing_resolved_prefix_cmd.split_whitespace() {
            if !string_slice_representing_prefix_token.is_empty() {
                if let Some(path_buf_representing_prefix_physical_path) = probe_host_physical_entity(string_slice_representing_prefix_token, option_representing_active_engine_bin_dir) {
                    if let Some(path_slice_representing_parent) = path_buf_representing_prefix_physical_path.parent() {
                        collection.vector_of_path_bufs_representing_secondary_penetration_mount_sources.push(path_slice_representing_parent.to_path_buf());
                    }
                    collection.vector_of_strings_representing_launcher_prefix_commands.push(path_buf_representing_prefix_physical_path.to_string_lossy().into_owned());
                } else {
                    collection.vector_of_strings_representing_launcher_prefix_commands.push(string_slice_representing_prefix_token.to_string());
                }
            }
        }

        // 3. 收集主目标参数 (WINER_EXE_ARGS)
        let string_representing_resolved_exe_args = pyramid.resolve_configuration_value("WINER_EXE_ARGS", "");
        for string_slice_representing_arg_token in string_representing_resolved_exe_args.split_whitespace() {
            if !string_slice_representing_arg_token.is_empty() {
                collection.vector_of_strings_representing_remaining_cli_arguments.push(string_slice_representing_arg_token.to_string());
            }
        }
    }

    collection
}

/// 子步骤 3.2：安全地将 WINER_DESKTOP 插入到前缀指令链的最前端
fn inject_virtual_desktop_prefix_if_configured_and_safe(
    scanned_collection: &mut IntermediateScannedArgumentsCollection,
    sandbox_context_representing_runtime_environment: &SandboxContext,
) {
    let string_representing_desktop_resolution = sandbox_context_representing_runtime_environment
        .configuration_pyramid_representing_all_layers
        .resolve_configuration_value("WINER_DESKTOP", "");

    if !string_representing_desktop_resolution.is_empty() {
        let boolean_flag_already_contains_explorer_prefix = scanned_collection.vector_of_strings_representing_launcher_prefix_commands
            .iter()
            .any(|string_representing_arg| {
                let string_representing_arg_lowercase = string_representing_arg.to_lowercase();
                string_representing_arg_lowercase == "explorer" 
                || string_representing_arg_lowercase == "explorer.exe"
                || string_representing_arg_lowercase.starts_with("/desktop=")
                || string_representing_arg_lowercase.starts_with("-desktop=")
            });

        if !boolean_flag_already_contains_explorer_prefix {
            let string_representing_desktop_argument = format!("/desktop=sandbox,{}", string_representing_desktop_resolution);
            // 必须插入到最前端，确保虚拟桌面包裹一切后续工具 (如补丁注入器)
            scanned_collection.vector_of_strings_representing_launcher_prefix_commands.insert(0, string_representing_desktop_argument);
            scanned_collection.vector_of_strings_representing_launcher_prefix_commands.insert(0, String::from("explorer"));
        }
    }
}

/// 子步骤 3.3：执行 VFS 解引用比对，决算出最终的强类型 TargetCategory 意图分类
/// 架构回归纯粹：由于探针已经具备引擎优先视野，这里直接恢复最纯粹的原版解引用对比！
fn disambiguate_target_intent_and_build_specification(
    mut scanned_collection: IntermediateScannedArgumentsCollection,
    path_buf_representing_secured_engine_path: PathBuf,
) -> TargetSpecification {
    let target_category_enum_representing_execution_type: TargetCategory;
    
    if scanned_collection.boolean_flag_indicating_primary_target_found {
        let path_buf_representing_physical_absolute_path = scanned_collection.option_representing_absolute_path_to_primary_target_executable.clone().unwrap();
        
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
                string_representing_subcommand_name: scanned_collection.option_representing_primary_target_raw_input.clone().unwrap(),
            };
            // 物理路径重置为空，彻底防范家目录穿透挂载
            scanned_collection.option_representing_absolute_path_to_primary_target_executable = None;
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
        if !scanned_collection.vector_of_strings_representing_launcher_prefix_commands.is_empty() {
            let string_representing_virtual_command = scanned_collection.vector_of_strings_representing_launcher_prefix_commands.remove(0);
            scanned_collection.option_representing_primary_target_raw_input = Some(string_representing_virtual_command.clone());
            
            // 将剩余的所有伪前缀倒推回目标参数列表中
            let mut vector_of_strings_representing_new_remaining_args = scanned_collection.vector_of_strings_representing_launcher_prefix_commands.clone();
            vector_of_strings_representing_new_remaining_args.append(&mut scanned_collection.vector_of_strings_representing_remaining_cli_arguments);
            scanned_collection.vector_of_strings_representing_remaining_cli_arguments = vector_of_strings_representing_new_remaining_args;
            
            // 清空前缀链
            scanned_collection.vector_of_strings_representing_launcher_prefix_commands.clear();
            
            target_category_enum_representing_execution_type = TargetCategory::VirtualWineCommand {
                string_representing_command_name: string_representing_virtual_command,
            };
        } else {
            eprintln!("[bwrap-winer] CRITICAL ERROR: Execution pipeline failed to establish any target command.");
            std::process::exit(1);
        }
    }

    TargetSpecification {
        string_representing_raw_user_input_target: scanned_collection.option_representing_primary_target_raw_input.unwrap(),
        option_representing_absolute_path_to_primary_target_executable: scanned_collection.option_representing_absolute_path_to_primary_target_executable,
        vector_of_strings_representing_launcher_prefix_commands: scanned_collection.vector_of_strings_representing_launcher_prefix_commands,
        vector_of_path_bufs_representing_secondary_penetration_mount_sources: scanned_collection.vector_of_path_bufs_representing_secondary_penetration_mount_sources,
        target_category_enum_representing_execution_type,
        vector_of_strings_representing_remaining_cli_arguments: scanned_collection.vector_of_strings_representing_remaining_cli_arguments,
    }
}

/// 主协调器：执行基于“双轨意图-现实对照”的零白名单解引用与分类算法。
pub fn resolve_target_executable_and_validate_via_multi_arg_scanner(
    vector_of_strings_representing_raw_target_and_arguments: Vec<String>,
    sandbox_context_representing_runtime_environment: &SandboxContext,
    option_representing_cli_custom_wine_path: &Option<String>,
) -> TargetSpecification {
    let string_representing_custom_wine_binary_path = if let Some(string_representing_cli_wine_path) = option_representing_cli_custom_wine_path {
        string_representing_cli_wine_path.clone()
    } else {
        sandbox_context_representing_runtime_environment.configuration_pyramid_representing_all_layers.resolve_configuration_value("WINER_WINE_PATH", "wine")
    };

    // 新增：将引擎解析彻底前置，并提取其 bin 目录供探针优先使用
    let path_buf_representing_secured_engine_path = resolve_engine_binary_path(&string_representing_custom_wine_binary_path);
    let option_representing_active_engine_bin_dir = path_buf_representing_secured_engine_path.parent();

    // 步骤 1：扫描 (已融入 CLI 覆盖 vs TOML 默认的严格互斥)
    let mut scanned_collection = scan_and_collect_physical_entities_and_prefixes(
        vector_of_strings_representing_raw_target_and_arguments,
        sandbox_context_representing_runtime_environment,
        option_representing_active_engine_bin_dir,
    );

    // 步骤 2：虚拟桌面安全注入 (确保排在前缀最前列)
    inject_virtual_desktop_prefix_if_configured_and_safe(
        &mut scanned_collection,
        sandbox_context_representing_runtime_environment,
    );

    // 步骤 3：结算并返回最终实体
    disambiguate_target_intent_and_build_specification(
        scanned_collection,
        path_buf_representing_secured_engine_path,
    )
}
