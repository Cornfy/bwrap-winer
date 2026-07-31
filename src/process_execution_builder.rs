use std::os::unix::process::CommandExt;
use std::path::Path;

use crate::core_data_structures::{MountSpecification, SandboxContext, TargetCategory, TargetSpecification};
use crate::file_system_utilities::{fs_absolute_path_secure, resolve_wine_runner_root_directory_from_binary_path};

// ==========================================
// 💡 命令行基础调度与帮助信息
// ==========================================

pub fn print_bwrap_winer_help_information() {
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
    println!("    [3] User Sandbox Config ([WINER_ID].toml)        (Dotfiles-friendly profiles in XDG_CONFIG_HOME)");
    println!("    [4] Global User Config (config.toml)               (Global engineering configuration)");
    println!("    [5] Hardcoded default values                       (System-wide fallback security)");
    println!();
    println!("COMPLIANT PATHS (XDG BASE DIRECTORY SPECIFICATION):");
    println!("    Global Config  $XDG_CONFIG_HOME/bwrap-winer/config.toml             (Default: ~/.config/...)");
    println!("    User Profile   $XDG_CONFIG_HOME/bwrap-winer/[WINER_ID].toml");
    println!("    Sandbox Root   $XDG_DATA_HOME/bwrap-winer/sandboxes/                (Default: ~/.local/share/...)");
    println!("    Runtime Meta   $XDG_DATA_HOME/bwrap-winer/sandboxes/[WINER_ID]/winer_meta.toml");
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

pub fn handle_help_command_if_needed(vector_of_strings_representing_command_line_arguments: &[String]) {
    if vector_of_strings_representing_command_line_arguments.is_empty()
        || vector_of_strings_representing_command_line_arguments[0] == "-h"
        || vector_of_strings_representing_command_line_arguments[0] == "--help"
    {
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

pub fn handle_list_command_if_needed(
    vector_of_strings_representing_command_line_arguments: &[String],
    path_buf_representing_sandbox_data_root_directory: &Path,
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

// ==========================================
// 🚀 终局管线：容器指令替换执行器
// ==========================================

pub fn assemble_bubblewrap_arguments_and_execute_process_replacement(
    sandbox_context_representing_runtime_environment: SandboxContext,
    target_specification_representing_validated_execution: TargetSpecification,
    vector_of_strings_representing_sorted_directories_to_create: Vec<String>,
    vector_of_verified_mount_specifications: Vec<MountSpecification>,
    option_representing_cli_custom_wine_path: Option<String>,
) -> ! {
    let mut vector_of_strings_representing_bubblewrap_command_arguments: Vec<String> = Vec::new();
    let pyramid = &sandbox_context_representing_runtime_environment.configuration_pyramid_representing_all_layers;

    let path_buf_representing_canonicalized_sandbox_home = fs_absolute_path_secure(&sandbox_context_representing_runtime_environment.path_buf_representing_sandbox_home_directory);

    // ==========================================
    // 1. 系统核心挂载、挂载点创建及硬件节点
    // ==========================================

    let array_of_strings_representing_standard_readonly_bind_mount_paths = ["/usr", "/etc", "/sys", "/proc"];
    for string_slice_representing_path_to_bind in array_of_strings_representing_standard_readonly_bind_mount_paths {
        if Path::new(string_slice_representing_path_to_bind).exists() {
            vector_of_strings_representing_bubblewrap_command_arguments.push(String::from("--ro-bind"));
            vector_of_strings_representing_bubblewrap_command_arguments.push(String::from(string_slice_representing_path_to_bind));
            vector_of_strings_representing_bubblewrap_command_arguments.push(String::from(string_slice_representing_path_to_bind));
        }
    }
    let array_of_strings_representing_conditional_readonly_bind_mount_paths = ["/bin", "/sbin", "/lib", "/lib64"];
    for string_slice_representing_path_to_bind in array_of_strings_representing_conditional_readonly_bind_mount_paths {
        if Path::new(string_slice_representing_path_to_bind).exists() {
            vector_of_strings_representing_bubblewrap_command_arguments.push(String::from("--ro-bind-try"));
            vector_of_strings_representing_bubblewrap_command_arguments.push(String::from(string_slice_representing_path_to_bind));
            vector_of_strings_representing_bubblewrap_command_arguments.push(String::from(string_slice_representing_path_to_bind));
        }
    }

    vector_of_strings_representing_bubblewrap_command_arguments.push(String::from("--tmpfs"));
    vector_of_strings_representing_bubblewrap_command_arguments.push(String::from("/tmp"));
    vector_of_strings_representing_bubblewrap_command_arguments.push(String::from("--tmpfs"));
    vector_of_strings_representing_bubblewrap_command_arguments.push(String::from("/var"));
    vector_of_strings_representing_bubblewrap_command_arguments.push(String::from("--tmpfs"));
    vector_of_strings_representing_bubblewrap_command_arguments.push(String::from("/run"));

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

    if pyramid.resolve_configuration_value("WINER_DEV", "1") == "1" {
        if Path::new("/dev").exists() {
            vector_of_strings_representing_bubblewrap_command_arguments.push(String::from("--dev-bind"));
            vector_of_strings_representing_bubblewrap_command_arguments.push(String::from("/dev"));
            vector_of_strings_representing_bubblewrap_command_arguments.push(String::from("/dev"));
        }
    } else {
        vector_of_strings_representing_bubblewrap_command_arguments.push(String::from("--dev"));
        vector_of_strings_representing_bubblewrap_command_arguments.push(String::from("/dev"));
        if Path::new("/dev/dri").exists() {
            vector_of_strings_representing_bubblewrap_command_arguments.push(String::from("--dev-bind"));
            vector_of_strings_representing_bubblewrap_command_arguments.push(String::from("/dev/dri"));
            vector_of_strings_representing_bubblewrap_command_arguments.push(String::from("/dev/dri"));
        }
        for unsigned_integer_index_representing_nvidia_device_node in 0..10 {
            let string_representing_nvidia_node_path = format!("/dev/nvidia{}", unsigned_integer_index_representing_nvidia_device_node);
            if Path::new(&string_representing_nvidia_node_path).exists() {
                vector_of_strings_representing_bubblewrap_command_arguments.push(String::from("--dev-bind"));
                vector_of_strings_representing_bubblewrap_command_arguments.push(string_representing_nvidia_node_path.clone());
                vector_of_strings_representing_bubblewrap_command_arguments.push(string_representing_nvidia_node_path);
            }
        }
        let array_of_strings_representing_nvidia_control_paths = [
            "/dev/nvidiactl", "/dev/nvidia-modeset", "/dev/nvidia-uvm", "/dev/nvidia-uvm-tools",
        ];
        for string_slice_representing_nvidia_control_path in array_of_strings_representing_nvidia_control_paths {
            if Path::new(string_slice_representing_nvidia_control_path).exists() {
                vector_of_strings_representing_bubblewrap_command_arguments.push(String::from("--dev-bind"));
                vector_of_strings_representing_bubblewrap_command_arguments.push(String::from(string_slice_representing_nvidia_control_path));
                vector_of_strings_representing_bubblewrap_command_arguments.push(String::from(string_slice_representing_nvidia_control_path));
            }
        }
    }

    for string_representing_directory_to_create in vector_of_strings_representing_sorted_directories_to_create {
        vector_of_strings_representing_bubblewrap_command_arguments.push(String::from("--dir"));
        vector_of_strings_representing_bubblewrap_command_arguments.push(string_representing_directory_to_create);
    }

    // ==========================================
    // 2. 宿主机隐私家目录幻象映射与穿透验证层挂载
    // ==========================================

    let string_representing_host_home_directory_path = sandbox_context_representing_runtime_environment.path_buf_representing_host_home_directory.to_string_lossy().into_owned();
    let string_representing_sandbox_home_directory_path = sandbox_context_representing_runtime_environment.path_buf_representing_sandbox_home_directory.to_string_lossy().into_owned();
    vector_of_strings_representing_bubblewrap_command_arguments.push(String::from("--bind"));
    vector_of_strings_representing_bubblewrap_command_arguments.push(string_representing_sandbox_home_directory_path);
    vector_of_strings_representing_bubblewrap_command_arguments.push(string_representing_host_home_directory_path.clone());
    
    vector_of_strings_representing_bubblewrap_command_arguments.push(String::from("--setenv"));
    vector_of_strings_representing_bubblewrap_command_arguments.push(String::from("HOME"));
    vector_of_strings_representing_bubblewrap_command_arguments.push(string_representing_host_home_directory_path.clone());
    vector_of_strings_representing_bubblewrap_command_arguments.push(String::from("--setenv"));
    vector_of_strings_representing_bubblewrap_command_arguments.push(String::from("USER"));
    vector_of_strings_representing_bubblewrap_command_arguments.push(sandbox_context_representing_runtime_environment.string_representing_host_username.clone());
    vector_of_strings_representing_bubblewrap_command_arguments.push(String::from("--setenv"));
    vector_of_strings_representing_bubblewrap_command_arguments.push(String::from("LOGNAME"));
    vector_of_strings_representing_bubblewrap_command_arguments.push(sandbox_context_representing_runtime_environment.string_representing_host_username);

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

    // ==========================================
    // 3. 环境变量注入与引擎库嗅探
    // ==========================================

    let mut hash_set_representing_all_configuration_keys = std::collections::HashSet::new();
    
    hash_set_representing_all_configuration_keys.insert(String::from("WINEPREFIX"));
    hash_set_representing_all_configuration_keys.insert(String::from("WINER_EXE_PATH"));
    
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
        if !string_representing_key.starts_with("WINER_") || string_representing_key == "WINER_EXE_PATH" {
            let mut string_representing_resolved_value = pyramid.resolve_configuration_value(&string_representing_key, "");
            if !string_representing_resolved_value.is_empty() {
                // 如果 WINEPREFIX/EXE_PATH 落在沙箱内部，需进行容器内路径转换，保证其投射到假的 $HOME 中
                if string_representing_key == "WINEPREFIX" || string_representing_key == "WINER_EXE_PATH" {
                    let path_buf_representing_custom_path = fs_absolute_path_secure(Path::new(&string_representing_resolved_value));
                    
                    if path_buf_representing_custom_path.starts_with(&path_buf_representing_canonicalized_sandbox_home) {
                        if let Ok(path_slice_representing_relative_subpath) = path_buf_representing_custom_path.strip_prefix(&path_buf_representing_canonicalized_sandbox_home) {
                            let path_buf_representing_in_container_path = sandbox_context_representing_runtime_environment.path_buf_representing_host_home_directory.join(path_slice_representing_relative_subpath);
                            string_representing_resolved_value = path_buf_representing_in_container_path.to_string_lossy().into_owned();
                        }
                    }
                }
                vector_of_strings_representing_bubblewrap_command_arguments.push(String::from("--setenv"));
                vector_of_strings_representing_bubblewrap_command_arguments.push(string_representing_key);
                vector_of_strings_representing_bubblewrap_command_arguments.push(string_representing_resolved_value);
            }
        }
    }

    vector_of_strings_representing_bubblewrap_command_arguments.push(String::from("--unsetenv"));
    vector_of_strings_representing_bubblewrap_command_arguments.push(String::from("LD_PRELOAD"));

    // 引擎环境配置与库路径嗅探
    let string_representing_custom_wine_binary_path = if let Some(string_representing_cli_wine_path) = option_representing_cli_custom_wine_path {
        fs_absolute_path_secure(Path::new(&string_representing_cli_wine_path)).to_string_lossy().into_owned()
    } else {
        let string_representing_wine_path_raw = pyramid.resolve_configuration_value("WINER_WINE_PATH", "wine");
        if string_representing_wine_path_raw == "wine" {
            string_representing_wine_path_raw
        } else {
            fs_absolute_path_secure(Path::new(&string_representing_wine_path_raw)).to_string_lossy().into_owned()
        }
    };

    let boolean_flag_indicating_ld_library_path_injection_needed = pyramid.resolve_configuration_value("LD_LIBRARY_PATH", "").is_empty();
    let boolean_flag_indicating_gst_plugin_path_injection_needed = pyramid.resolve_configuration_value("GST_PLUGIN_PATH", "").is_empty();
    let mut string_representing_sniffed_gst_plugin_path = String::new();

    if string_representing_custom_wine_binary_path != "wine" && (string_representing_custom_wine_binary_path.contains('/') || string_representing_custom_wine_binary_path.contains('\\')) {
        let path_buf_representing_wine_binary = std::path::PathBuf::from(&string_representing_custom_wine_binary_path);
        if let Some(path_buf_representing_inferred_runner_root) = resolve_wine_runner_root_directory_from_binary_path(&path_buf_representing_wine_binary) {
            
            if boolean_flag_indicating_ld_library_path_injection_needed {
                let mut vector_of_strings_representing_inferred_library_paths = Vec::new();
                let array_of_strings_representing_potential_library_subdirectories = ["lib", "lib64", "files/lib", "files/lib64"];
                
                for string_slice_representing_library_subdirectory in array_of_strings_representing_potential_library_subdirectories {
                    let path_buf_representing_potential_library_path = path_buf_representing_inferred_runner_root.join(string_slice_representing_library_subdirectory);
                    if path_buf_representing_potential_library_path.exists() {
                        vector_of_strings_representing_inferred_library_paths.push(path_buf_representing_potential_library_path.to_string_lossy().into_owned());
                    }
                }

                if !vector_of_strings_representing_inferred_library_paths.is_empty() {
                    let string_representing_joined_ld_library_path = vector_of_strings_representing_inferred_library_paths.join(":");
                    vector_of_strings_representing_bubblewrap_command_arguments.push(String::from("--setenv"));
                    vector_of_strings_representing_bubblewrap_command_arguments.push(String::from("LD_LIBRARY_PATH"));
                    vector_of_strings_representing_bubblewrap_command_arguments.push(string_representing_joined_ld_library_path);
                }
            }

            if boolean_flag_indicating_gst_plugin_path_injection_needed {
                let mut vector_of_strings_representing_inferred_gst_paths = Vec::new();
                let array_of_strings_representing_potential_gst_subdirectories = [
                    "lib/gstreamer-1.0", "lib64/gstreamer-1.0", "files/lib/gstreamer-1.0", "files/lib64/gstreamer-1.0"
                ];
                
                for string_slice_representing_gst_subdirectory in array_of_strings_representing_potential_gst_subdirectories {
                    let path_buf_representing_potential_gst_path = path_buf_representing_inferred_runner_root.join(string_slice_representing_gst_subdirectory);
                    if path_buf_representing_potential_gst_path.exists() {
                        vector_of_strings_representing_inferred_gst_paths.push(path_buf_representing_potential_gst_path.to_string_lossy().into_owned());
                    }
                }

                if !vector_of_strings_representing_inferred_gst_paths.is_empty() {
                    string_representing_sniffed_gst_plugin_path = vector_of_strings_representing_inferred_gst_paths.join(":");
                }
            }
        }
    }

    if boolean_flag_indicating_gst_plugin_path_injection_needed {
        vector_of_strings_representing_bubblewrap_command_arguments.push(String::from("--setenv"));
        vector_of_strings_representing_bubblewrap_command_arguments.push(String::from("GST_PLUGIN_PATH"));
        vector_of_strings_representing_bubblewrap_command_arguments.push(string_representing_sniffed_gst_plugin_path);
    }

    vector_of_strings_representing_bubblewrap_command_arguments.push(String::from("--die-with-parent"));

    // ==========================================
    // 4. v0.3.0 意图级目标分发与指令完美缝合组装
    // ==========================================

    // 第一层分发：CWD 工作目录
    let path_buf_representing_target_working_directory = match &target_specification_representing_validated_execution.target_category_enum_representing_execution_type {
        TargetCategory::PhysicalWindowsExecutable { path_buf_representing_host_absolute_path } => {
            path_buf_representing_host_absolute_path.parent()
                .map(|parent| parent.to_path_buf())
                .unwrap_or_else(|| sandbox_context_representing_runtime_environment.path_buf_representing_host_home_directory.clone())
        },
        _ => sandbox_context_representing_runtime_environment.path_buf_representing_host_home_directory.clone() // 虚拟命令保底切换到安全的 $HOME
    };
    
    // CWD 清洗投影
    let path_buf_representing_canonicalized_cwd = fs_absolute_path_secure(&path_buf_representing_target_working_directory);
    let mut string_representing_target_working_directory_path = path_buf_representing_canonicalized_cwd.to_string_lossy().into_owned();
    
    if path_buf_representing_canonicalized_cwd.starts_with(&path_buf_representing_canonicalized_sandbox_home) {
        if let Ok(path_slice_representing_relative_subpath) = path_buf_representing_canonicalized_cwd.strip_prefix(&path_buf_representing_canonicalized_sandbox_home) {
            let path_buf_representing_in_container_path = sandbox_context_representing_runtime_environment.path_buf_representing_host_home_directory.join(path_slice_representing_relative_subpath);
            string_representing_target_working_directory_path = path_buf_representing_in_container_path.to_string_lossy().into_owned();
        }
    }
    
    vector_of_strings_representing_bubblewrap_command_arguments.push(String::from("--chdir"));
    vector_of_strings_representing_bubblewrap_command_arguments.push(string_representing_target_working_directory_path);


    // 第二层分发：沙箱内部实际执行参数流 (Inner Command Stream)
    let mut vector_of_strings_representing_sandbox_inner_command_execution: Vec<String> = Vec::new();
    
    // a. 宿主外围包装器注入 (如 gamemoderun)
    if pyramid.resolve_configuration_value("WINER_GAMEMODE", "0") == "1" {
        vector_of_strings_representing_sandbox_inner_command_execution.push(String::from("gamemoderun"));
    }
    
    // b. 无论目标为何，物理形态必然接管给 Wine 代理（先推入 wine 二进制）
    vector_of_strings_representing_sandbox_inner_command_execution.push(string_representing_custom_wine_binary_path);
    
    // c. 预推导前缀指令流完美回填 (Launcher Prefix Backfill)
    for string_representing_prefix in target_specification_representing_validated_execution.vector_of_strings_representing_launcher_prefix_commands {
        vector_of_strings_representing_sandbox_inner_command_execution.push(string_representing_prefix);
    }
    
    // d. 目标形态决算 (Target Category Settlement)
    match &target_specification_representing_validated_execution.target_category_enum_representing_execution_type {
        TargetCategory::WineMulticallTool { string_representing_subcommand_name } => {
            vector_of_strings_representing_sandbox_inner_command_execution.push(string_representing_subcommand_name.clone());
        },
        TargetCategory::VirtualWineCommand { string_representing_command_name } => {
            vector_of_strings_representing_sandbox_inner_command_execution.push(string_representing_command_name.clone());
        },
        TargetCategory::PhysicalWindowsExecutable { path_buf_representing_host_absolute_path } => {
            // 对物理 EXE 进行投影路径转化
            let path_buf_representing_canonicalized_target = fs_absolute_path_secure(path_buf_representing_host_absolute_path);
            let mut string_representing_final_target_path = path_buf_representing_canonicalized_target.to_string_lossy().into_owned();
            
            if path_buf_representing_canonicalized_target.starts_with(&path_buf_representing_canonicalized_sandbox_home) {
                if let Ok(path_slice_representing_relative_subpath) = path_buf_representing_canonicalized_target.strip_prefix(&path_buf_representing_canonicalized_sandbox_home) {
                    let path_buf_representing_in_container_path = sandbox_context_representing_runtime_environment.path_buf_representing_host_home_directory.join(path_slice_representing_relative_subpath);
                    string_representing_final_target_path = path_buf_representing_in_container_path.to_string_lossy().into_owned();
                }
            }
            vector_of_strings_representing_sandbox_inner_command_execution.push(string_representing_final_target_path);
        },
        TargetCategory::HostLinuxExecutableBlock => {
            std::process::exit(1); // 故障保险，绝对拦截
        }
    }
    
    // e. 原样透传目标参数 (Target Arguments Passthrough)
    let string_representing_resolved_exe_args = pyramid.resolve_configuration_value("WINER_EXE_ARGS", "");
    for string_slice_representing_arg in string_representing_resolved_exe_args.split_whitespace() {
        if !string_slice_representing_arg.is_empty() {
            vector_of_strings_representing_sandbox_inner_command_execution.push(string_slice_representing_arg.to_string());
        }
    }
    for string_representing_cli_argument in target_specification_representing_validated_execution.vector_of_strings_representing_remaining_cli_arguments {
        vector_of_strings_representing_sandbox_inner_command_execution.push(string_representing_cli_argument);
    }
    
    // 缝合所有内部指令至 bwrap 参数尾部
    for string_representing_inner_argument in vector_of_strings_representing_sandbox_inner_command_execution {
        vector_of_strings_representing_bubblewrap_command_arguments.push(string_representing_inner_argument);
    }

    // ==========================================
    // 5. 调用系统 Execve 接管进程
    // ==========================================

    let mut command_representing_final_process_replacement_invocation = std::process::Command::new("bwrap");
    command_representing_final_process_replacement_invocation.args(&vector_of_strings_representing_bubblewrap_command_arguments);
    let error_indicating_failed_process_replacement = command_representing_final_process_replacement_invocation.exec();

    eprintln!("[bwrap-winer] CRITICAL ERROR: Failed to execute process replacement system call (execve): {:?}", error_indicating_failed_process_replacement);
    std::process::exit(1);
}
