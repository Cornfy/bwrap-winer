use std::path::{Path, PathBuf};

use crate::core_data_structures::{
    MountSpecification, SandboxContext, TargetCategory, TargetSpecification,
};
use crate::file_system_utilities::{
    fs_absolute_path_secure,
    ensure_mount_point_exists_in_sandbox_home,
    get_unique_non_system_parent_paths,
    resolve_wine_runner_root_directory_from_binary_path,
};

// ==========================================
// 🛡️ 通用安全门禁防线 (Universal Security Shield)
// ==========================================

/// 通用安全门禁防线：通过非独占性共享路径排除法，判断目标路径是否散落在系统的共享大目录中。
/// 用于拦截并阻止任何试图将整个根目录、/usr 等系统核心，以及宿主整个家目录进行自动 bind-mount 的危险行为。
pub fn determine_if_path_is_prohibited_shared_system_directory(
    path_slice_representing_directory_to_check: &Path,
    path_slice_representing_host_home_directory: &Path,
) -> bool {
    let string_representing_path = path_slice_representing_directory_to_check.to_string_lossy().into_owned();
    
    // 系统级公共共享容器名单（根目录等直接硬拦截，防止隔离逃逸）
    let array_of_strings_representing_scattered_system_paths = [
        "/", "/usr", "/usr/local", "/opt", "/mnt", "/media", "/etc", "/var", "/sys", "/dev", "/run", "/tmp"
    ];
    
    for string_slice_representing_scattered_path in array_of_strings_representing_scattered_system_paths {
        if string_representing_path == string_slice_representing_scattered_path {
            return true;
        }
    }

    // 🚨 核心拦截：绝不允许程序试图自动穿透挂载整个真实的宿主家目录 🚨
    if path_slice_representing_directory_to_check == path_slice_representing_host_home_directory {
        return true;
    }

    false
}

// ==========================================
// 🚀 核心挂载规格收集器 (Mount Specification Collector)
// ==========================================

pub fn collect_mount_specifications(
    sandbox_context_representing_runtime_environment: &SandboxContext,
    target_specification_representing_validated_execution: &TargetSpecification,
    option_representing_cli_custom_wine_path: &Option<String>,
) -> Vec<MountSpecification> {
    let mut vector_of_mount_specifications: Vec<MountSpecification> = Vec::new();
    let pyramid = &sandbox_context_representing_runtime_environment.configuration_pyramid_representing_all_layers;

    let string_representing_penetrate_depth_value = pyramid.resolve_configuration_value("WINER_PENETRATE", "1");
    let unsigned_integer_representing_penetrate_depth = string_representing_penetrate_depth_value.parse::<usize>().unwrap_or(1);

    let path_buf_representing_canonicalized_sandbox_home = fs_absolute_path_secure(&sandbox_context_representing_runtime_environment.path_buf_representing_sandbox_home_directory);

    // 🌟 基于强类型意图结算的精准挂载分发 🌟
    // 只有真正的宿主物理 Windows 程序，才被允许触发路径穿透计算
    if let TargetCategory::PhysicalWindowsExecutable { path_buf_representing_host_absolute_path } = &target_specification_representing_validated_execution.target_category_enum_representing_execution_type {
        
        let path_buf_representing_canonicalized_executable = fs_absolute_path_secure(path_buf_representing_host_absolute_path);
        let boolean_flag_indicating_executable_is_in_sandbox = path_buf_representing_canonicalized_executable.starts_with(&path_buf_representing_canonicalized_sandbox_home);

        // 主目标穿透挂载 (Primary Target Penetration)
        if !boolean_flag_indicating_executable_is_in_sandbox {
            let mut path_buf_representing_current_penetrated_directory = path_buf_representing_host_absolute_path.clone();
            
            if unsigned_integer_representing_penetrate_depth == 0 {
                vector_of_mount_specifications.push(MountSpecification {
                    path_buf_representing_host_source: path_buf_representing_host_absolute_path.clone(),
                    path_buf_representing_container_destination: path_buf_representing_host_absolute_path.clone(),
                    boolean_flag_indicating_readonly: true,
                    boolean_flag_indicating_try_only: false,
                    boolean_flag_indicating_host_directory_creation_allowed: false,
                });
            } else {
                for _ in 0..unsigned_integer_representing_penetrate_depth {
                    if let Some(path_slice_representing_parent_directory) = path_buf_representing_current_penetrated_directory.parent() {
                        let path_buf_representing_parent = path_slice_representing_parent_directory.to_path_buf();
                        
                        // 🚨 门禁检查：绝不允许退栈到被禁止的大目录
                        if determine_if_path_is_prohibited_shared_system_directory(&path_buf_representing_parent, &sandbox_context_representing_runtime_environment.path_buf_representing_host_home_directory) {
                            eprintln!("[bwrap-winer] SECURITY SHIELD: Penetration path reached a prohibited shared directory (e.g. HOME or ROOT).");
                            eprintln!("[bwrap-winer] Stopping penetration at: {:?}", path_buf_representing_current_penetrated_directory);
                            break;
                        }
                        
                        path_buf_representing_current_penetrated_directory = path_buf_representing_parent;
                    } else {
                        break;
                    }
                }
                
                // 🚨 二次结算防线：防止用户直接在 HOME 运行安装包，导致计算后的目录仍然是大目录
                if determine_if_path_is_prohibited_shared_system_directory(&path_buf_representing_current_penetrated_directory, &sandbox_context_representing_runtime_environment.path_buf_representing_host_home_directory) {
                    eprintln!("[bwrap-winer] CRITICAL WARNING: Target resides directly in a prohibited directory. Downgrading to file-only read-only mount.");
                    vector_of_mount_specifications.push(MountSpecification {
                        path_buf_representing_host_source: path_buf_representing_host_absolute_path.clone(),
                        path_buf_representing_container_destination: path_buf_representing_host_absolute_path.clone(),
                        boolean_flag_indicating_readonly: true,
                        boolean_flag_indicating_try_only: true,
                        boolean_flag_indicating_host_directory_creation_allowed: false,
                    });
                } else {
                    vector_of_mount_specifications.push(MountSpecification {
                        path_buf_representing_host_source: path_buf_representing_current_penetrated_directory.clone(),
                        path_buf_representing_container_destination: path_buf_representing_current_penetrated_directory.clone(),
                        boolean_flag_indicating_readonly: false,
                        boolean_flag_indicating_try_only: false,
                        boolean_flag_indicating_host_directory_creation_allowed: false,
                    });
                }
            }
        }

        // 🌟 副目标二次穿透挂载追加 (Secondary Penetration Mounts) 🌟
        // 应对 Mod / 补丁注入器链条带来的多个跨目录物理文件依赖
        for path_buf_representing_secondary_directory in &target_specification_representing_validated_execution.vector_of_path_bufs_representing_secondary_penetration_mount_sources {
            if determine_if_path_is_prohibited_shared_system_directory(path_buf_representing_secondary_directory, &sandbox_context_representing_runtime_environment.path_buf_representing_host_home_directory) {
                eprintln!("[bwrap-winer] SECURITY SHIELD: Refusing to auto-mount secondary dependency path {:?} as it is a prohibited directory.", path_buf_representing_secondary_directory);
            } else if !path_buf_representing_secondary_directory.starts_with(&path_buf_representing_canonicalized_sandbox_home) {
                vector_of_mount_specifications.push(MountSpecification {
                    path_buf_representing_host_source: path_buf_representing_secondary_directory.clone(),
                    path_buf_representing_container_destination: path_buf_representing_secondary_directory.clone(),
                    boolean_flag_indicating_readonly: false,
                    boolean_flag_indicating_try_only: true,
                    boolean_flag_indicating_host_directory_creation_allowed: false,
                });
            }
        }
    }

    // ==========================================
    // 环境挂载：WINEPREFIX 与 Wine Runner 目录
    // ==========================================

    let string_representing_wine_prefix_resolved_value = pyramid.resolve_configuration_value("WINEPREFIX", "");
    if !string_representing_wine_prefix_resolved_value.is_empty() {
        let path_buf_representing_custom_wine_prefix = fs_absolute_path_secure(Path::new(&string_representing_wine_prefix_resolved_value));
        
        if path_buf_representing_custom_wine_prefix.starts_with(&path_buf_representing_canonicalized_sandbox_home) {
            let _ = std::fs::create_dir_all(&path_buf_representing_custom_wine_prefix);
        } else {
            vector_of_mount_specifications.push(MountSpecification {
                path_buf_representing_host_source: path_buf_representing_custom_wine_prefix.clone(),
                path_buf_representing_container_destination: path_buf_representing_custom_wine_prefix,
                boolean_flag_indicating_readonly: false,
                boolean_flag_indicating_try_only: false,
                boolean_flag_indicating_host_directory_creation_allowed: true,
            });
        }
    }

    let string_representing_custom_wine_binary_path = if let Some(string_representing_cli_wine_path) = option_representing_cli_custom_wine_path {
        string_representing_cli_wine_path.clone()
    } else {
        pyramid.resolve_configuration_value("WINER_WINE_PATH", "wine")
    };

    if string_representing_custom_wine_binary_path != "wine" && (string_representing_custom_wine_binary_path.contains('/') || string_representing_custom_wine_binary_path.contains('\\')) {
        let path_buf_representing_wine_binary = fs_absolute_path_secure(Path::new(&string_representing_custom_wine_binary_path));
        
        if let Some(path_buf_representing_inferred_runner_root) = resolve_wine_runner_root_directory_from_binary_path(&path_buf_representing_wine_binary) {
            if determine_if_path_is_prohibited_shared_system_directory(&path_buf_representing_inferred_runner_root, &sandbox_context_representing_runtime_environment.path_buf_representing_host_home_directory) {
                eprintln!("[bwrap-winer] WARNING: The resolved Wine Runner Root ({:?}) is a prohibited shared system directory.", path_buf_representing_inferred_runner_root);
                eprintln!("[bwrap-winer] For security, auto-mounting is disabled for shared paths to prevent sandbox escape.");
            } else {
                vector_of_mount_specifications.push(MountSpecification {
                    path_buf_representing_host_source: path_buf_representing_inferred_runner_root.clone(),
                    path_buf_representing_container_destination: path_buf_representing_inferred_runner_root,
                    boolean_flag_indicating_readonly: true,
                    boolean_flag_indicating_try_only: false,
                    boolean_flag_indicating_host_directory_creation_allowed: false,
                });
            }
        }
    }

    // ==========================================
    // 用户自定义挂载：WINER_BIND 与 WINER_RO_BIND
    // ==========================================

    let string_representing_custom_binds_value = pyramid.resolve_configuration_value("WINER_BIND", "");
    if !string_representing_custom_binds_value.is_empty() {
        for string_slice_representing_raw_bind_pair in string_representing_custom_binds_value.split(',') {
            let string_slice_representing_trimmed_bind_pair = string_slice_representing_raw_bind_pair.trim();
            if string_slice_representing_trimmed_bind_pair.is_empty() { continue; }
            let vector_of_slices_representing_pair_split: Vec<&str> = string_slice_representing_trimmed_bind_pair.split(':').collect();
            let string_representing_raw_host_path = vector_of_slices_representing_pair_split[0].trim().to_string();

            if string_representing_raw_host_path.is_empty() {
                eprintln!("[bwrap-winer] CRITICAL ERROR: Invalid empty host path detected in WINER_BIND configuration.");
                std::process::exit(1);
            }

            let string_representing_raw_container_path = if vector_of_slices_representing_pair_split.len() > 1 {
                let string_slice_representing_trimmed_container = vector_of_slices_representing_pair_split[1].trim();
                if string_slice_representing_trimmed_container.is_empty() {
                    eprintln!("[bwrap-winer] CRITICAL ERROR: Invalid empty container path detected in WINER_BIND configuration.");
                    std::process::exit(1);
                }
                string_slice_representing_trimmed_container.to_string()
            } else {
                string_representing_raw_host_path.clone()
            };

            vector_of_mount_specifications.push(MountSpecification {
                path_buf_representing_host_source: fs_absolute_path_secure(Path::new(&string_representing_raw_host_path)),
                path_buf_representing_container_destination: fs_absolute_path_secure(Path::new(&string_representing_raw_container_path)),
                boolean_flag_indicating_readonly: false,
                boolean_flag_indicating_try_only: false,
                boolean_flag_indicating_host_directory_creation_allowed: false,
            });
        }
    }

    let string_representing_custom_ro_binds_value = pyramid.resolve_configuration_value("WINER_RO_BIND", "");
    if !string_representing_custom_ro_binds_value.is_empty() {
        for string_slice_representing_raw_ro_bind_pair in string_representing_custom_ro_binds_value.split(',') {
            let string_slice_representing_trimmed_ro_bind_pair = string_slice_representing_raw_ro_bind_pair.trim();
            if string_slice_representing_trimmed_ro_bind_pair.is_empty() { continue; }
            let vector_of_slices_representing_pair_split: Vec<&str> = string_slice_representing_trimmed_ro_bind_pair.split(':').collect();
            let string_representing_raw_host_path = vector_of_slices_representing_pair_split[0].trim().to_string();

            if string_representing_raw_host_path.is_empty() {
                eprintln!("[bwrap-winer] CRITICAL ERROR: Invalid empty host path detected in WINER_RO_BIND configuration.");
                std::process::exit(1);
            }

            let string_representing_raw_container_path = if vector_of_slices_representing_pair_split.len() > 1 {
                let string_slice_representing_trimmed_container = vector_of_slices_representing_pair_split[1].trim();
                if string_slice_representing_trimmed_container.is_empty() {
                    eprintln!("[bwrap-winer] CRITICAL ERROR: Invalid empty container path detected in WINER_RO_BIND configuration.");
                    std::process::exit(1);
                }
                string_slice_representing_trimmed_container.to_string()
            } else {
                string_representing_raw_host_path.clone()
            };

            vector_of_mount_specifications.push(MountSpecification {
                path_buf_representing_host_source: fs_absolute_path_secure(Path::new(&string_representing_raw_host_path)),
                path_buf_representing_container_destination: fs_absolute_path_secure(Path::new(&string_representing_raw_container_path)),
                boolean_flag_indicating_readonly: true,
                boolean_flag_indicating_try_only: false,
                boolean_flag_indicating_host_directory_creation_allowed: false,
            });
        }
    }

    // ==========================================
    // 必备硬件/图形基础设施挂载 (Wayland, X11, Audio, Fonts, DBus)
    // ==========================================

    if let Ok(string_representing_wayland_display_value) = std::env::var("WAYLAND_DISPLAY") {
        if let Ok(string_representing_xdg_runtime_directory_value) = std::env::var("XDG_RUNTIME_DIR") {
            let path_buf_representing_wayland_socket = PathBuf::from(&string_representing_xdg_runtime_directory_value).join(&string_representing_wayland_display_value);
            vector_of_mount_specifications.push(MountSpecification {
                path_buf_representing_host_source: path_buf_representing_wayland_socket.clone(),
                path_buf_representing_container_destination: path_buf_representing_wayland_socket,
                boolean_flag_indicating_readonly: false,
                boolean_flag_indicating_try_only: true,
                boolean_flag_indicating_host_directory_creation_allowed: false,
            });
        }
    }

    vector_of_mount_specifications.push(MountSpecification {
        path_buf_representing_host_source: PathBuf::from("/tmp/.X11-unix"),
        path_buf_representing_container_destination: PathBuf::from("/tmp/.X11-unix"),
        boolean_flag_indicating_readonly: false,
        boolean_flag_indicating_try_only: true,
        boolean_flag_indicating_host_directory_creation_allowed: false,
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
                boolean_flag_indicating_host_directory_creation_allowed: false,
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
            boolean_flag_indicating_host_directory_creation_allowed: false,
        });
    }

    let path_buf_representing_user_fonts_directory = sandbox_context_representing_runtime_environment.path_buf_representing_host_home_directory.join(".local/share/fonts");
    vector_of_mount_specifications.push(MountSpecification {
        path_buf_representing_host_source: path_buf_representing_user_fonts_directory.clone(),
        path_buf_representing_container_destination: path_buf_representing_user_fonts_directory,
        boolean_flag_indicating_readonly: true,
        boolean_flag_indicating_try_only: true,
        boolean_flag_indicating_host_directory_creation_allowed: false,
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
            boolean_flag_indicating_host_directory_creation_allowed: false,
        });
    }

    vector_of_mount_specifications
}

// ==========================================
// 🩹 挂载点自愈引擎 (Mount Point Healer)
// ==========================================

pub fn resolve_and_heal_mounts(
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
            if mount_spec.boolean_flag_indicating_host_directory_creation_allowed {
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
            } else {
                eprintln!("[bwrap-winer] CRITICAL ERROR: Required host mount source does not exist and auto-creation is strictly disabled to prevent pollution: {:?}", mount_spec.path_buf_representing_host_source);
                std::process::exit(1);
            }
        }
    }

    let mut vector_of_strings_representing_sorted_directories: Vec<String> = hash_set_representing_all_needed_container_directories.into_iter().collect();
    // 按路径深度排序，确保 bwrap 能够按顺序创建父级目录
    vector_of_strings_representing_sorted_directories.sort_by_key(|string_representing_path| string_representing_path.len());

    (vector_of_strings_representing_sorted_directories, vector_of_verified_mount_specifications)
}
