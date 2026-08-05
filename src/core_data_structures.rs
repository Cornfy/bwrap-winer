use std::collections::HashMap;
use std::path::PathBuf;

// ==========================================
// 🎯 目标分类枚举 (Target Classification Enum)
// ==========================================

/// 目标执行类型的强类型分类枚举：完美对应物理探针扫描后的 4 种终局意图。
/// 彻底消除多个 Boolean 标志位可能导致的无效状态组合。
#[derive(Debug, PartialEq)]
pub enum TargetCategory {
    /// 1. Wine 内置多路复用工具（如 winecfg, regedit）
    /// 特征：在宿主磁盘上存在，且解引用终点等于 Wine 引擎实体。
    WineMulticallTool {
        string_representing_subcommand_name: String,
    },
    
    /// 2. Wine 纯虚拟命令（如 cmd, explorer）
    /// 特征：在宿主系统 PATH、CWD、引擎目录中均未找到任何物理实体。
    VirtualWineCommand {
        string_representing_command_name: String,
    },
    
    /// 3. 宿主机物理 Windows 程序（如 game.exe, patcher.exe）
    /// 特征：真实存在于宿主磁盘，且非 Linux ELF 二进制文件。
    PhysicalWindowsExecutable {
        path_buf_representing_host_absolute_path: PathBuf,
    },
    
    /// 4. 宿主机原生 Linux ELF 程序
    /// 特征：真实存在于宿主磁盘，读取魔数确认为 0x7f454c46。
    #[allow(dead_code)]
    HostLinuxExecutableBlock,
}


// ==========================================
// 🧱 核心结构体定义 (Core Data Structures)
// ==========================================

/// 目标可执行文件及衍生状态的解析结果实体 (v0.3.0 升级版)。
/// 负责在“多参数物理探针扫描器”完成后，向后续管线传递所有必要信息。
pub struct TargetSpecification {
    #[allow(dead_code)]
    pub string_representing_raw_user_input_target: String,

    #[allow(dead_code)]
    pub option_representing_absolute_path_to_primary_target_executable: Option<PathBuf>,
    
    // 自动收集的前缀指令链 (如 ["explorer", "/desktop=1080p"])
    pub vector_of_strings_representing_launcher_prefix_commands: Vec<String>,
    
    // 自动收集的后续物理文件父目录，用于追加穿透挂载 (应对 Mod/补丁 启动多 EXE 场景)
    pub vector_of_path_bufs_representing_secondary_penetration_mount_sources: Vec<PathBuf>,
    
    // 强类型意图结算分类
    pub target_category_enum_representing_execution_type: TargetCategory,
    
    // 剩余的目标执行参数
    pub vector_of_strings_representing_remaining_cli_arguments: Vec<String>,
}

/// 挂载描述规范实体：用于将所有沙箱内外的数据流映射完全管线化。
pub struct MountSpecification {
    pub path_buf_representing_host_source: PathBuf,
    pub path_buf_representing_container_destination: PathBuf,
    pub boolean_flag_indicating_readonly: bool,
    pub boolean_flag_indicating_try_only: bool,
    pub boolean_flag_indicating_host_directory_creation_allowed: bool,
}

/// 配置金字塔实体：在初始化时已将全局、用户、沙箱、环境变量 4 层配置
/// 按优先级从低到高进行覆盖合并，查询效率为 O(1)。
pub struct ConfigurationPyramid {
    // 私有字段，外部无法直接访问，保护了封装性
    merged_configuration_map: HashMap<String, String>,
}

impl ConfigurationPyramid {
    /// 构造函数：执行金字塔合并逻辑
    pub fn new(
        hash_map_representing_global_config: HashMap<String, String>,
        hash_map_representing_user_config: HashMap<String, String>,
        hash_map_representing_local_config: HashMap<String, String>,
    ) -> Self {
        let mut merged_configuration_map = HashMap::new();

        // 优先级 4: 全局配置 (最低优先级)
        merged_configuration_map.extend(hash_map_representing_global_config);
        // 优先级 3: 用户配置
        merged_configuration_map.extend(hash_map_representing_user_config);
        // 优先级 2: 沙箱局部配置
        merged_configuration_map.extend(hash_map_representing_local_config);

        // 优先级 1: 环境变量 (最高优先级)
        for (string_representing_env_key, string_representing_env_value) in std::env::vars() {
            if string_representing_env_key.starts_with("WINER_") || string_representing_env_key == "WINEPREFIX" {
                merged_configuration_map.insert(string_representing_env_key, string_representing_env_value);
            }
        }

        ConfigurationPyramid { merged_configuration_map }
    }

    /// O(1) 极速查询，并统一在此处处理波浪号展开
    pub fn resolve_configuration_value(&self, string_slice_representing_variable_key: &str, string_slice_representing_hardcoded_default_value: &str) -> String {
        let string_representing_raw_value = self.merged_configuration_map
            .get(string_slice_representing_variable_key)
            .cloned()
            .unwrap_or_else(|| string_slice_representing_hardcoded_default_value.to_string());
            
        crate::file_system_utilities::expand_tilde_in_configuration_value(string_representing_raw_value)
    }

    /// 暴露所有需要注入到沙箱内部的环境变量键名
    pub fn get_all_configuration_keys(&self) -> Vec<String> {
        self.merged_configuration_map.keys().cloned().collect()
    }
}

/// 沙箱运行时环境上下文实体：在各个管线阶段流转的不可变静态数据聚合。
pub struct SandboxContext {
    #[allow(dead_code)]
    pub string_representing_derived_sandbox_identifier: String,
    pub path_buf_representing_host_home_directory: PathBuf,
    pub string_representing_host_username: String,
    pub path_buf_representing_sandbox_home_directory: PathBuf,

    // 💡 强类型化所有容器隔离与运行开关
    pub boolean_flag_indicating_network_enabled: bool,
    pub boolean_flag_indicating_pid_sharing_enabled: bool,
    pub boolean_flag_indicating_ipc_sharing_enabled: bool,
    pub boolean_flag_indicating_full_device_passthrough_enabled: bool,
    pub boolean_flag_indicating_gamemode_enabled: bool,

    pub configuration_pyramid_representing_all_layers: ConfigurationPyramid,
}

impl SandboxContext {
    /// 确保沙箱持久化目录及宿主 Home 投影基座在执行任何挂载前必定存在。
    pub fn ensure_sandbox_root_and_home_directories_exist(&self) {
        if let Err(error_representing_failed_directory_creation) = std::fs::create_dir_all(&self.path_buf_representing_sandbox_home_directory) {
            eprintln!("[bwrap-winer] CRITICAL ERROR: Failed to create sandbox persistence directory: {:?}", error_representing_failed_directory_creation);
            std::process::exit(1);
        }
    }
}
