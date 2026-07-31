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

/// 配置金字塔实体：安全封装 3 个维度的哈希表，并提供便捷的级联查询接口。
pub struct ConfigurationPyramid {
    pub hash_map_representing_sandbox_local_configuration_keys_and_values: HashMap<String, String>,
    pub hash_map_representing_sandbox_specific_user_configuration_keys_and_values: HashMap<String, String>,
    pub hash_map_representing_global_configuration_keys_and_values: HashMap<String, String>,
}

impl ConfigurationPyramid {
    /// 利用内部结构体调用底层的分层查询逻辑（具体实现在 configuration_management 模块）
    pub fn resolve_configuration_value(&self, string_slice_representing_variable_key: &str, string_slice_representing_hardcoded_default_value: &str) -> String {
        crate::configuration_management::resolve_configuration_value_from_hierarchical_sources(
            string_slice_representing_variable_key,
            &self.hash_map_representing_sandbox_local_configuration_keys_and_values,
            &self.hash_map_representing_sandbox_specific_user_configuration_keys_and_values,
            &self.hash_map_representing_global_configuration_keys_and_values,
            string_slice_representing_hardcoded_default_value,
        )
    }
}

/// 沙箱运行时环境上下文实体：在各个管线阶段流转的不可变静态数据聚合。
pub struct SandboxContext {
    #[allow(dead_code)]
    pub string_representing_derived_sandbox_identifier: String,
    pub path_buf_representing_host_home_directory: PathBuf,
    pub string_representing_host_username: String,
    pub path_buf_representing_sandbox_home_directory: PathBuf,
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
