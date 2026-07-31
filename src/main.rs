mod core_data_structures;
mod file_system_utilities;
mod configuration_management;
mod target_resolution_engine;
mod sandbox_mount_pipeline;
mod process_execution_builder;

// 引入我们将要在其他模块中定义的核心组件
use core_data_structures::SandboxContext;
use configuration_management::{
    resolve_host_environment_base_paths,
    resolve_sandbox_data_root_directory,
    load_configuration_hierarchy,
};
use target_resolution_engine::{
    parse_target_executable_and_remaining_arguments_from_cli,
    resolve_sandbox_identity,
    resolve_target_executable_and_validate_via_multi_arg_scanner,
};
use sandbox_mount_pipeline::{
    collect_mount_specifications,
    resolve_and_heal_mounts,
};
use process_execution_builder::{
    assemble_bubblewrap_arguments_and_execute_process_replacement,
    handle_help_command_if_needed,
    handle_list_command_if_needed,
};

fn main() {
    // 1. 获取用户从命令行输入的原始参数切片
    let vector_of_strings_representing_command_line_arguments: Vec<String> = std::env::args().skip(1).collect();

    // 2. 基础命令行短路命令拦截 (Help & List)
    handle_help_command_if_needed(&vector_of_strings_representing_command_line_arguments);

    // 3. 解析宿主环境与配置存储基础路径
    let (path_buf_representing_host_home_directory, string_representing_host_username, path_buf_representing_global_config_root) = 
        resolve_host_environment_base_paths();

    let path_buf_representing_sandbox_data_root_directory = resolve_sandbox_data_root_directory(
        &path_buf_representing_host_home_directory,
        &path_buf_representing_global_config_root,
    );

    handle_list_command_if_needed(
        &vector_of_strings_representing_command_line_arguments,
        &path_buf_representing_sandbox_data_root_directory,
    );

    // 4. 初步提取可能的自定义 Wine 引擎路径与原始输入参数
    let (option_representing_cli_custom_wine_path, vector_of_strings_representing_raw_target_and_arguments) = 
        parse_target_executable_and_remaining_arguments_from_cli(&vector_of_strings_representing_command_line_arguments);

    // 5. 根据原始输入或环境变量，解析出绝对唯一的沙箱身份标识 (WINER_ID)
    let string_representing_derived_sandbox_identifier = resolve_sandbox_identity(
        &vector_of_strings_representing_raw_target_and_arguments,
        &path_buf_representing_global_config_root,
    );

    // 6. 装载 5 层配置金字塔
    let configuration_pyramid_representing_all_layers = load_configuration_hierarchy(
        &path_buf_representing_global_config_root,
        &path_buf_representing_sandbox_data_root_directory,
        &string_representing_derived_sandbox_identifier,
    );

    // 7. 实例化不可变的运行时上下文 (Sandbox Context)
    let sandbox_context_representing_runtime_environment = SandboxContext {
        string_representing_derived_sandbox_identifier: string_representing_derived_sandbox_identifier.clone(),
        path_buf_representing_host_home_directory,
        string_representing_host_username,
        path_buf_representing_sandbox_home_directory: path_buf_representing_sandbox_data_root_directory.join(&string_representing_derived_sandbox_identifier).join("sandbox_home"),
        configuration_pyramid_representing_all_layers,
    };

    // 8. 确保沙箱持久化目录存在
    sandbox_context_representing_runtime_environment.ensure_sandbox_root_and_home_directories_exist();

    // =========================================================================
    // v0.3.0 核心管线重构：多参数扫描、分类、安全门禁与组装
    // =========================================================================

    // 9. [核心] 执行多参数物理实体探针扫描与意图结算
    let target_specification_representing_validated_execution = resolve_target_executable_and_validate_via_multi_arg_scanner(
        vector_of_strings_representing_raw_target_and_arguments,
        &sandbox_context_representing_runtime_environment,
        &option_representing_cli_custom_wine_path,
    );

    // 10. [核心] 通过通用安全门禁生成穿透挂载清单
    let vector_of_mount_specifications = collect_mount_specifications(
        &sandbox_context_representing_runtime_environment,
        &target_specification_representing_validated_execution,
        &option_representing_cli_custom_wine_path,
    );

    // 11. 执行宿主物理自愈，剔除无效挂载
    let (vector_of_strings_representing_sorted_directories_to_create, vector_of_verified_mount_specifications) = 
        resolve_and_heal_mounts(
            vector_of_mount_specifications,
            &sandbox_context_representing_runtime_environment,
        );

    // 12. 组装最终容器指令并执行进程替换 (Execve)
    assemble_bubblewrap_arguments_and_execute_process_replacement(
        sandbox_context_representing_runtime_environment,
        target_specification_representing_validated_execution,
        vector_of_strings_representing_sorted_directories_to_create,
        vector_of_verified_mount_specifications,
        option_representing_cli_custom_wine_path,
    );
}
