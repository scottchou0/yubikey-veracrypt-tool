yubikey-veracrypt-tool原名称为WalletKeyTool
下文均称为WalletKeyTool

C# WPF / Windows 桌面辅助程序：YubiKey OTP HMAC-SHA1 Challenge-Response + HKDF-SHA256 + VeraCrypt Keyfile。

> **安全状态：研究/测试原型。未经过独立安全审计，且本次生成环境没有 .NET SDK 和实体 YubiKey，无法在此实际编译或完成硬件集成测试。不要直接用于真实助记词或重要资产。先用虚构恢复密钥和 VeraCrypt 测试容器完成全流程演练。**

## 项目结构

- `src/WalletKeyTool/WalletKeyTool.csproj`：WPF 项目文件
- `src/WalletKeyTool/App.xaml`：深色主题资源
- `src/WalletKeyTool/MainWindow.xaml`：中文图形界面
- `src/WalletKeyTool/MainWindow.xaml.cs`：设备检测、初始化、重新配置、Keyfile 生成、恢复、哈希验证

## 环境

- Windows 10/11 x64（建议使用仍受支持的 Windows 版本）
- .NET 8 SDK
- 支持 OTP HMAC-SHA1 Challenge-Response 的 YubiKey
- VeraCrypt（单独安装）

NuGet 使用 `Yubico.YubiKey` 1.18.1。HMAC-SHA1 Challenge-Response 使用 20 字节 HMAC 密钥和 64 字节 challenge；通过 USB/Lightning HID 工作，不支持 NFC 方式完成此流程。

## 编译运行

1. 安装 Visual Studio 2022，并选择“.NET 桌面开发”工作负载及 .NET 8 SDK。
2. 解压本项目。
3. 用 Visual Studio 打开 `src/WalletKeyTool/WalletKeyTool.csproj`，或在该目录打开 PowerShell 执行：

```powershell
dotnet restore
dotnet build -c Release
dotnet run
```

发布单文件：

```powershell
dotnet publish -c Release -r win-x64 --self-contained true /p:PublishSingleFile=true
```

输出目录：`bin\Release\net8.0-windows\win-x64\publish\`。

## 操作顺序

1. 在 VeraCrypt 中创建独立恢复容器，使用独立强密码，不添加本程序生成的 Keyfile；挂载为盘符（例如 R:）。
2. 在程序“首次初始化”中，将恢复密钥路径设为 `R:\recovery-secret.txt`。程序先用 `CreateNew` 写入恢复材料，再配置 YubiKey OTP 短按槽 HMAC-SHA1，并用硬件响应回读验证。
3. 若初始化中断但恢复文件已经创建，保留该文件；使用“使用已有恢复密钥重新配置 YubiKey”继续，不要重新生成另一份恢复密钥。
4. 卸载恢复容器。制作至少两份独立副本并分开存放；恢复容器密码单独保管，不与容器副本放在一起。
5. 日常使用“连接 YubiKey 并生成 Keyfile”。输出位置优先选择 RAM Disk（需自行安装和配置）；不要把 Keyfile 长期留在普通磁盘。
6. 在 VeraCrypt GUI 中手动选择主容器、输入主容器密码并添加 Keyfile。本程序不会把密码放进命令行，也不会自动挂载。
7. 恢复演练：挂载恢复容器，选择 `recovery-secret.txt`，生成恢复 Keyfile；比较两个 64 字节 Keyfile 的 SHA-256；最后用恢复 Keyfile 和主容器原密码实际挂载测试容器。

## 0.2.0 变更

- HKDF-SHA256 代码整理为 RFC 5869 两轮扩展逻辑，增加中间缓冲区清理；算法标签保持不变，以免改变既有 Keyfile。
- 恢复密钥文件增加大小限制，避免读取异常大文件。
- 比较 Keyfile 前检查文件必须为 64 字节，并在比较后清理内存缓冲区。
- 版本号更新为 0.2.0。

## 关键安全限制

- HMAC-SHA1 是 YubiKey OTP Challenge-Response 此接口提供的算法；密钥为 20 字节。HKDF 输出 64 字节并不会把原始安全强度提高到 512 bit。
- 恢复密钥文件是敏感明文材料，只能保存在已挂载的 VeraCrypt 恢复容器内；不要放在普通磁盘或与主容器放在同一介质。
- 单只 YubiKey 丢失或损坏时，恢复材料可用于重新配置另一只兼容 YubiKey；恢复材料本身必须保持机密。
- YubiKey 触摸确认不能防御已经感染的 Windows。恶意软件可能在响应生成、Keyfile 输出或容器挂载后窃取数据。
- 删除 Keyfile 不等于可靠擦除。SSD、页面文件、休眠文件、崩溃转储和备份可能保留数据。
- VeraCrypt XTS 主要提供机密性，不提供独立的文件完整性认证。SHA-256 比较只能证明两份 Keyfile 字节一致，不是对恢复密钥来源的认证。
- 不要把恢复密钥、助记词、Keyfile 或 VeraCrypt 密码粘贴到聊天窗口、日志或截图中。

## 必须完成的测试

- 先用虚构恢复密钥及空白测试容器，完整测试初始化、日常生成、恢复生成、重新配置、SHA-256 比对和 VeraCrypt 实际挂载。
- 在干净的第二台 Windows 设备上执行恢复演练，验证恢复容器副本确实可用。
- 只以哈希一致作为成功标准是不够的；必须实际挂载测试容器并读取测试文件。
- 在完成 Windows 编译、真实硬件测试和独立安全审计前，不要导入真实助记词或存放重要资产。
