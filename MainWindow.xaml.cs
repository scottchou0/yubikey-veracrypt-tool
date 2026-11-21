using Microsoft.Win32;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Windows;
using System.Windows.Input;
using Yubico.YubiKey;
using Yubico.YubiKey.Otp;

namespace WalletKeyTool;

public partial class MainWindow : Window
{
    private const int HmacKeySize = 20;
    private const int KeyfileSize = 64;
    private const string ChallengeLabel = "WalletKeyTool-V1-HMAC-SHA1-Challenge";
    private const string HkdfSaltLabel = "WalletKeyTool-V1-HKDF-SHA256-Salt";
    private const string HkdfInfoLabel = "WalletKeyTool-V1-VeraCrypt-Keyfile";

    public MainWindow()
    {
        InitializeComponent();
        Log("程序已启动。请先阅读安全提示，并使用测试容器演练。");
    }

    private void Log(string message)
    {
        Dispatcher.Invoke(() =>
        {
            LogBox.AppendText($"[{DateTime.Now:HH:mm:ss}] {message}{Environment.NewLine}");
            LogBox.ScrollToEnd();
        });
    }

    private static byte[] Challenge() => SHA512.HashData(Encoding.UTF8.GetBytes(ChallengeLabel));

    private static byte[] DeriveKeyfile(ReadOnlySpan<byte> ikm)
    {
        // RFC 5869 HKDF-SHA256. Keep these labels stable for compatibility with
        // previously generated Keyfiles; changing them requires a format migration.
        byte[] salt = Encoding.UTF8.GetBytes(HkdfSaltLabel);
        byte[] info = Encoding.UTF8.GetBytes(HkdfInfoLabel);
        byte[] ikmCopy = ikm.ToArray();
        byte[] prk = Array.Empty<byte>();
        byte[] previous = Array.Empty<byte>();
        byte[] output = new byte[KeyfileSize];
        try
        {
            using (var extract = new HMACSHA256(salt))
                prk = extract.ComputeHash(ikmCopy);

            using var expand = new HMACSHA256(prk);
            int offset = 0;
            byte counter = 1;
            while (offset < output.Length)
            {
                byte[] input = new byte[previous.Length + info.Length + 1];
                byte[] block;
                try
                {
                    Buffer.BlockCopy(previous, 0, input, 0, previous.Length);
                    Buffer.BlockCopy(info, 0, input, previous.Length, info.Length);
                    input[^1] = counter++;
                    block = expand.ComputeHash(input);
                }
                finally { CryptographicOperations.ZeroMemory(input); }

                try
                {
                    int take = Math.Min(block.Length, output.Length - offset);
                    Buffer.BlockCopy(block, 0, output, offset, take);
                    offset += take;
                }
                finally
                {
                    if (previous.Length > 0) CryptographicOperations.ZeroMemory(previous);
                    previous = block;
                }
            }
            return output;
        }
        catch
        {
            CryptographicOperations.ZeroMemory(output);
            throw;
        }
        finally
        {
            CryptographicOperations.ZeroMemory(ikmCopy);
            CryptographicOperations.ZeroMemory(salt);
            CryptographicOperations.ZeroMemory(info);
            if (prk.Length > 0) CryptographicOperations.ZeroMemory(prk);
            if (previous.Length > 0) CryptographicOperations.ZeroMemory(previous);
        }
    }

    private static IYubiKeyDevice GetSingleYubiKey()
    {
        var devices = YubiKeyDevice.FindAll().ToList();
        if (devices.Count == 0) throw new InvalidOperationException("未检测到 YubiKey。请检查 USB 连接。");
        if (devices.Count > 1) throw new InvalidOperationException("检测到多只 YubiKey。请只连接准备使用的一只。");
        return devices[0];
    }

    private static void WriteNewFile(string path, ReadOnlySpan<byte> data)
    {
        if (string.IsNullOrWhiteSpace(path)) throw new ArgumentException("请指定输出文件位置。");
        if (File.Exists(path)) throw new IOException("目标文件已存在。为避免覆盖，操作已取消。请选择新文件名。");
        string? dir = Path.GetDirectoryName(Path.GetFullPath(path));
        if (!string.IsNullOrEmpty(dir)) Directory.CreateDirectory(dir);
        using var fs = new FileStream(path, FileMode.CreateNew, FileAccess.Write, FileShare.None);
        fs.Write(data);
        fs.Flush(true);
    }

    private static byte[] ReadRecoverySecret(string path)
    {
        if (!File.Exists(path)) throw new FileNotFoundException("找不到恢复密钥文件。", path);
        var info = new FileInfo(path);
        if (info.Length < 40 || info.Length > 128)
            throw new InvalidDataException("恢复密钥文件大小异常；预期为 40 个十六进制字符及可选换行。");
        string hex = File.ReadAllText(path, Encoding.ASCII).Trim();
        byte[] secret;
        try { secret = Convert.FromHexString(hex); }
        catch { throw new InvalidDataException("恢复密钥文件格式不正确。"); }
        if (secret.Length != HmacKeySize)
        {
            CryptographicOperations.ZeroMemory(secret);
            throw new InvalidDataException("恢复密钥长度错误。预期为 20 字节。");
        }
        return secret;
    }

    private static byte[] GetYubiResponse(Action notify)
    {
        var key = GetSingleYubiKey();
        byte[] challenge = Challenge();
        try
        {
            using var otp = new OtpSession(key);
            return otp.CalculateChallengeResponse(Slot.ShortPress)
                .UseChallenge(challenge)
                .UseYubiOtp(false)
                .UseTouchNotifier(notify)
                .GetDataBytes().ToArray();
        }
        finally { CryptographicOperations.ZeroMemory(challenge); }
    }

    private void Detect_Click(object sender, RoutedEventArgs e)
    {
        try
        {
            var key = GetSingleYubiKey();
            DeviceStatus.Text = "检测到 YubiKey";
            DeviceDetail.Text = "已发现一只设备；请确认 OTP 短按槽可被配置。";
            Log("检测到一只 YubiKey。");
        }
        catch (Exception ex)
        {
            DeviceStatus.Text = "未检测到可用设备";
            DeviceDetail.Text = ex.Message;
            Log("设备检测失败：" + ex.Message);
        }
    }

    private async void Initialize_Click(object sender, RoutedEventArgs e)
    {
        string path = RecoveryPathBox.Text.Trim();
        if (string.IsNullOrWhiteSpace(path)) { MessageBox.Show("请选择恢复密钥文件保存位置。建议先挂载恢复容器，再选择容器内路径。"); return; }
        if (File.Exists(path)) { MessageBox.Show("恢复密钥文件已存在。为防止破坏旧恢复材料，拒绝覆盖。"); return; }
        var confirm = MessageBox.Show("此操作会覆盖 YubiKey OTP 短按槽现有配置，并创建新的恢复密钥。请确认：恢复容器已挂载、保存位置正确、短按槽可覆盖。继续？", "确认初始化", MessageBoxButton.YesNo, MessageBoxImage.Warning);
        if (confirm != MessageBoxResult.Yes) return;
        SetBusy(true);
        try
        {
            await Task.Run(() =>
            {
                byte[] secret = RandomNumberGenerator.GetBytes(HmacKeySize);
                try
                {
                    // 先以 CreateNew 写入恢复材料，再配置硬件。文件存在后绝不覆盖；异常时保留文件供排查。
                    string hex = Convert.ToHexString(secret) + Environment.NewLine;
                    using (var fs = new FileStream(path, FileMode.CreateNew, FileAccess.Write, FileShare.None))
                    using (var writer = new StreamWriter(fs, Encoding.ASCII)) { writer.Write(hex); writer.Flush(); fs.Flush(true); }
                    Log("恢复密钥已写入指定位置。现在配置 YubiKey。");
                    using (var otp = new OtpSession(GetSingleYubiKey()))
                        otp.ConfigureChallengeResponse(Slot.ShortPress).UseHmacSha1().UseKey(new ReadOnlyMemory<byte>(secret)).UseButton().Execute();
                    // 用硬件回读验证配置，确保恢复材料与设备匹配。
                    byte[] challenge = Challenge();
                    byte[] expected;
                    using (var hmac = new HMACSHA1(secret)) expected = hmac.ComputeHash(challenge);
                    byte[] actual = GetYubiResponse(() => Dispatcher.Invoke(() => MessageBox.Show(this, "请触摸 YubiKey 金属触点以完成初始化验证。", "等待触摸", MessageBoxButton.OK, MessageBoxImage.Information)));
                    bool valid = CryptographicOperations.FixedTimeEquals(expected, actual);
                    CryptographicOperations.ZeroMemory(challenge);
                    CryptographicOperations.ZeroMemory(expected);
                    CryptographicOperations.ZeroMemory(actual);
                    if (!valid) throw new CryptographicException("YubiKey 回读验证失败。恢复文件仍保留，请勿删除。");
                }
                finally { CryptographicOperations.ZeroMemory(secret); }
            });
            Log("初始化成功：恢复材料已保存，YubiKey HMAC 响应验证通过。");
            MessageBox.Show("初始化成功。请卸载恢复容器，并制作独立异地副本。现在先使用测试容器验证完整恢复流程。", "完成", MessageBoxButton.OK, MessageBoxImage.Information);
        }
        catch (Exception ex) { Log("初始化失败：" + ex.Message); MessageBox.Show("初始化失败：\n" + ex.Message + "\n\n如果恢复文件已创建，请保留它，不要重新初始化。"); }
        finally { SetBusy(false); }
    }

    private async void Provision_Click(object sender, RoutedEventArgs e)
    {
        string path = RecoveryPathBox.Text.Trim();
        if (string.IsNullOrWhiteSpace(path) || !File.Exists(path))
        {
            MessageBox.Show("请先挂载恢复容器，并选择其中已有的 recovery-secret.txt。此功能不会生成新密钥。");
            return;
        }
        var confirm = MessageBox.Show("此操作会把现有恢复密钥重新配置到当前 YubiKey 的 OTP 短按槽，并覆盖该槽现有配置。继续？", "确认重新配置", MessageBoxButton.YesNo, MessageBoxImage.Warning);
        if (confirm != MessageBoxResult.Yes) return;
        SetBusy(true);
        try
        {
            await Task.Run(() =>
            {
                byte[] secret = ReadRecoverySecret(path);
                try
                {
                    using (var otp = new OtpSession(GetSingleYubiKey()))
                        otp.ConfigureChallengeResponse(Slot.ShortPress).UseHmacSha1().UseKey(new ReadOnlyMemory<byte>(secret)).UseButton().Execute();
                    byte[] challenge = Challenge();
                    byte[] expected;
                    using (var hmac = new HMACSHA1(secret)) expected = hmac.ComputeHash(challenge);
                    byte[] actual = GetYubiResponse(() => Dispatcher.Invoke(() => Log("请触摸 YubiKey 以验证重新配置。")));
                    bool valid = CryptographicOperations.FixedTimeEquals(expected, actual);
                    CryptographicOperations.ZeroMemory(challenge);
                    CryptographicOperations.ZeroMemory(expected);
                    CryptographicOperations.ZeroMemory(actual);
                    if (!valid) throw new CryptographicException("设备响应与恢复密钥不匹配。请保留恢复材料，不要创建真实钱包容器。");
                }
                finally { CryptographicOperations.ZeroMemory(secret); }
            });
            Log("重新配置成功，硬件响应与恢复材料一致。");
            MessageBox.Show("重新配置并验证成功。请继续执行恢复演练。", "完成", MessageBoxButton.OK, MessageBoxImage.Information);
        }
        catch (Exception ex) { Log("重新配置失败：" + ex.Message); MessageBox.Show("重新配置失败：\n" + ex.Message); }
        finally { SetBusy(false); }
    }

    private async void Generate_Click(object sender, RoutedEventArgs e)
    {
        string path = KeyfilePathBox.Text.Trim();
        if (string.IsNullOrWhiteSpace(path)) { MessageBox.Show("请先选择 Keyfile 输出位置。建议选择 RAM Disk。"); return; }
        SetBusy(true);
        try
        {
            await Task.Run(() =>
            {
                byte[] response = GetYubiResponse(() => Dispatcher.Invoke(() => Log("请触摸 YubiKey 金属触点。")));
                try
                {
                    if (response.Length != 20) throw new CryptographicException("YubiKey 返回长度不是 20 字节。");
                    byte[] keyfile = DeriveKeyfile(response);
                    try { WriteNewFile(path, keyfile); }
                    finally { CryptographicOperations.ZeroMemory(keyfile); }
                }
                finally { CryptographicOperations.ZeroMemory(response); }
            });
            Log("Keyfile 生成成功：" + path);
            MessageBox.Show("Keyfile 已生成。请尽快在 VeraCrypt 中使用，并避免长期保留在普通磁盘。删除文件不保证安全擦除。", "完成");
        }
        catch (Exception ex) { Log("生成失败：" + ex.Message); MessageBox.Show("生成失败：\n" + ex.Message); }
        finally { SetBusy(false); }
    }

    private async void Recover_Click(object sender, RoutedEventArgs e)
    {
        string secretPath = RestoreSecretBox.Text.Trim();
        string outputPath = RestoreKeyfileBox.Text.Trim();
        if (string.IsNullOrWhiteSpace(secretPath) || string.IsNullOrWhiteSpace(outputPath)) { MessageBox.Show("请选择恢复密钥文件和 Keyfile 输出位置。"); return; }
        var confirm = MessageBox.Show("确认恢复容器已经挂载，并且选择的是可信的 recovery-secret.txt？恢复密钥会在本机内存中短暂使用。继续？", "确认恢复", MessageBoxButton.YesNo, MessageBoxImage.Warning);
        if (confirm != MessageBoxResult.Yes) return;
        SetBusy(true);
        try
        {
            await Task.Run(() =>
            {
                byte[] secret = ReadRecoverySecret(secretPath);
                try
                {
                    byte[] challenge = Challenge();
                    byte[] response;
                    try { using var hmac = new HMACSHA1(secret); response = hmac.ComputeHash(challenge); }
                    finally { CryptographicOperations.ZeroMemory(challenge); }
                    try
                    {
                        byte[] keyfile = DeriveKeyfile(response);
                        try { WriteNewFile(outputPath, keyfile); }
                        finally { CryptographicOperations.ZeroMemory(keyfile); }
                    }
                    finally { CryptographicOperations.ZeroMemory(response); }
                }
                finally { CryptographicOperations.ZeroMemory(secret); }
            });
            Log("恢复 Keyfile 生成成功：" + outputPath);
            MessageBox.Show("恢复 Keyfile 已生成。下一步必须使用它和主容器原密码实际挂载主容器，验证恢复是否成功。", "恢复完成");
        }
        catch (Exception ex) { Log("恢复失败：" + ex.Message); MessageBox.Show("恢复失败：\n" + ex.Message); }
        finally { SetBusy(false); }
    }

    private void Compare_Click(object sender, RoutedEventArgs e)
    {
        try
        {
            string a = NormalCompareBox.Text.Trim(), b = RestoreCompareBox.Text.Trim();
            if (!File.Exists(a) || !File.Exists(b)) throw new FileNotFoundException("请分别选择两个已生成的 Keyfile。");
            if (new FileInfo(a).Length != KeyfileSize || new FileInfo(b).Length != KeyfileSize)
                throw new InvalidDataException("Keyfile 长度不正确。当前版本要求两个文件均为 64 字节。");
            byte[] ba = File.ReadAllBytes(a);
            byte[] bb = File.ReadAllBytes(b);
            try
            {
                if (ba.Length != KeyfileSize || bb.Length != KeyfileSize)
                    throw new InvalidDataException("Keyfile 长度不正确。当前版本要求两个文件均为 64 字节。");
                byte[] ha = SHA256.HashData(ba);
                byte[] hb = SHA256.HashData(bb);
                try
                {
                    bool equal = CryptographicOperations.FixedTimeEquals(ha, hb);
                    CompareResult.Text = equal ? "通过：两个 Keyfile 的 SHA-256 完全一致。仍需实际挂载容器验证。" : "失败：两个 Keyfile 不一致。不要使用它们解锁真实钱包容器。";
                    CompareResult.Foreground = equal ? System.Windows.Media.Brushes.LightGreen : System.Windows.Media.Brushes.OrangeRed;
                    Log(equal ? "Keyfile 哈希一致。" : "Keyfile 哈希不一致！");
                }
                finally { CryptographicOperations.ZeroMemory(ha); CryptographicOperations.ZeroMemory(hb); }
            }
            finally { CryptographicOperations.ZeroMemory(ba); CryptographicOperations.ZeroMemory(bb); }
        }
        catch (Exception ex) { MessageBox.Show(ex.Message); }
    }

    private void BrowseRecovery_Click(object sender, RoutedEventArgs e) => SavePath(RecoveryPathBox, "恢复密钥文本|recovery-secret.txt|所有文件|*.*");
    private void BrowseKeyfile_Click(object sender, RoutedEventArgs e) => SavePath(KeyfilePathBox, "Keyfile|wallet.key|所有文件|*.*");
    private void BrowseRestoreKeyfile_Click(object sender, RoutedEventArgs e) => SavePath(RestoreKeyfileBox, "Keyfile|recovered.key|所有文件|*.*");
    private void BrowseRestoreSecret_Click(object sender, RoutedEventArgs e) => OpenPath(RestoreSecretBox, "恢复密钥文件|*.txt|所有文件|*.*");
    private void BrowseNormalCompare_Click(object sender, RoutedEventArgs e) => OpenPath(NormalCompareBox, "Keyfile|*.*");
    private void BrowseRestoreCompare_Click(object sender, RoutedEventArgs e) => OpenPath(RestoreCompareBox, "Keyfile|*.*");
    private void BrowseVeraCrypt_Click(object sender, RoutedEventArgs e) => OpenPath(VeraCryptPathBox, "VeraCrypt 程序|VeraCrypt.exe|程序|*.exe");

    private static void SavePath(System.Windows.Controls.TextBox box, string filter)
    {
        var d = new SaveFileDialog { Filter = filter, AddExtension = false, OverwritePrompt = false };
        if (d.ShowDialog() == true) box.Text = d.FileName;
    }
    private static void OpenPath(System.Windows.Controls.TextBox box, string filter)
    {
        var d = new OpenFileDialog { Filter = filter, CheckFileExists = true };
        if (d.ShowDialog() == true) box.Text = d.FileName;
    }

    private void OpenVeraCrypt_Click(object sender, RoutedEventArgs e)
    {
        try
        {
            string path = VeraCryptPathBox.Text.Trim();
            if (!File.Exists(path)) throw new FileNotFoundException("请先选择 VeraCrypt.exe 的位置。");
            Process.Start(new ProcessStartInfo(path) { UseShellExecute = true });
            Log("已打开 VeraCrypt。密码输入和挂载操作由 VeraCrypt 自己处理。");
        }
        catch (Exception ex) { MessageBox.Show(ex.Message); }
    }

    private void SetBusy(bool busy)
    {
        IsEnabled = !busy;
        Mouse.OverrideCursor = busy ? Cursors.Wait : null;
    }
}
