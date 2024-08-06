using System;
using System.Text;
using System.Security.Cryptography;
using Microsoft.Win32;
using System.Diagnostics;
using System.IO;
using System.Management;
using System.Net.NetworkInformation;
using System.Security.Principal;

class Program
{
    static void Main(string[] args)
    {
        Console.WriteLine("Enter your license key (format: ####-####-####-####): ");
        string licenseKey = Console.ReadLine();

        if (ValidateLicenseKey(licenseKey))
        {
            Console.WriteLine("License key is valid.");
            // Proceed with the rest of the program
            while (true)
            {
                ShowMenu();
                string choice = Console.ReadLine();

                if (choice == "1")
                {
                    CheckHWID();
                    ReturnToMenu();
                }
                else if (choice == "2")
                {
                    if (!IsRunAsAdministrator())
                    {
                        // Restart the program with administrator rights
                        var processInfo = new ProcessStartInfo(Process.GetCurrentProcess().MainModule.FileName)
                        {
                            UseShellExecute = true,
                            Verb = "runas"
                        };
                        Process.Start(processInfo);
                        Environment.Exit(0);
                    }
                    else
                    {
                        Console.Write("Do you want to spoof your hardware (y/n): ");
                        string spoofChoice = Console.ReadLine();
                        if (spoofChoice.Equals("y", StringComparison.OrdinalIgnoreCase))
                        {
                            SpoofHWID();
                            ReturnToMenu();
                        }
                        else
                        {
                            ReturnToMenu();
                        }
                    }
                }
                else
                {
                    Console.WriteLine("Invalid choice. Please enter 1 or 2.");
                    ReturnToMenu();
                }
            }
        }
        else
        {
            Console.WriteLine("Invalid license key. Exiting...");
            Console.ReadLine(); // Wait for user to press Enter before exiting
        }
    }

    static bool ValidateLicenseKey(string licenseKey)
    {
        if (string.IsNullOrEmpty(licenseKey) || licenseKey.Length != 19)
            return false;

        // Check format ####-####-####-####
        var parts = licenseKey.Split('-');
        if (parts.Length != 4 || parts[0].Length != 4 || parts[1].Length != 4 || parts[2].Length != 4 || parts[3].Length != 4)
            return false;

        // Encode license key to Base64
        string base64EncodedKey = Convert.ToBase64String(Encoding.UTF8.GetBytes(licenseKey));

        // Calculate the sum of all numeric characters in the base64 encoded string
        int sum = 0;
        foreach (char c in base64EncodedKey)
        {
            if (char.IsDigit(c))
            {
                sum += c - '0';
            }
        }

        // Add the numbers in the last part of the original key
        foreach (char c in parts[3])
        {
            if (char.IsDigit(c))
            {
                sum += c - '0';
            }
        }

        // Check if the sum is in the range of 0 to 20
        return sum >= 0 && sum <= 20;
    }

    static void ShowMenu()
    {
        Console.Clear();
        Console.WriteLine("========================================================");
        Console.WriteLine("=                   Check HWID  (1)                    =");
        Console.WriteLine("=                   Spoof HWID  (2)                    =");
        Console.WriteLine("========================================================");
        Console.Write("Enter your choice: ");
    }

    static void ReturnToMenu()
    {
        Console.WriteLine("\nPress Enter to return to the menu...");
        Console.ReadLine();
        Console.Clear();
    }

    static void CheckHWID()
    {
        QueryWmi("SELECT SerialNumber FROM Win32_BaseBoard", "SerialNumber");
        QueryWmi("SELECT ProcessorId FROM Win32_Processor", "ProcessorId");
        QueryWmi("SELECT SerialNumber FROM Win32_DiskDrive", "SerialNumber");
        QueryWmi("SELECT SerialNumber FROM Win32_BIOS", "SerialNumber");
        QueryWmi("SELECT SerialNumber FROM Win32_PhysicalMemory", "SerialNumber");
        QueryWmi("SELECT DeviceID, VolumeSerialNumber FROM Win32_LogicalDisk", "VolumeSerialNumber");
        QueryWmi("SELECT MACAddress FROM Win32_NetworkAdapter WHERE MACAddress IS NOT NULL", "MACAddress");
        QueryWmi("SELECT Name FROM Win32_VideoController", "Name");
        QueryWmi("SELECT Name FROM Win32_ComputerSystem", "Name");
        QueryWmi("SELECT SerialNumber FROM Win32_OperatingSystem", "SerialNumber");
        QueryWmi("SELECT FirmwareType FROM Win32_ComputerSystem", "FirmwareType");
        QueryWmi("SELECT SMBIOSBIOSVersion FROM Win32_BIOS", "SMBIOSBIOSVersion");
    }

    static void QueryWmi(string query, string property)
    {
        try
        {
            ManagementObjectSearcher searcher = new ManagementObjectSearcher(query);
            foreach (ManagementObject queryObj in searcher.Get())
            {
                if (queryObj[property] != null)
                {
                    Console.WriteLine($"{property} : {queryObj[property]}");
                }
            }
        }
        catch (ManagementException e)
        {
            Console.WriteLine("An error occurred while querying for WMI data: " + e.Message);
        }
    }

    static bool IsRunAsAdministrator()
    {
        var wi = WindowsIdentity.GetCurrent();
        var wp = new WindowsPrincipal(wi);
        return wp.IsInRole(WindowsBuiltInRole.Administrator);
    }

    static void SpoofHWID()
    {
        CheckRegistryKeys();
        SpoofInstallationID();
        SpoofPCName();
        SpoofDisks();
        SpoofGUIDs();
        SpoofMAC();
        SpoofGPU();
        SpoofEFIVariableId();
        SpoofSMBIOSSerialNumber();
        UbisoftCache();
        DeleteValorantCache();
        Console.WriteLine("\nHWID spoofing completed.");
    }

    // Spoofing Methods
    public static void CheckRegistryKeys()
    {
        try
        {
            CheckRegistryKey("SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion", "InstallationID");
            CheckRegistryKey("SYSTEM\\CurrentControlSet\\Control\\ComputerName\\ComputerName", "ComputerName");
            CheckRegistryKey("SYSTEM\\CurrentControlSet\\Control\\ComputerName\\ComputerName", "ActiveComputerName");
            CheckRegistryKey("SYSTEM\\CurrentControlSet\\Control\\ComputerName\\ComputerNamePhysicalDnsDomain", "");
            CheckRegistryKey("SYSTEM\\CurrentControlSet\\Control\\ComputerName\\ActiveComputerName", "ComputerName");
            CheckRegistryKey("SYSTEM\\CurrentControlSet\\Control\\ComputerName\\ActiveComputerName", "ActiveComputerName");
            CheckRegistryKey("SYSTEM\\CurrentControlSet\\Control\\ComputerName\\ActiveComputerName", "ComputerNamePhysicalDnsDomain");
            CheckRegistryKey("SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters", "Hostname");
            CheckRegistryKey("SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters", "NV Hostname");
            CheckRegistryKey("SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters\\Interfaces", "Hostname");
            CheckRegistryKey("SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters\\Interfaces", "NV Hostname");
            CheckRegistryKey("HARDWARE\\DEVICEMAP\\Scsi", ""); // ScsiPorts
            CheckRegistryKey("HARDWARE\\DEVICEMAP\\Scsi\\{port}", ""); // ScsiBuses
            CheckRegistryKey("HARDWARE\\DEVICEMAP\\Scsi\\{port}\\{bus}\\Target Id 0\\Logical Unit Id 0", "DeviceIdentifierPage");
            CheckRegistryKey("HARDWARE\\DEVICEMAP\\Scsi\\{port}\\{bus}\\Target Id 0\\Logical Unit Id 0", "Identifier");
            CheckRegistryKey("HARDWARE\\DEVICEMAP\\Scsi\\{port}\\{bus}\\Target Id 0\\Logical Unit Id 0", "InquiryData");
            CheckRegistryKey("HARDWARE\\DEVICEMAP\\Scsi\\{port}\\{bus}\\Target Id 0\\Logical Unit Id 0", "SerialNumber");
            CheckRegistryKey("HARDWARE\\DESCRIPTION\\System\\MultifunctionAdapter\\0\\DiskController\\0\\DiskPeripheral", ""); // DiskPeripherals
            CheckRegistryKey("HARDWARE\\DESCRIPTION\\System\\MultifunctionAdapter\\0\\DiskController\\0\\DiskPeripheral\\{disk}", "Identifier");
            CheckRegistryKey("SYSTEM\\CurrentControlSet\\Control\\IDConfigDB\\Hardware Profiles\\0001", "HwProfileGuid");
            CheckRegistryKey("SOFTWARE\\Microsoft\\Cryptography", "MachineGuid");
            CheckRegistryKey("SOFTWARE\\Microsoft\\SQMClient", "MachineId");
            CheckRegistryKey("SYSTEM\\CurrentControlSet\\Control\\SystemInformation", "BIOSReleaseDate");
            CheckRegistryKey("SYSTEM\\CurrentControlSet\\Control\\SystemInformation", "BIOSVersion");
            CheckRegistryKey("SYSTEM\\CurrentControlSet\\Control\\SystemInformation", "ComputerHardwareId");
            CheckRegistryKey("SYSTEM\\CurrentControlSet\\Control\\SystemInformation", "ComputerHardwareIds");
            CheckRegistryKey("SYSTEM\\CurrentControlSet\\Control\\SystemInformation", "ComputerManufacturer");
            CheckRegistryKey("SYSTEM\\CurrentControlSet\\Control\\SystemInformation", "ComputerModel");
            CheckRegistryKey("SYSTEM\\CurrentControlSet\\Control\\SystemInformation", "InstallDate");
            CheckRegistryKey("SYSTEM\\CurrentControlSet\\Control\\SystemInformation", "SystemBiosMajorVersion");
            CheckRegistryKey("SYSTEM\\CurrentControlSet\\Control\\SystemInformation", "SystemBiosMinorVersion");
            CheckRegistryKey("SYSTEM\\CurrentControlSet\\Control\\SystemInformation", "SystemBiosVersion");
            CheckRegistryKey("SYSTEM\\CurrentControlSet\\Control\\SystemInformation", "SystemManufacturer");
            CheckRegistryKey("SYSTEM\\CurrentControlSet\\Control\\SystemInformation", "SystemProductName");
            CheckRegistryKey("SYSTEM\\CurrentControlSet\\Control\\SystemInformation", "SystemSku");
            CheckRegistryKey("SYSTEM\\CurrentControlSet\\Control\\SystemInformation", "SystemVersion");
        }
        catch (Exception ex)
        {
            Console.WriteLine("Error to check the Registry-Key: " + ex.Message);
        }
    }

    public static void CheckRegistryKey(string keyPath, string valueName)
    {
        RegistryKey key = Registry.LocalMachine.OpenSubKey(keyPath);
        if (key != null)
        {
            if (!string.IsNullOrEmpty(valueName))
            {
                if (key.GetValue(valueName) == null)
                {
                    Console.WriteLine("Registry-Key not found: " + keyPath + "\\" + valueName);
                }
            }
            else
            {
                if (key.SubKeyCount == 0)
                {
                    Console.WriteLine("Registry-Key not found: " + keyPath);
                }
            }
        }
        else
        {
            Console.WriteLine("Registry-Key not found: " + keyPath);
        }
    }

    public static void SpoofInstallationID()
    {
        using (RegistryKey key = Registry.LocalMachine.OpenSubKey("SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion", true))
        {
            if (key != null)
            {
                string newInstallationID = Guid.NewGuid().ToString();
                key.SetValue("InstallationID", newInstallationID);
                key.Close();
            }
        }
    }

    public static void SpoofPCName()
    {
        string randomName = RandomId(8); // Generate a random PC name
        using (RegistryKey computerName = Registry.LocalMachine.OpenSubKey("SYSTEM\\CurrentControlSet\\Control\\ComputerName\\ComputerName", true))
        {
            computerName.SetValue("ComputerName", randomName);
            computerName.SetValue("ActiveComputerName", randomName);
            computerName.SetValue("ComputerNamePhysicalDnsDomain", "");
        }

        using (RegistryKey activeComputerName = Registry.LocalMachine.OpenSubKey("SYSTEM\\CurrentControlSet\\Control\\ComputerName\\ActiveComputerName", true))
        {
            activeComputerName.SetValue("ComputerName", randomName);
            activeComputerName.SetValue("ActiveComputerName", randomName);
            activeComputerName.SetValue("ComputerNamePhysicalDnsDomain", "");
        }

        using (RegistryKey tcpipParams = Registry.LocalMachine.OpenSubKey("SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters", true))
        {
            tcpipParams.SetValue("Hostname", randomName);
            tcpipParams.SetValue("NV Hostname", randomName);
        }

        using (RegistryKey tcpipInterfaces = Registry.LocalMachine.OpenSubKey("SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters\\Interfaces", true))
        {
            foreach (string interfaceKey in tcpipInterfaces.GetSubKeyNames())
            {
                using (RegistryKey interfaceSubKey = tcpipInterfaces.OpenSubKey(interfaceKey, true))
                {
                    interfaceSubKey.SetValue("Hostname", randomName);
                    interfaceSubKey.SetValue("NV Hostname", randomName);
                }
            }
        }
    }

    public static string RandomId(int length)
    {
        string chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
        StringBuilder result = new StringBuilder();
        Random random = new Random();

        for (int i = 0; i < length; i++)
        {
            result.Append(chars[random.Next(chars.Length)]);
        }

        return result.ToString();
    }

    public static string RandomMac()
    {
        string chars = "ABCDEF0123456789";
        string windows = "26AE";
        StringBuilder result = new StringBuilder();
        Random random = new Random();

        result.Append(chars[random.Next(chars.Length)]);
        result.Append(windows[random.Next(windows.Length)]);

        for (int i = 0; i < 5; i++)
        {
            result.Append("-");
            result.Append(chars[random.Next(chars.Length)]);
            result.Append(chars[random.Next(chars.Length)]);
        }

        return result.ToString();
    }

    public static void Enable_LocalAreaConnection(string adapterId, bool enable = true)
    {
        string interfaceName = "Ethernet";
        foreach (NetworkInterface i in NetworkInterface.GetAllNetworkInterfaces())
        {
            if (i.Id == adapterId)
            {
                interfaceName = i.Name;
                break;
            }
        }

        string control = enable ? "enable" : "disable";

        var psi = new ProcessStartInfo("netsh", $"interface set interface \"{interfaceName}\" {control}")
        {
            RedirectStandardOutput = true,
            UseShellExecute = false,
            CreateNoWindow = true
        };
        var p = new Process
        {
            StartInfo = psi
        };
        p.Start();
        p.WaitForExit();
    }

    public static void SpoofDisks()
    {
        using (RegistryKey ScsiPorts = Registry.LocalMachine.OpenSubKey("HARDWARE\\DEVICEMAP\\Scsi"))
        {
            foreach (string port in ScsiPorts.GetSubKeyNames())
            {
                using (RegistryKey ScsiBuses = Registry.LocalMachine.OpenSubKey($"HARDWARE\\DEVICEMAP\\Scsi\\{port}"))
                {
                    foreach (string bus in ScsiBuses.GetSubKeyNames())
                    {
                        using (RegistryKey ScsuiBus = Registry.LocalMachine.OpenSubKey($"HARDWARE\\DEVICEMAP\\Scsi\\{port}\\{bus}\\Target Id 0\\Logical Unit Id 0", true))
                        {
                            if (ScsuiBus != null)
                            {
                                if (ScsuiBus.GetValue("DeviceType").ToString() == "DiskPeripheral")
                                {
                                    string identifier = RandomId(14);
                                    string serialNumber = RandomId(14);

                                    ScsuiBus.SetValue("DeviceIdentifierPage", Encoding.UTF8.GetBytes(serialNumber));
                                    ScsuiBus.SetValue("Identifier", identifier);
                                    ScsuiBus.SetValue("InquiryData", Encoding.UTF8.GetBytes(identifier));
                                    ScsuiBus.SetValue("SerialNumber", serialNumber);
                                }
                            }
                        }
                    }
                }
            }
        }

        using (RegistryKey DiskPeripherals = Registry.LocalMachine.OpenSubKey("HARDWARE\\DESCRIPTION\\System\\MultifunctionAdapter\\0\\DiskController\\0\\DiskPeripheral"))
        {
            foreach (string disk in DiskPeripherals.GetSubKeyNames())
            {
                using (RegistryKey DiskPeripheral = Registry.LocalMachine.OpenSubKey($"HARDWARE\\DESCRIPTION\\System\\MultifunctionAdapter\\0\\DiskController\\0\\DiskPeripheral\\{disk}", true))
                {
                    DiskPeripheral.SetValue("Identifier", $"{RandomId(8)}-{RandomId(8)}-A");
                }
            }
        }
    }

    public static void SpoofGUIDs()
    {
        using (RegistryKey HardwareGUID = Registry.LocalMachine.OpenSubKey("SYSTEM\\CurrentControlSet\\Control\\IDConfigDB\\Hardware Profiles\\0001", true))
        {
            HardwareGUID.SetValue("HwProfileGuid", $"{{{Guid.NewGuid()}}}");
        }

        using (RegistryKey MachineGUID = Registry.LocalMachine.OpenSubKey("SOFTWARE\\Microsoft\\Cryptography", true))
        {
            MachineGUID.SetValue("MachineGuid", Guid.NewGuid().ToString());
        }

        using (RegistryKey MachineId = Registry.LocalMachine.OpenSubKey("SOFTWARE\\Microsoft\\SQMClient", true))
        {
            MachineId.SetValue("MachineId", $"{{{Guid.NewGuid()}}}");
        }

        using (RegistryKey SystemInfo = Registry.LocalMachine.OpenSubKey("SYSTEM\\CurrentControlSet\\Control\\SystemInformation", true))
        {
            Random rnd = new Random();
            int day = rnd.Next(1, 31);
            string dayStr = day < 10 ? $"0{day}" : day.ToString();

            int month = rnd.Next(1, 13);
            string monthStr = month < 10 ? $"0{month}" : month.ToString();

            SystemInfo.SetValue("BIOSReleaseDate", $"{dayStr}/{monthStr}/{rnd.Next(2000, 2023)}");
            SystemInfo.SetValue("BIOSVersion", RandomId(10));
            SystemInfo.SetValue("ComputerHardwareId", $"{{{Guid.NewGuid()}}}");
            SystemInfo.SetValue("ComputerHardwareIds", $"{{{Guid.NewGuid()}}}\n{{{Guid.NewGuid()}}}\n{{{Guid.NewGuid()}}}\n");
            SystemInfo.SetValue("SystemManufacturer", RandomId(15));
            SystemInfo.SetValue("SystemProductName", RandomId(6));
        }

        using (RegistryKey Update = Registry.LocalMachine.OpenSubKey("SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\WindowsUpdate", true))
        {
            Update.SetValue("SusClientId", Guid.NewGuid().ToString());
            Update.SetValue("SusClientIdValidation", Encoding.UTF8.GetBytes(RandomId(25)));
        }
    }

    public static void UbisoftCache()
    {
        string appDataPath = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
        string ubisoftPath = Path.Combine("Ubisoft Game Launcher", "cache");
        string ubisoftLogsPath = Path.Combine("Ubisoft Game Launcher", "logs");
        string ubisoftSavegamesPath = Path.Combine("Ubisoft Game Launcher", "savegames");
        string ubisoftSpoolPath = Path.Combine("Ubisoft Game Launcher", "spool");

        DeleteDirectoryFiles(Path.Combine("C:", "Program Files (x86)", "Ubisoft", ubisoftPath));
        DeleteDirectoryFiles(Path.Combine("C:", "Program Files (x86)", "Ubisoft", ubisoftLogsPath));
        DeleteDirectoryFiles(Path.Combine("C:", "Program Files (x86)", "Ubisoft", ubisoftSavegamesPath));
        DeleteDirectoryFiles(Path.Combine(appDataPath, "Ubisoft Game Launcher", ubisoftSpoolPath));
    }

    public static void DeleteValorantCache()
    {
        string valorantPath = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData) + "\\VALORANT\\saved";

        if (Directory.Exists(valorantPath))
        {
            DeleteDirectoryFiles(valorantPath);
        }
    }

    public static void DeleteDirectoryFiles(string directoryPath)
    {
        DirectoryInfo di = new DirectoryInfo(directoryPath);

        foreach (FileInfo file in di.GetFiles())
        {
            file.Delete();
        }
        foreach (DirectoryInfo dir in di.GetDirectories())
        {
            dir.Delete(true);
        }
    }

    public static bool SpoofMAC()
    {
        bool err = false;

        using (RegistryKey NetworkAdapters = Registry.LocalMachine.OpenSubKey("SYSTEM\\CurrentControlSet\\Control\\Class\\{4d36e972-e325-11ce-bfc1-08002be10318}"))
        {
            foreach (string adapter in NetworkAdapters.GetSubKeyNames())
            {
                if (adapter != "Properties")
                {
                    try
                    {
                        using (RegistryKey NetworkAdapter = Registry.LocalMachine.OpenSubKey($"SYSTEM\\CurrentControlSet\\Control\\Class\\{{4d36e972-e325-11ce-bfc1-08002be10318}}\\{adapter}", true))
                        {
                            if (NetworkAdapter.GetValue("BusType") != null)
                            {
                                NetworkAdapter.SetValue("NetworkAddress", RandomMac());
                                string adapterId = NetworkAdapter.GetValue("NetCfgInstanceId").ToString();
                                Enable_LocalAreaConnection(adapterId, false);
                                Enable_LocalAreaConnection(adapterId, true);
                            }
                        }
                    }
                    catch (System.Security.SecurityException)
                    {
                        Console.WriteLine("\n[X] Start the spoofer in admin mode to spoof your MAC address!");
                        err = true;
                        break;
                    }
                }
            }
        }

        return err;
    }

    public static void SpoofGPU()
    {
        string keyName = @"SYSTEM\CurrentControlSet\Enum\PCI\VEN_10DE&DEV_0DE1&SUBSYS_37621462&REV_A1";
        using (RegistryKey key = Registry.LocalMachine.OpenSubKey(keyName, true))
        {
            if (key != null)
            {
                string newHardwareID = "PCIVEN_8086&DEV_1234&SUBSYS_5678ABCD&REV_01";
                string oldHardwareID = key.GetValue("HardwareID") as string;

                key.SetValue("HardwareID", newHardwareID);
                key.SetValue("CompatibleIDs", new string[] { newHardwareID });
                key.SetValue("Driver", "pci.sys");
                key.SetValue("ConfigFlags", 0x00000000, RegistryValueKind.DWord);
                key.SetValue("ClassGUID", "{4d36e968-e325-11ce-bfc1-08002be10318}");
                key.SetValue("Class", "Display");

                key.Close();
            }
        }
    }

    public static void SpoofEFIVariableId()
    {
        try
        {
            using (RegistryKey efiVariables = Registry.LocalMachine.OpenSubKey("SYSTEM\\CurrentControlSet\\Control\\Nsi\\{eb004a03-9b1a-11d4-9123-0050047759bc}\\26", true))
            {
                if (efiVariables != null)
                {
                    string efiVariableId = Guid.NewGuid().ToString();
                    efiVariables.SetValue("VariableId", efiVariableId);
                    efiVariables.Close();
                }
            }
        }
        catch (Exception)
        {
            Console.WriteLine("\n[X] Start the spoofer in admin mode to spoof your MAC address!");
        }
    }

    public static void SpoofSMBIOSSerialNumber()
    {
        try
        {
            using (RegistryKey smbiosData = Registry.LocalMachine.OpenSubKey("HARDWARE\\DESCRIPTION\\System\\BIOS", true))
            {
                if (smbiosData != null)
                {
                    string serialNumber = RandomId(10);
                    smbiosData.SetValue("SystemSerialNumber", serialNumber);
                    smbiosData.Close();
                }
                else
                {
                    Console.WriteLine("\n[X] Cant find the SMBIOS");
                }
            }
        }
        catch (Exception)
        {
            Console.WriteLine("\n[X] Start the spoofer in admin mode to spoof your MAC address!");
        }
    }
}
