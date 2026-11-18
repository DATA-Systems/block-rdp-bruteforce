<#
  .SYNOPSIS
  Detects and blocks Remote Desktop Services (RDS) brute-force attacks using only Windows Event Logs
  and the builtin Windows Firewall.

  .DESCRIPTION
  Scans Windows Event Logs for RDS/RDP connection attempts, detects brute-force activity within a
  configurable time window, logs suspicious IP addresses, and blocks them using dedicated
  Windows Firewall rules.
  - PowerShell 7 recommended, but works with Windows PowerShell (v5), too
  - Uses compiled C# to interact with eventlogs, because eveything else is just slow
  - Excludes IPv4 private address ranges, ULA and localhost from beeing blocked
  - No parameters needed, just run it script evey 5-10m
  - Creates and uses a (customizeable) Windows firewall rule
  - Logs to Windows "application" eventlog (Event ID 13370)

  .EXAMPLE
  PS> .\block_rdp_brute.ps1

  .EXAMPLE
  Task Scheduler: powershell.exe -NoProfile -NoLogo -NonInteractive -ExecutionPolicy Bypass -File "<PATH>\block_rdp_brute.ps1"

  .NOTES
  (c) DATA-Systems 2022, OpenSource, tested contributions welcome (we use this in prod)
    v1.25   18.11.2025 b.stromberg@data-systems.de
    v1.1    03.06.2022 FL
    v1.0    18.05.2022 FL
#>

# Name of firewall rule. Default "BlockRDPBruteForce"
$ruleName = "BlockRDPBruteForce"

# PowerShell 7 / .NET: Add-Type requires *explicit* references to framework assemblies.
# The assemblies are intentionally specified by NAME (rather than by file path from the
# TRUSTED_PLATFORM_ASSEMBLIES list), because Add-Type resolves these names against the runtime itself.
# If paths are used instead, the compiler fails to locate System.Private.CoreLib (error CS0012).
# The only exception is System.Diagnostics.EventLog, which is not part of the shared framework
# and is therefore specified via its file path. Thanks for that.
$referencedAssemblies = $null
if ($PSVersionTable.PSEdition -eq "Core") {
    Add-Type -AssemblyName System.Diagnostics.EventLog -ErrorAction Stop

    $eventLogAssemblyPath = [System.Diagnostics.EventLog].Assembly.Location
    if ([string]::IsNullOrWhiteSpace($eventLogAssemblyPath) -or
        -not (Test-Path -LiteralPath $eventLogAssemblyPath)) {
        throw "Die Assembly System.Diagnostics.EventLog konnte nicht aufgelöst werden."
    }

    $referencedAssemblies = @(
        "System.Runtime"
        "System.Private.CoreLib"
        "System.Collections"
        "System.Linq"
        "System.Linq.Expressions"
        "System.ObjectModel"
        "System.Threading"
        "System.Net.Primitives"
        "System.Net.NetworkInformation"
        "System.ComponentModel.Primitives"
        "Microsoft.CSharp"
        $eventLogAssemblyPath
    )
}

$typeDefinition = @"

    using System;
    using System.Collections.Generic;
    using System.Diagnostics;
    using System.Diagnostics.Eventing.Reader;
    using System.IO;
    using System.Linq;
    using System.Net;
    using System.Net.NetworkInformation;
    using System.Runtime.InteropServices;

    public class IPComparer : IComparer<IPAddress>
    {
        private static readonly Lazy<IPComparer> _default = new Lazy<IPComparer>(() =>
        {
            return new IPComparer();
        }, System.Threading.LazyThreadSafetyMode.ExecutionAndPublication);

        public static IPComparer Default { get { return _default.Value; } }

        public int Compare(IPAddress x, IPAddress y)
        {
            if (x.AddressFamily != y.AddressFamily)
                return (int)x.AddressFamily > (int)y.AddressFamily ? 1 : -1;

            var returnVal = 0;
            var b1 = x.GetAddressBytes();
            var b2 = y.GetAddressBytes();
 
            for (int i = 0, j = b1.Length; i < j; i++)
            {
                if (b1[i] < b2[i])
                {
                    returnVal = -1;
                    break;
                }
                else if (b1[i] > b2[i])
                {
                    returnVal = 1;
                    break;
                }
            }

            return returnVal;
        }
    }
    
    public static class Interfaces
    {
        private static readonly Lazy<SortedSet<IPAddress>> _localIPs = new Lazy<SortedSet<IPAddress>>(() =>
        {
            return new SortedSet<IPAddress>(NetworkInterface.GetAllNetworkInterfaces()
                .Where(x => x.OperationalStatus == OperationalStatus.Up)
                .SelectMany(x => x.GetIPProperties().UnicastAddresses)
                .Select(x => x.Address),
            IPComparer.Default);
        }, System.Threading.LazyThreadSafetyMode.ExecutionAndPublication);

        public static ISet<IPAddress> LocalIPs { get { return _localIPs.Value; } }
    }

    public static class IPAddressExtensions
    {
        private static readonly Lazy<IPAddress> PrivateAddressBlockA = new Lazy<IPAddress>(() => { return IPAddress.Parse("10.0.0.0"); }, System.Threading.LazyThreadSafetyMode.ExecutionAndPublication);
        private static readonly Lazy<IPAddress> PrivateAddressBlockB = new Lazy<IPAddress>(() => { return IPAddress.Parse("172.16.0.0"); }, System.Threading.LazyThreadSafetyMode.ExecutionAndPublication);
        private static readonly Lazy<IPAddress> PrivateAddressBlockC = new Lazy<IPAddress>(() => { return IPAddress.Parse("192.168.0.0"); }, System.Threading.LazyThreadSafetyMode.ExecutionAndPublication);
        private static readonly Lazy<IPAddress> LoopbackAddressBlock = new Lazy<IPAddress>(() => { return IPAddress.Parse("127.0.0.0"); }, System.Threading.LazyThreadSafetyMode.ExecutionAndPublication);

        // Bytebasierter Praefix-Vergleich (IPv4 und IPv6). Die alte Variante las bei IPv6 nur
        // die ersten 4 Bytes und lieferte bei 0 Bit Praefix (Shift um 32) ein falsches Ergebnis.
        public static bool IsInRange(this IPAddress ipAddress, IPAddress cidrAddress, int netmaskBitCount)
        {
            if (ipAddress.AddressFamily != cidrAddress.AddressFamily)
                return false;

            var ipBytes = ipAddress.GetAddressBytes();
            var cidrBytes = cidrAddress.GetAddressBytes();
            if (netmaskBitCount < 0 || netmaskBitCount > ipBytes.Length * 8)
                return false;

            var fullBytes = netmaskBitCount / 8;
            var remainingBits = netmaskBitCount % 8;

            for (var i = 0; i < fullBytes; i++)
            {
                if (ipBytes[i] != cidrBytes[i])
                    return false;
            }

            if (remainingBits > 0)
            {
                var mask = (byte)(0xFF << (8 - remainingBits));
                if ((ipBytes[fullBytes] & mask) != (cidrBytes[fullBytes] & mask))
                    return false;
            }

            return true;
        }

        public static bool IsInPrivateRange(this IPAddress ipAddress)
        {
            return ipAddress.IsInRange(PrivateAddressBlockA.Value, 8) ||
                ipAddress.IsInRange(PrivateAddressBlockB.Value, 12) ||
                ipAddress.IsInRange(PrivateAddressBlockC.Value, 16);
        }

        public static bool IsPublicIP(this IPAddress ipAddress)
        {
            return !(ipAddress.IsInPrivateRange() ||
                IPAddress.IsLoopback(ipAddress) ||
                ipAddress.IsInRange(LoopbackAddressBlock.Value, 8));
        }

        public static bool IsLocalIP(this IPAddress ipAddress)
        {
            return Interfaces.LocalIPs.Contains(ipAddress);
        }
    }

    public class Events
    {
        private const int DefaultTimeframe = 15;
        private const int DefaultThreshold = 25;
        private const int DefaultBatchSize = 100;

        private readonly SortedSet<IPAddress> _sortedIPs;
        public int Count { get { return _sortedIPs.Count; } }
        public string[] IPs { get { return Count > 0 ? _sortedIPs.Select(x => x.ToString()).ToArray() : new string[0]; } }
        
        public Events() : this(DefaultTimeframe, DefaultThreshold)
        {
        }

        public Events(int Timeframe, int Threshold)
        {
            var logSource = "Security";
            var eventId = "4625";
            var endTime = DateTime.UtcNow;

            var query = string.Format(@"*[System/EventID={0}] and *[System[TimeCreated[@SystemTime >= '{1}']]] and *[System[TimeCreated[@SystemTime <= '{2}']]]",
                eventId,
                endTime.AddMinutes(-Math.Abs(Timeframe)).ToString("o"),
                endTime.ToString("o"));
                
            var eventList = new List<string>();
            string readError = null;
            var elQuery = new EventLogQuery(logSource, PathType.LogName, query)
            {
                ReverseDirection = true
            };
            using (var loginEventPropertySelector = new EventLogPropertySelector(new[]
            {
                //"Event/EventData/Data[@Name='TargetUserSid']",
                //"Event/EventData/Data[@Name='TargetLogonId']",
                //"Event/EventData/Data[@Name='LogonType']",
                //"Event/EventData/Data[@Name='ElevatedToken']",
                //"Event/EventData/Data[@Name='WorkstationName']",
                //"Event/EventData/Data[@Name='ProcessName']",
                "Event/EventData/Data[@Name='IpAddress']",
                //"Event/EventData/Data[@Name='IpPort']"
            }))
            using (var elReader = new EventLogReader(elQuery)
            {
                BatchSize = DefaultBatchSize
            })
            {
                EventRecord eventInstance = null;
                try
                {
                    while ((eventInstance = elReader.ReadEvent()) != null)
                    {
                        using (eventInstance)
                        {
                            var properties = ((EventLogRecord)eventInstance).GetPropertyValues(loginEventPropertySelector);
                            var ip = properties[0] as string;
                            if (!string.IsNullOrWhiteSpace(ip) && ip != "-")
                                eventList.Add(ip);
                        }
                    }
                }
                catch (Exception ex)
                {
                    // No silent error swallowing. Continue working with the portion already read, but record the error in the application log.
                    readError = ex.GetType().Name + ": " + ex.Message;
                }
            }

            if (readError != null)
                Log.Warning("[BlockRDPBruteForce] Error reading the security log (Timeframe " + Timeframe + " min). Script continued using intermediate results. " + readError);

            _sortedIPs = BuildSet(eventList, Threshold);
        }

        // Normalizes entries: IPv4-mapped IPv6->IPv4, removes zone IDs, discards invalid values.
        // Counts occurrences per address, and retains only those addresses above the threshold.
        public static SortedSet<IPAddress> BuildSet(IEnumerable<string> rawAddresses, int threshold)
        {
            return new SortedSet<IPAddress>(rawAddresses
                    .Select(x => Normalize(x))
                    .Where(x => x != null)
                    .GroupBy(x => x.ToString())
                    .Where(x => x.Count() > threshold)
                    .Select(x => x.First()),
            IPComparer.Default);
        }

        public static IPAddress Normalize(string text)
        {
            IPAddress ip;
            if (string.IsNullOrWhiteSpace(text) || !IPAddress.TryParse(text.Trim(), out ip))
                return null;

            var bytes = ip.GetAddressBytes();
            if (bytes.Length == 16)
            {
                var mapped = bytes[10] == 0xFF && bytes[11] == 0xFF;
                for (var i = 0; mapped && i < 10; i++)
                    mapped = bytes[i] == 0;

                if (mapped)
                    ip = new IPAddress(new[] { bytes[12], bytes[13], bytes[14], bytes[15] });
                else
                    ip = new IPAddress(bytes);
            }

            if (IPAddress.IsLoopback(ip) || ip.Equals(IPAddress.Any) || ip.Equals(IPAddress.IPv6Any))
                return null;

            return ip;
        }

        // Reads saved entries from the firewall rule (e.g., "1.2.3.4/255.255.255.255,5.6.7.8"). Non-IP entries
        // like "*" or "LocalSubnet" are ignored.
        public static IPAddress[] ParseAddressList(string list)
        {
            if (string.IsNullOrWhiteSpace(list))
                return new IPAddress[0];

            return list
                .Split(new[] { ',' })
                .Select(x => x.Trim().Split(new[] { '/' }, 2)[0])
                .SelectMany(x => x.Split(new[] { '-' }))
                .Select(x => Normalize(x))
                .Where(x => x != null)
                .ToArray();
        }

        public IEnumerable<IPAddress> UnionWith(IEnumerable<IPAddress> union)
        {
            var list = union.ToList();
            _sortedIPs.UnionWith(list);
            return list;
        }

        public IEnumerable<IPAddress> UnionWith(Events union)
        {
            return UnionWith(union._sortedIPs.AsEnumerable());
        }

        public IEnumerable<IPAddress> UnionWith(IEnumerable<string> union)
        {
            return UnionWith(union.Select(x => Normalize(x)).Where(x => x != null).ToList());
        }

        public IEnumerable<IPAddress> UnionWith(string union)
        {
            return UnionWith(ParseAddressList(union));
        }

        public void ExceptWith(IEnumerable<IPAddress> except)
        {
            _sortedIPs.ExceptWith(except);
        }
    }
    
    public static class Firewall
    {
        private static readonly Lazy<dynamic> _instance = new Lazy<dynamic>(() =>
        {
            // GUID E2B3C97F-6AE1-41AC-817A-F6F92166D7DD -> CLSID Windows-Firewall-COM-Objekt ("NetFwPolicy2")
            return Activator.CreateInstance(Type.GetTypeFromCLSID(new Guid("E2B3C97F-6AE1-41AC-817A-F6F92166D7DD"), true));
        }, System.Threading.LazyThreadSafetyMode.ExecutionAndPublication);

        public static dynamic Instance { get { return _instance.Value; } }
        public static dynamic Rules { get { return Instance.Rules; } }

        // Returns the RemoteAddresses for the rule, or null if the rule does not exist. 
        // This prevents PowerShell from having to interpret each and every exception as "rule missing."
        public static string GetRemoteAddresses(string ruleName)
        {
            dynamic rule = FindRule(ruleName);
            if (rule == null)
                return null;

            string addresses = rule.RemoteAddresses;
            return addresses ?? "";
        }

        public static void SetRemoteAddresses(string ruleName, string remoteAddresses)
        {
            dynamic rule = FindRule(ruleName);
            if (rule == null)
                throw new InvalidOperationException("Firewall-Regel nicht gefunden: " + ruleName);

            rule.RemoteAddresses = remoteAddresses;
        }

        private static dynamic FindRule(string ruleName)
        {
            try
            {
                return Rules.Item(ruleName);
            }
            catch (FileNotFoundException)
            {
                return null;
            }
            catch (COMException)
            {
                // The HRESULT returned for "not found" varies depending on the Windows version (thanks for that).
                // Verifing via the rule list, just to be safe.
                foreach (dynamic rule in (System.Collections.IEnumerable)Rules)
                {
                    string name = rule.Name;
                    if (string.Equals(name, ruleName, StringComparison.OrdinalIgnoreCase))
                        return rule;
                }
                return null;
            }
        }
    }   

    public static class Log
    {
        public static void Information(string message) { Write(message, EventLogEntryType.Information); }
        public static void Warning(string message) { Write(message, EventLogEntryType.Warning); }
        public static void Error(string message) { Write(message, EventLogEntryType.Error); }

        private static void Write(string message, EventLogEntryType type)
        {
            try
            {
                if (message != null && message.Length > 30000)
                    message = message.Substring(0, 30000) + "...";

                using (var eventLog = new EventLog("Application"))
                {
                    eventLog.Source = "Application";
                    eventLog.WriteEntry(message, type, 13370, 4);
                }
            }
            catch
            {
                // Errors during logging must _not_ interrupt the actual work, so this empty catch.
            }
        }
    }

    public static class DateTimeExtensions
    {
        public static DateTime RoundToTicks(this DateTime target, long ticks) { return new DateTime((target.Ticks + ticks / 2) / ticks * ticks, target.Kind); }
        public static DateTime RoundUpToTicks(this DateTime target, long ticks) { return new DateTime((target.Ticks + ticks - 1) / ticks * ticks, target.Kind); }
        public static DateTime RoundDownToTicks(this DateTime target, long ticks) { return new DateTime(target.Ticks / ticks * ticks, target.Kind); }
        public static DateTime Round(this DateTime target, TimeSpan round) { return RoundToTicks(target, round.Ticks); }
        public static DateTime RoundUp(this DateTime target, TimeSpan round) { return RoundUpToTicks(target, round.Ticks); }
        public static DateTime RoundDown(this DateTime target, TimeSpan round) { return RoundDownToTicks(target, round.Ticks); }
        public static DateTime RoundToMinutes(this DateTime target, int minutes = 1) { return RoundToTicks(target, minutes * TimeSpan.TicksPerMinute); }
        public static DateTime RoundUpToMinutes(this DateTime target, int minutes = 1) { return RoundUpToTicks(target, minutes * TimeSpan.TicksPerMinute); }
        public static DateTime RoundDownToMinutes(this DateTime target, int minutes = 1) { return RoundDownToTicks(target, minutes * TimeSpan.TicksPerMinute); }
        public static DateTime RoundToHours(this DateTime target, int hours = 1) { return RoundToTicks(target, hours * TimeSpan.TicksPerHour); }
        public static DateTime RoundUpToHours(this DateTime target, int hours = 1) { return RoundUpToTicks(target, hours * TimeSpan.TicksPerHour); }
        public static DateTime RoundDownToHours(this DateTime target, int hours = 1) { return RoundDownToTicks(target, hours * TimeSpan.TicksPerHour); }
        public static DateTime RoundToDays(this DateTime target, int days = 1) { return RoundToTicks(target, days * TimeSpan.TicksPerDay); }
        public static DateTime RoundUpToDays(this DateTime target, int days = 1) { return RoundUpToTicks(target, days * TimeSpan.TicksPerDay); }
        public static DateTime RoundDownToDays(this DateTime target, int days = 1) { return RoundDownToTicks(target, days * TimeSpan.TicksPerDay); }
    }
"@

# If called again within the same hostedsession (like in vscode or ISE), Add-Type would fail with an "already exists" error.
if (-not ("Events" -as [type])) {
    if ($referencedAssemblies) {
        Add-Type -TypeDefinition $typeDefinition -ReferencedAssemblies $referencedAssemblies -ErrorAction Stop
    } else {
        # Windows PowerShell (5.1) .NET Framework compiler. The C# code uses "dynamic" (COM firewall API),
        # which requires an explicit reference to Microsoft.CSharp (otherwise error CS0518/Binder not defined).
        Add-Type -TypeDefinition $typeDefinition -ReferencedAssemblies @("System.Core", "Microsoft.CSharp") -ErrorAction Stop
    }
}

try {
    $run = 1
    $events = [Events]::new()

    $now = [DateTimeExtensions]::RoundToMinutes([DateTime]::Now, 15)
    if($now.Minute -eq 0) {
        $run = 2
        $events.UnionWith([Events]::new(60, 45)) | Out-Null

        $now = [DateTimeExtensions]::RoundToHours($now, 1)
        switch ($now.Hour)
        {
            {$_ -in 0, 3, 6, 9, 12, 15, 18, 21} {
                $run = 3
                $events.UnionWith([Events]::new(360, 90)) | Out-Null
            }
        }
    }

    if($events.Count -gt 0) {
        $events.ExceptWith([Interfaces]::LocalIPs)
    }

    if($events.Count -gt 0) {
        $newIps = @()
        $total = 0

        # $null = rule does not (yet) exist. Other errors (COM, permissions) result in a visible error,
        # rather than silently creating a duplicate rule.
        $currText = [Firewall]::GetRemoteAddresses($ruleName)

        if($null -eq $currText) {
            $newIps = $events.IPs
            $total = $newIps.Length
            New-NetFirewallRule -DisplayName $ruleName -Action Block -Direction Inbound -Protocol TCP -LocalPort 3389 -RemoteAddress $newIps -ErrorAction Stop | Out-Null
        } else {
            $currIps = [Events]::ParseAddressList($currText)
            $events.ExceptWith($currIps)
            $newIps = $events.IPs
            $total = $currIps.Length + $newIps.Length

            if($newIps.Length -gt 0) {
                # Leave the existing rule text unchanged and simply append the new IPs.
                # This ensures that manually added subnets/ranges and other options are preserved. If the rule
                # does not contain a valid IP (e.g., "*"), it is just replaced entirely - by the new IP(s).
                $joined = [string]::Join(",", $newIps)
                if($currIps.Length -gt 0) {
                    $joined = $currText + "," + $joined
                }
                [Firewall]::SetRemoteAddresses($ruleName, $joined)
            }
        }

        if($newIps.Length -gt 0) {
            [Log]::Information("[BlockRDPBruteForce] Total: $($total) / New: $([string]::Join(", ", $newIps))")
        }
    }
} catch {
    [Log]::Error("[BlockRDPBruteForce] Error: $($_.Exception.Message) $($_.ScriptStackTrace)")
    throw
}
