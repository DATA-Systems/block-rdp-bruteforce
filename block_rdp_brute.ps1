#########################
# DATA-Systems (c) 2022 #
#    v1.0 18.05.2022    #
#    v1.1 03.06.2022    #
#########################

#powershell.exe -NoProfile -NoLogo -NonInteractive -ExecutionPolicy Bypass -File "C:\Program Files\scripts\block_rdp_brute.ps1"

$providerOptions = New-Object "System.Collections.Generic.Dictionary[string, string]"
$providerOptions.Add("CompilerVersion", "v4.0");
$CodeDomProvider = New-Object "Microsoft.CSharp.CSharpCodeProvider" $providerOptions

$CompilerParameters = New-Object "System.CodeDom.Compiler.CompilerParameters"
$CompilerParameters.CompilerOptions = "/optimize /debug-"
$CompilerParameters.GenerateInMemory = $true
$CompilerParameters.GenerateExecutable = $false
$CompilerParameters.IncludeDebugInformation = $false
$CompilerParameters.ReferencedAssemblies.Add("System.dll") | Out-Null
$CompilerParameters.ReferencedAssemblies.Add("System.Core.dll") | Out-Null
$CompilerParameters.ReferencedAssemblies.Add("System.Linq.dll") | Out-Null
$CompilerParameters.ReferencedAssemblies.Add("Microsoft.CSharp.dll") | Out-Null

#Add-Type -ReferencedAssemblies "System", "System.Linq", "Microsoft.CSharp" -TypeDefinition @"
Add-Type -CodeDomProvider $CodeDomProvider -CompilerParameters $CompilerParameters -TypeDefinition @"
    using System;
    using System.Collections.Generic;
    using System.Diagnostics;
    using System.Diagnostics.Eventing.Reader;
    using System.IO;
    using System.Linq;
    using System.Net;
    using System.Net.NetworkInformation;

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

        public static bool IsInRange(this IPAddress ipAddress, IPAddress cidrAddress, int netmaskBitCount)
        {
            if (ipAddress.AddressFamily != cidrAddress.AddressFamily)
                return false;

            var ipAddressBytes = BitConverter.ToInt32(ipAddress.GetAddressBytes(), 0);
            var cidrAddressBytes = BitConverter.ToInt32(cidrAddress.GetAddressBytes(), 0);
            var cidrMaskBytes = IPAddress.HostToNetworkOrder(-1 << (32 - netmaskBitCount));

            return (ipAddressBytes & cidrMaskBytes) == (cidrAddressBytes & cidrMaskBytes);
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
        public string[] IPs { get { return Count > 0 ? _sortedIPs.Select(x => x.ToString()).ToArray() : Array.Empty<string>(); } }
        
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
                var eventInstance = elReader.ReadEvent();
                try
                {
                    for (; eventInstance != null; eventInstance = elReader.ReadEvent())
                        using(eventInstance)
                        {
                            var properties = ((EventLogRecord)eventInstance).GetPropertyValues(loginEventPropertySelector);
                            var ip = (string)properties[0];
                            if(!string.IsNullOrWhiteSpace(ip) && ip != "-")
                                eventList.Add(ip); //eventList.Add((string)eventInstance.Properties[19].Value);
                        }
                }
                catch
                {
                }
                finally
                {
                    if (eventInstance != null)
                        eventInstance.Dispose();
                }
            }

            _sortedIPs = new SortedSet<IPAddress>(eventList
                    .GroupBy(x => x, StringComparer.OrdinalIgnoreCase)
                    .Where(x => x.Count() > Threshold)
                    .Select(x => IPAddress.Parse(x.Key)),
            IPComparer.Default);
        }

        public IEnumerable<IPAddress> UnionWith(IEnumerable<IPAddress> union)
        {
            _sortedIPs.UnionWith(union);
            return union;
        }

        public IEnumerable<IPAddress> UnionWith(Events union)
        {
            return UnionWith(union._sortedIPs.AsEnumerable());
        }

        public IEnumerable<IPAddress> UnionWith(IEnumerable<string> union)
        {
            return UnionWith(union.Select(x => IPAddress.Parse(x)));
        }

        public IEnumerable<IPAddress> UnionWith(string union)
        {
            return UnionWith(union
                .Split(new[] { ',' })
                .Select(x => x.Split(new[] { '/' }, 2)[0])
                .SelectMany(x => x.Split(new[] { '-' }))
                .Distinct(StringComparer.OrdinalIgnoreCase));
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
            return Activator.CreateInstance(Type.GetTypeFromCLSID(new Guid("E2B3C97F-6AE1-41AC-817A-F6F92166D7DD"), true));
        }, System.Threading.LazyThreadSafetyMode.ExecutionAndPublication);

        public static dynamic Instance { get { return _instance.Value; } }
        public static dynamic Rules { get { return Instance.Rules; } }
    }   

    public static class Log
    {
        public static void Information(string message)
        {
            using (var eventLog = new EventLog("Application"))
            {
                eventLog.Source = "Application";
                eventLog.WriteEntry(message, EventLogEntryType.Information, 1337, 4);
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

$run = 1
$events = New-Object "Events"

$now = [DateTimeExtensions]::RoundToMinutes([DateTime]::Now, 15)
if($now.Minute -eq 0) {
    $run = 2
    $events.UnionWith((New-Object "Events" 60, 45)) | Out-Null

    $now = [DateTimeExtensions]::RoundToHours($now, 1)
    switch ($now.Hour)
    {
        {$_ -in 0, 3, 6, 9, 12, 15, 18, 21} {
            $run = 3
            $events.UnionWith((New-Object "Events" 360, 90)) | Out-Null 
        }
    }
}

if($events.Count -gt 0) {
    $events.ExceptWith([Interfaces]::LocalIPs)
    if($events.Count -gt 0) {
        try {
            $rule = [Firewall]::Rules.Item("BlockRDPBruteForce")
            $currIps = $events.UnionWith($rule.RemoteAddresses)
            $total = $events.Count
            $newIps = $events.IPs
            $events.ExceptWith($currIps)
            if($events.Count -gt 0) {
                $rule.RemoteAddresses = [string]::Join(",", $newIps)
            }
            $newIps = $events.IPs
        } catch {
            $total = $events.Count
            $newIps = $events.IPs
            New-NetFirewallRule -DisplayName "BlockRDPBruteForce" -Action Block -Direction Inbound -Protocol TCP -LocalPort 3389 -RemoteAddress $newIps | Out-Null
        } finally {
            if($newIps.Length -gt 0) {
                [Log]::Information("[BlockRDPBruteForce] Total: $($total) / New: $([string]::Join(", ", $newIps))")
            }
        }
    }
}