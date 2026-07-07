//! Curated MITRE ATT&CK (Enterprise) tactic + technique table — enough
//! coverage for a convincing matrix and rule/actor tagging. `TechniqueId`
//! is an index into `techniques`; the string id ("T1059.001") is display
//! data, not a key.

const std = @import("std");

pub const TechniqueId = u16;

/// The 14 Enterprise tactics, in kill-chain (matrix column) order.
pub const Tactic = enum(u8) {
    reconnaissance,
    resource_development,
    initial_access,
    execution,
    persistence,
    privilege_escalation,
    defense_evasion,
    credential_access,
    discovery,
    lateral_movement,
    collection,
    command_and_control,
    exfiltration,
    impact,

    pub fn label(self: Tactic) [:0]const u8 {
        return switch (self) {
            .reconnaissance => "Recon",
            .resource_development => "Resource Dev",
            .initial_access => "Initial Access",
            .execution => "Execution",
            .persistence => "Persistence",
            .privilege_escalation => "Priv Esc",
            .defense_evasion => "Defense Evasion",
            .credential_access => "Cred Access",
            .discovery => "Discovery",
            .lateral_movement => "Lateral Move",
            .collection => "Collection",
            .command_and_control => "C2",
            .exfiltration => "Exfiltration",
            .impact => "Impact",
        };
    }
};

pub const tactic_count = @typeInfo(Tactic).@"enum".fields.len;

pub const Technique = struct {
    id: [:0]const u8,
    name: [:0]const u8,
    tactic: Tactic,
};

pub const techniques = [_]Technique{
    // Reconnaissance / Resource Development
    .{ .id = "T1595", .name = "Active Scanning", .tactic = .reconnaissance },
    .{ .id = "T1598", .name = "Phishing for Information", .tactic = .reconnaissance },
    .{ .id = "T1583.001", .name = "Acquire Infra: Domains", .tactic = .resource_development },
    .{ .id = "T1588.002", .name = "Obtain Capabilities: Tool", .tactic = .resource_development },
    // Initial Access
    .{ .id = "T1566.001", .name = "Phishing: Attachment", .tactic = .initial_access },
    .{ .id = "T1566.002", .name = "Phishing: Link", .tactic = .initial_access },
    .{ .id = "T1190", .name = "Exploit Public-Facing App", .tactic = .initial_access },
    .{ .id = "T1078", .name = "Valid Accounts", .tactic = .initial_access },
    .{ .id = "T1133", .name = "External Remote Services", .tactic = .initial_access },
    // Execution
    .{ .id = "T1059.001", .name = "PowerShell", .tactic = .execution },
    .{ .id = "T1059.003", .name = "Windows Command Shell", .tactic = .execution },
    .{ .id = "T1059.005", .name = "Visual Basic", .tactic = .execution },
    .{ .id = "T1059.007", .name = "JavaScript", .tactic = .execution },
    .{ .id = "T1204.002", .name = "User Execution: File", .tactic = .execution },
    .{ .id = "T1047", .name = "WMI", .tactic = .execution },
    .{ .id = "T1053.005", .name = "Scheduled Task", .tactic = .execution },
    // Persistence
    .{ .id = "T1547.001", .name = "Registry Run Keys", .tactic = .persistence },
    .{ .id = "T1543.003", .name = "Windows Service", .tactic = .persistence },
    .{ .id = "T1136.001", .name = "Create Account: Local", .tactic = .persistence },
    .{ .id = "T1574.002", .name = "DLL Side-Loading", .tactic = .persistence },
    .{ .id = "T1505.003", .name = "Web Shell", .tactic = .persistence },
    // Privilege Escalation
    .{ .id = "T1548.002", .name = "Bypass UAC", .tactic = .privilege_escalation },
    .{ .id = "T1055", .name = "Process Injection", .tactic = .privilege_escalation },
    .{ .id = "T1068", .name = "Exploit for Priv Esc", .tactic = .privilege_escalation },
    .{ .id = "T1134", .name = "Access Token Manipulation", .tactic = .privilege_escalation },
    // Defense Evasion
    .{ .id = "T1070.004", .name = "File Deletion", .tactic = .defense_evasion },
    .{ .id = "T1070.001", .name = "Clear Event Logs", .tactic = .defense_evasion },
    .{ .id = "T1027", .name = "Obfuscated Files", .tactic = .defense_evasion },
    .{ .id = "T1218.011", .name = "Rundll32", .tactic = .defense_evasion },
    .{ .id = "T1218.005", .name = "Mshta", .tactic = .defense_evasion },
    .{ .id = "T1562.001", .name = "Disable Security Tools", .tactic = .defense_evasion },
    .{ .id = "T1112", .name = "Modify Registry", .tactic = .defense_evasion },
    // Credential Access
    .{ .id = "T1003.001", .name = "LSASS Memory", .tactic = .credential_access },
    .{ .id = "T1110.003", .name = "Password Spraying", .tactic = .credential_access },
    .{ .id = "T1555.003", .name = "Creds from Browsers", .tactic = .credential_access },
    .{ .id = "T1558.003", .name = "Kerberoasting", .tactic = .credential_access },
    .{ .id = "T1552.001", .name = "Creds in Files", .tactic = .credential_access },
    // Discovery
    .{ .id = "T1082", .name = "System Info Discovery", .tactic = .discovery },
    .{ .id = "T1087.002", .name = "Domain Account Discovery", .tactic = .discovery },
    .{ .id = "T1018", .name = "Remote System Discovery", .tactic = .discovery },
    .{ .id = "T1057", .name = "Process Discovery", .tactic = .discovery },
    .{ .id = "T1046", .name = "Network Service Discovery", .tactic = .discovery },
    .{ .id = "T1069.002", .name = "Domain Groups Discovery", .tactic = .discovery },
    // Lateral Movement
    .{ .id = "T1021.001", .name = "RDP", .tactic = .lateral_movement },
    .{ .id = "T1021.002", .name = "SMB/Admin Shares", .tactic = .lateral_movement },
    .{ .id = "T1021.006", .name = "WinRM", .tactic = .lateral_movement },
    .{ .id = "T1570", .name = "Lateral Tool Transfer", .tactic = .lateral_movement },
    .{ .id = "T1550.002", .name = "Pass the Hash", .tactic = .lateral_movement },
    // Collection
    .{ .id = "T1560.001", .name = "Archive via Utility", .tactic = .collection },
    .{ .id = "T1005", .name = "Data from Local System", .tactic = .collection },
    .{ .id = "T1114.002", .name = "Remote Email Collection", .tactic = .collection },
    .{ .id = "T1113", .name = "Screen Capture", .tactic = .collection },
    // Command and Control
    .{ .id = "T1071.001", .name = "Web Protocols (C2)", .tactic = .command_and_control },
    .{ .id = "T1071.004", .name = "DNS (C2)", .tactic = .command_and_control },
    .{ .id = "T1573.002", .name = "Asymmetric Crypto C2", .tactic = .command_and_control },
    .{ .id = "T1090.003", .name = "Multi-hop Proxy", .tactic = .command_and_control },
    .{ .id = "T1105", .name = "Ingress Tool Transfer", .tactic = .command_and_control },
    // Exfiltration
    .{ .id = "T1041", .name = "Exfil Over C2 Channel", .tactic = .exfiltration },
    .{ .id = "T1567.002", .name = "Exfil to Cloud Storage", .tactic = .exfiltration },
    .{ .id = "T1048.003", .name = "Exfil Over Alt Protocol", .tactic = .exfiltration },
    // Impact
    .{ .id = "T1486", .name = "Data Encrypted (Ransom)", .tactic = .impact },
    .{ .id = "T1490", .name = "Inhibit System Recovery", .tactic = .impact },
    .{ .id = "T1489", .name = "Service Stop", .tactic = .impact },
    .{ .id = "T1529", .name = "System Shutdown/Reboot", .tactic = .impact },
};

pub const technique_count: TechniqueId = @intCast(techniques.len);

pub fn get(id: TechniqueId) *const Technique {
    return &techniques[@min(id, techniques.len - 1)];
}

/// All technique indices belonging to `tactic`, comptime-counted.
pub fn tacticTechniqueCount(tactic: Tactic) usize {
    var n: usize = 0;
    for (techniques) |t| {
        if (t.tactic == tactic) n += 1;
    }
    return n;
}

test "technique table sane" {
    try std.testing.expect(techniques.len >= 60);
    // Every tactic has at least one technique (matrix has no empty column).
    inline for (@typeInfo(Tactic).@"enum".fields) |f| {
        const tac: Tactic = @enumFromInt(f.value);
        var n: usize = 0;
        for (techniques) |t| {
            if (t.tactic == tac) n += 1;
        }
        try std.testing.expect(n >= 1);
    }
}
