//! `build-catalog discover`: finds popular GitHub projects that publish
//! ready-made downloads, and writes them as source lines
//! (catalog/auto-sources.txt) for the builder to try.
//!
//!   build-catalog discover --out catalog/auto-sources.txt
//!                          [--sources catalog/sources.txt] [--min-stars 500]
//!                          [--max-wait-min 50]
//!
//! It runs GraphQL repository searches, one language at a time, over star
//! ranges small enough that each search stays under GitHub's 1,000-result cap.
//! A repository is kept when it
//!   * has at least `--min-stars` stars, is not a fork, mirror, template,
//!     archived or disabled, and was pushed to in the last two years,
//!   * is at least 180 days old (stars on a new repository are cheap to fake),
//!   * has a latest release that is not a pre-release, with at least two files.
//! Whether those files fit abv0's platforms is the builder's job: it picks the
//! assets, pins their SHA-256 and runs the malware scan, as for any source.
//!
//! Each query asks for 100 repositories and only the size of their asset list,
//! so a full run costs a few hundred GraphQL points.

const std = @import("std");
const deps = @import("catalog_deps");

const ghrelease = deps.ghrelease;
const safepath = deps.safepath;
const Allocator = std.mem.Allocator;

/// Languages whose projects usually ship compiled programs.
pub const languages = [_][]const u8{
    "Go",      "Rust", "C", "C++",  "Zig",     "Nim",    "Haskell", "OCaml",
    "Crystal", "D",    "V", "Odin", "Fortran", "Pascal", "Ada",     "Hare",
};

/// Where each language's star ranges start; a range with more than 1,000
/// results is split further.
const star_cuts = [_]u32{ 500, 600, 700, 850, 1000, 1300, 1700, 2300, 3200, 5000, 8000, 15000, 40000 };

pub const Range = struct { lo: u32, hi: ?u32 };

pub const Repo = struct {
    owner: []const u8,
    name: []const u8,
    stars: u32,
};

pub const Page = struct {
    count: u32,
    has_next: bool,
    cursor: ?[]const u8,
    repos: []Repo,
};

/// The search string for one language and star range. `since` is the
/// `pushed:>` date (YYYY-MM-DD).
pub fn searchString(a: Allocator, lang: []const u8, r: Range, since: []const u8) ![]u8 {
    const stars = if (r.hi) |hi|
        try std.fmt.allocPrint(a, "{d}..{d}", .{ r.lo, hi })
    else
        try std.fmt.allocPrint(a, ">={d}", .{r.lo});
    // Quoted, so C++ and names with spaces stay one value.
    return std.fmt.allocPrint(a, "language:\"{s}\" stars:{s} fork:false archived:false pushed:>{s} sort:stars", .{ lang, stars, since });
}

fn writeGqlString(w: anytype, s: []const u8) !void {
    try w.writeByte('"');
    for (s) |c| switch (c) {
        '"' => try w.writeAll("\\\""),
        '\\' => try w.writeAll("\\\\"),
        0...0x1f, 0x7f => try w.print("\\u{x:0>4}", .{c}),
        else => try w.writeByte(c),
    };
    try w.writeByte('"');
}

/// The GraphQL document for one page of a search.
pub fn buildQuery(a: Allocator, search: []const u8, after: ?[]const u8) ![]u8 {
    var out = std.ArrayList(u8).init(a);
    const w = out.writer();
    try w.writeAll("query{search(type:REPOSITORY,first:100,query:");
    try writeGqlString(w, search);
    if (after) |c| {
        try w.writeAll(",after:");
        try writeGqlString(w, c);
    }
    try w.writeAll("){repositoryCount pageInfo{hasNextPage endCursor} nodes{...on Repository{");
    try w.writeAll("name owner{login} stargazerCount createdAt isFork isArchived isMirror isTemplate isDisabled ");
    try w.writeAll("latestRelease{isPrerelease isDraft releaseAssets(first:1){totalCount}}}}}}");
    return out.toOwnedSlice();
}

pub fn requestBody(a: Allocator, query: []const u8) ![]u8 {
    var out = std.ArrayList(u8).init(a);
    try out.appendSlice("{\"query\":");
    try std.json.encodeJsonString(query, .{}, out.writer());
    try out.append('}');
    return out.toOwnedSlice();
}

fn field(v: std.json.Value, key: []const u8) ?std.json.Value {
    if (v != .object) return null;
    return v.object.get(key);
}

fn boolField(v: std.json.Value, key: []const u8) bool {
    const f = field(v, key) orelse return false;
    return f == .bool and f.bool;
}

fn intField(v: std.json.Value, key: []const u8) i64 {
    const f = field(v, key) orelse return 0;
    return if (f == .integer) f.integer else 0;
}

fn strField(v: std.json.Value, key: []const u8) ?[]const u8 {
    const f = field(v, key) orelse return null;
    return if (f == .string) f.string else null;
}

/// Days since the epoch for an ISO date (`2024-05-01T...`), or null.
pub fn epochDay(iso: []const u8) ?i64 {
    if (iso.len < 10 or iso[4] != '-' or iso[7] != '-') return null;
    const y = std.fmt.parseInt(i64, iso[0..4], 10) catch return null;
    const m = std.fmt.parseInt(i64, iso[5..7], 10) catch return null;
    const d = std.fmt.parseInt(i64, iso[8..10], 10) catch return null;
    if (m < 1 or m > 12 or d < 1 or d > 31) return null;
    // Days from civil (Howard Hinnant).
    const yy = if (m <= 2) y - 1 else y;
    const era = @divFloor(yy, 400);
    const yoe = yy - era * 400;
    const mp = @mod(m + 9, 12);
    const doy = @divFloor(153 * mp + 2, 5) + d - 1;
    const doe = yoe * 365 + @divFloor(yoe, 4) - @divFloor(yoe, 100) + doy;
    return era * 146097 + doe - 719468;
}

/// One search page: the total count, the cursor, and the repositories that
/// pass the filters. `today` is days since the epoch.
pub fn parsePage(a: Allocator, body: []const u8, min_stars: u32, today: i64) !Page {
    const parsed = try std.json.parseFromSliceLeaky(std.json.Value, a, body, .{});
    if (field(parsed, "errors")) |_| return error.GraphQLError;
    const data = field(parsed, "data") orelse return error.BadResponse;
    const search = field(data, "search") orelse return error.BadResponse;
    const info = field(search, "pageInfo") orelse return error.BadResponse;
    var page = Page{
        .count = @intCast(@max(intField(search, "repositoryCount"), 0)),
        .has_next = boolField(info, "hasNextPage"),
        .cursor = if (strField(info, "endCursor")) |c| try a.dupe(u8, c) else null,
        .repos = &.{},
    };
    var repos = std.ArrayList(Repo).init(a);
    const nodes = field(search, "nodes") orelse return page;
    if (nodes != .array) return page;
    for (nodes.array.items) |n| {
        if (boolField(n, "isFork") or boolField(n, "isArchived") or boolField(n, "isMirror") or
            boolField(n, "isTemplate") or boolField(n, "isDisabled")) continue;
        const stars = intField(n, "stargazerCount");
        if (stars < min_stars) continue;
        const created = epochDay(strField(n, "createdAt") orelse continue) orelse continue;
        if (today - created < 180) continue;
        const rel = field(n, "latestRelease") orelse continue;
        if (rel != .object or boolField(rel, "isPrerelease") or boolField(rel, "isDraft")) continue;
        const assets = field(rel, "releaseAssets") orelse continue;
        if (intField(assets, "totalCount") < 2) continue;
        const name = strField(n, "name") orelse continue;
        const owner = strField(field(n, "owner") orelse continue, "login") orelse continue;
        // Only names the rest of the pipeline accepts.
        const spec_text = try std.fmt.allocPrint(a, "{s}/{s}", .{ owner, name });
        const spec = ghrelease.parseSpec(spec_text) orelse continue;
        if (!std.mem.eql(u8, spec.owner, owner) or !std.mem.eql(u8, spec.repo, name)) continue;
        try repos.append(.{ .owner = try a.dupe(u8, owner), .name = try a.dupe(u8, name), .stars = @intCast(stars) });
    }
    page.repos = try repos.toOwnedSlice();
    return page;
}

/// The two halves of a range that has too many results, or null when it is
/// a single star count already.
pub fn split(r: Range) ?[2]Range {
    const hi = r.hi orelse return .{ .{ .lo = r.lo, .hi = r.lo * 2 }, .{ .lo = r.lo * 2 + 1, .hi = null } };
    if (hi <= r.lo) return null;
    const mid = r.lo + (hi - r.lo) / 2;
    return .{ .{ .lo = r.lo, .hi = mid }, .{ .lo = mid + 1, .hi = hi } };
}

/// The starting ranges for `min_stars`.
pub fn startRanges(a: Allocator, min_stars: u32) ![]Range {
    var out = std.ArrayList(Range).init(a);
    var lo = min_stars;
    for (star_cuts) |cut| {
        if (cut <= lo) continue;
        try out.append(.{ .lo = lo, .hi = cut - 1 });
        lo = cut;
    }
    try out.append(.{ .lo = lo, .hi = null });
    return out.toOwnedSlice();
}

/// A package name for `repo`: the repository name in lower case, or
/// `owner-repo` when that is taken or not a valid id. Null when neither works.
pub fn packageName(a: Allocator, repo: Repo, taken: *const std.StringHashMap(void)) !?[]const u8 {
    const plain = try std.ascii.allocLowerString(a, repo.name);
    if (safepath.isValidId(plain) and !taken.contains(plain)) return plain;
    const long = try std.fmt.allocPrint(a, "{s}-{s}", .{ repo.owner, repo.name });
    const lower = std.ascii.lowerString(long, long);
    if (safepath.isValidId(lower) and !taken.contains(lower)) return lower;
    return null;
}

fn moreStars(_: void, x: Repo, y: Repo) bool {
    if (x.stars != y.stars) return x.stars > y.stars;
    const o = std.mem.order(u8, x.owner, y.owner);
    if (o != .eq) return o == .lt;
    return std.mem.order(u8, x.name, y.name) == .lt;
}

/// The previous list: lower-cased `owner/repo` to the package name it had.
pub fn parsePrevious(a: Allocator, text: []const u8) !std.StringHashMap([]const u8) {
    var map = std.StringHashMap([]const u8).init(a);
    var lines = std.mem.splitScalar(u8, text, '\n');
    while (lines.next()) |raw| {
        const line = std.mem.trim(u8, raw, " \t\r");
        if (line.len == 0 or line[0] == '#') continue;
        var it = std.mem.tokenizeAny(u8, line, " \t");
        const name = it.next() orelse continue;
        const repo = it.next() orelse continue;
        if (!safepath.isValidId(name) or ghrelease.parseSpec(repo) == null) continue;
        try map.put(try std.ascii.allocLowerString(a, repo), try a.dupe(u8, name));
    }
    return map;
}

/// The previous list's repositories, for a search that stopped early: they
/// stay in the list (after everything found this time) so nothing drops out.
pub fn previousRepos(a: Allocator, previous: *const std.StringHashMap([]const u8), text: []const u8) ![]Repo {
    _ = previous;
    var out = std.ArrayList(Repo).init(a);
    var lines = std.mem.splitScalar(u8, text, '\n');
    while (lines.next()) |raw| {
        const line = std.mem.trim(u8, raw, " \t\r");
        if (line.len == 0 or line[0] == '#') continue;
        var it = std.mem.tokenizeAny(u8, line, " \t");
        _ = it.next() orelse continue;
        const spec = ghrelease.parseSpec(it.next() orelse continue) orelse continue;
        try out.append(.{ .owner = try a.dupe(u8, spec.owner), .name = try a.dupe(u8, spec.repo), .stars = 0 });
    }
    return out.toOwnedSlice();
}

/// The auto-sources file: most stars first, each repository once, none that
/// the hand-written sources already list (by repository or by name). A
/// repository keeps the package name it had in `previous`, so a package is
/// never renamed under the people who installed it.
pub fn render(a: Allocator, found: []Repo, hand_names: []const []const u8, hand_repos: []const []const u8, previous: *const std.StringHashMap([]const u8), generated: []const u8) ![]u8 {
    std.mem.sort(Repo, found, {}, moreStars);
    var taken = std.StringHashMap(void).init(a);
    for (hand_names) |n| try taken.put(n, {});
    var repos = std.StringHashMap(void).init(a);
    for (hand_repos) |r| try repos.put(try std.ascii.allocLowerString(a, r), {});
    // Names already given out are reserved for their repositories.
    var reserved = std.StringHashMap(void).init(a);
    for (found) |r| {
        const key = try std.ascii.allocLowerString(a, try std.fmt.allocPrint(a, "{s}/{s}", .{ r.owner, r.name }));
        if (repos.contains(key)) continue;
        if (previous.get(key)) |n| {
            if (!taken.contains(n)) try reserved.put(n, {});
        }
    }

    var lines = std.ArrayList(u8).init(a);
    var count: usize = 0;
    for (found) |r| {
        const key = try std.ascii.allocLowerString(a, try std.fmt.allocPrint(a, "{s}/{s}", .{ r.owner, r.name }));
        if (repos.contains(key)) continue;
        try repos.put(key, {});
        const kept: ?[]const u8 = if (previous.get(key)) |n| (if (!taken.contains(n)) n else null) else null;
        const name = kept orelse blk: {
            // A new repository may not take a name another one already has.
            var blocked = std.StringHashMap(void).init(a);
            var it = taken.keyIterator();
            while (it.next()) |k| try blocked.put(k.*, {});
            var rit = reserved.keyIterator();
            while (rit.next()) |k| try blocked.put(k.*, {});
            break :blk (try packageName(a, r, &blocked)) orelse continue;
        };
        try taken.put(name, {});
        try lines.writer().print("{s} {s}/{s}\n", .{ name, r.owner, r.name });
        count += 1;
    }
    var out = std.ArrayList(u8).init(a);
    try out.writer().print(
        \\# Generated by `build-catalog discover` on {s}: {d} popular GitHub projects
        \\# with release downloads. Do not edit; list a project in sources.txt to
        \\# override its line here.
        \\
    , .{ generated, count });
    try out.appendSlice(lines.items);
    return out.toOwnedSlice();
}

// ---------------------------------------------------------------------------
// Network
// ---------------------------------------------------------------------------

const graphql_url = "https://api.github.com/graphql";

const Client = struct {
    http: std.http.Client,
    token: []const u8,
    waited_s: u64 = 0,
    max_wait_s: u64,
    calls: usize = 0,
    server_errors: u64 = 0,

    /// POST one query. Rate limits are waited out while the budget lasts;
    /// a server error or a dropped connection (a pooled one goes stale during
    /// a long wait) is retried a few times on a new connection.
    fn post(self: *Client, a: Allocator, body: []const u8) ![]u8 {
        var attempt: usize = 0;
        while (true) : (attempt += 1) {
            // GitHub's secondary limits punish bursts of search queries.
            std.time.sleep(1500 * std.time.ns_per_ms);
            if (self.exchange(a, body)) |resp| return resp else |e| switch (e) {
                error.RateLimited, error.HttpError, error.OutOfMemory => return e,
                error.Retry => {
                    // After a long wait the pooled connection is likely dead.
                    self.resetPool(a);
                    continue;
                },
                else => {
                    if (attempt >= 4) return e;
                    std.debug.print("discover: {s}; retrying on a new connection\n", .{@errorName(e)});
                    self.resetPool(a);
                    std.time.sleep((attempt + 1) * 5 * std.time.ns_per_s);
                },
            }
        }
    }

    /// Drop every pooled connection; the next request opens a fresh one.
    fn resetPool(self: *Client, a: Allocator) void {
        const gpa = self.http.allocator;
        self.http.deinit();
        self.http = .{ .allocator = gpa };
        self.http.initDefaultProxies(a) catch {};
    }

    /// One request. `error.Retry` means "waited for a rate limit or a server
    /// error; send it again".
    fn exchange(self: *Client, a: Allocator, body: []const u8) ![]u8 {
        const auth = try std.fmt.allocPrint(a, "Bearer {s}", .{self.token});
        {
            var hbuf: [16 * 1024]u8 = undefined;
            var req = try self.http.open(.POST, try std.Uri.parse(graphql_url), .{
                .server_header_buffer = &hbuf,
                .headers = .{ .authorization = .{ .override = auth }, .user_agent = .{ .override = "abv0-discover" }, .content_type = .{ .override = "application/json" } },
            });
            defer req.deinit();
            req.transfer_encoding = .{ .content_length = body.len };
            try req.send();
            try req.writeAll(body);
            try req.finish();
            try req.wait();
            self.calls += 1;

            var reset: ?i64 = null;
            var retry_after: ?i64 = null;
            var remaining: ?i64 = null;
            var it = req.response.iterateHeaders();
            while (it.next()) |h| {
                if (std.ascii.eqlIgnoreCase(h.name, "x-ratelimit-reset")) reset = std.fmt.parseInt(i64, h.value, 10) catch null;
                if (std.ascii.eqlIgnoreCase(h.name, "x-ratelimit-remaining")) remaining = std.fmt.parseInt(i64, h.value, 10) catch null;
                if (std.ascii.eqlIgnoreCase(h.name, "retry-after")) retry_after = std.fmt.parseInt(i64, h.value, 10) catch null;
            }
            const resp = try req.reader().readAllAlloc(a, 16 * 1024 * 1024);
            const status = @intFromEnum(req.response.status);
            const limited = status == 403 or status == 429 or
                (status == 200 and std.mem.indexOf(u8, resp, "\"RATE_LIMITED\"") != null);
            if (status == 200 and !limited) {
                // Spend the last of the budget slowly: GitHub also limits bursts.
                if (remaining) |r| {
                    if (r < 50) std.time.sleep(2 * std.time.ns_per_s);
                }
                return resp;
            }
            if (limited) {
                const now = std.time.timestamp();
                const wait: u64 = @intCast(@max(retry_after orelse ((reset orelse now + 60) - now + 5), 5));
                if (self.waited_s + wait > self.max_wait_s) return error.RateLimited;
                std.debug.print("discover: rate limited; waiting {d} s\n", .{wait});
                std.time.sleep(wait * std.time.ns_per_s);
                self.waited_s += wait;
                return error.Retry;
            }
            if (status >= 500 and self.server_errors < 6) {
                self.server_errors += 1;
                std.time.sleep(self.server_errors * 5 * std.time.ns_per_s);
                return error.Retry;
            }
            std.debug.print("discover: HTTP {d}: {s}\n", .{ status, resp[0..@min(resp.len, 300)] });
            return error.HttpError;
        }
    }
};

fn die(comptime fmt: []const u8, args: anytype) noreturn {
    std.debug.print("discover: " ++ fmt ++ "\n", args);
    std.process.exit(2);
}

/// `build-catalog discover ...`; `args` are the words after `discover`.
pub fn main(gpa: Allocator, args: []const []const u8) !void {
    var arena_state = std.heap.ArenaAllocator.init(gpa);
    defer arena_state.deinit();
    const a = arena_state.allocator();

    var out_path: ?[]const u8 = null;
    var previous_path: ?[]const u8 = null;
    var sources_path: []const u8 = "catalog/sources.txt";
    var min_stars: u32 = 500;
    var max_wait_s: u64 = 50 * 60;
    var i: usize = 0;
    while (i < args.len) : (i += 1) {
        const arg = args[i];
        if (i + 1 >= args.len) die("{s} needs a value", .{arg});
        const v = args[i + 1];
        i += 1;
        if (std.mem.eql(u8, arg, "--out")) {
            out_path = v;
        } else if (std.mem.eql(u8, arg, "--sources")) {
            sources_path = v;
        } else if (std.mem.eql(u8, arg, "--previous")) {
            previous_path = v;
        } else if (std.mem.eql(u8, arg, "--min-stars")) {
            min_stars = std.fmt.parseInt(u32, v, 10) catch die("--min-stars wants a number", .{});
        } else if (std.mem.eql(u8, arg, "--max-wait-min")) {
            max_wait_s = (std.fmt.parseInt(u64, v, 10) catch die("--max-wait-min wants a number", .{})) *| 60;
        } else die("unknown option '{s}'", .{arg});
    }
    const out = out_path orelse die("--out is required", .{});
    // The last list keeps package names stable; by default the file being replaced.
    const prev_text: []const u8 = std.fs.cwd().readFileAlloc(a, previous_path orelse out, 16 * 1024 * 1024) catch "";
    const previous = try parsePrevious(a, prev_text);
    const token = std.process.getEnvVarOwned(a, "GITHUB_TOKEN") catch die("GITHUB_TOKEN must be set (GraphQL search needs a token)", .{});

    // What is written by hand already.
    var hand_names = std.ArrayList([]const u8).init(a);
    var hand_repos = std.ArrayList([]const u8).init(a);
    const text = std.fs.cwd().readFileAlloc(a, sources_path, 8 * 1024 * 1024) catch die("cannot read {s}", .{sources_path});
    var lines = std.mem.splitScalar(u8, text, '\n');
    while (lines.next()) |raw| {
        const line = std.mem.trim(u8, raw, " \t\r");
        if (line.len == 0 or line[0] == '#') continue;
        var it = std.mem.tokenizeAny(u8, line, " \t");
        const n = it.next() orelse continue;
        const r = it.next() orelse continue;
        try hand_names.append(n);
        try hand_repos.append(r);
    }

    const now = std.time.timestamp();
    const today = @divFloor(now, 86400);
    var since_buf: [32]u8 = undefined;
    const since = civilDate(&since_buf, today - 730);
    var date_buf: [32]u8 = undefined;
    const generated = civilDate(&date_buf, today);

    var client = Client{ .http = .{ .allocator = gpa }, .token = token, .max_wait_s = max_wait_s };
    defer client.http.deinit();
    client.http.initDefaultProxies(a) catch {};

    var found = std.ArrayList(Repo).init(a);
    var stopped = false;
    outer: for (languages) |lang| {
        var stack = std.ArrayList(Range).init(a);
        const starts = try startRanges(a, min_stars);
        var k = starts.len;
        while (k > 0) {
            k -= 1;
            try stack.append(starts[k]);
        }
        while (stack.popOrNull()) |range| {
            const search = try searchString(a, lang, range, since);
            var cursor: ?[]const u8 = null;
            var first = true;
            while (true) {
                const body = try requestBody(a, try buildQuery(a, search, cursor));
                const resp = client.post(a, body) catch |e| {
                    std.debug.print("discover: {s} stopped the search at {s} ({s})\n", .{ @errorName(e), lang, search });
                    stopped = true;
                    break :outer;
                };
                const page = parsePage(a, resp, min_stars, today) catch |e| {
                    std.debug.print("discover: unreadable answer for {s}: {s}\n", .{ search, @errorName(e) });
                    break;
                };
                if (first) std.debug.print("discover: {s} {d}..{?d}: {d} repositories\n", .{ lang, range.lo, range.hi, page.count });
                if (first and page.count > 1000) {
                    if (split(range)) |halves| {
                        try stack.append(halves[1]);
                        try stack.append(halves[0]);
                        break;
                    }
                }
                first = false;
                try found.appendSlice(page.repos);
                if (!page.has_next or page.cursor == null) break;
                cursor = page.cursor;
            }
        }
        std.debug.print("discover: {s}: {d} candidates so far ({d} queries)\n", .{ lang, found.items.len, client.calls });
    }

    // A search that stopped early keeps the last list's projects as well
    // (after the ones found now), so nothing drops out of the catalog because
    // of a rate limit; the next run picks up where this one could not.
    if (stopped) try found.appendSlice(try previousRepos(a, &previous, prev_text));
    const rendered = try render(a, found.items, hand_names.items, hand_repos.items, &previous, generated);
    try std.fs.cwd().writeFile(.{ .sub_path = out, .data = rendered });
    std.debug.print("discover: wrote {s} ({d} queries, {d} s waiting for rate limits){s}\n", .{
        out, client.calls, client.waited_s, if (stopped) "; the search stopped early, so last week's list was kept too" else "",
    });
    if (stopped) std.process.exit(1);
}

/// YYYY-MM-DD for days since the epoch.
pub fn civilDate(buf: *[32]u8, day: i64) []const u8 {
    const es = std.time.epoch.EpochSeconds{ .secs = @intCast(day * 86400) };
    const yd = es.getEpochDay().calculateYearDay();
    const md = yd.calculateMonthDay();
    return std.fmt.bufPrint(buf, "{d:0>4}-{d:0>2}-{d:0>2}", .{ yd.year, md.month.numeric(), md.day_index + 1 }) catch unreachable;
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

const testing = std.testing;

test "epochDay and civilDate agree" {
    try testing.expectEqual(@as(?i64, 0), epochDay("1970-01-01T00:00:00Z"));
    try testing.expectEqual(@as(?i64, 19723), epochDay("2024-01-01"));
    var buf: [32]u8 = undefined;
    try testing.expectEqualStrings("2024-01-01", civilDate(&buf, 19723));
    try testing.expect(epochDay("nope") == null);
}

test "searchString and buildQuery quote what they must" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const s = try searchString(a, "C++", .{ .lo = 500, .hi = 599 }, "2024-10-24");
    try testing.expectEqualStrings("language:\"C++\" stars:500..599 fork:false archived:false pushed:>2024-10-24 sort:stars", s);
    const open = try searchString(a, "Go", .{ .lo = 40000, .hi = null }, "2024-10-24");
    try testing.expect(std.mem.indexOf(u8, open, "stars:>=40000") != null);
    const q = try buildQuery(a, s, "Y3Vyc29y");
    try testing.expect(std.mem.indexOf(u8, q, "query:\"language:\\\"C++\\\" stars") != null);
    try testing.expect(std.mem.indexOf(u8, q, "after:\"Y3Vyc29y\"") != null);
}

test "ranges start at min_stars and split in halves" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const r = try startRanges(arena.allocator(), 500);
    try testing.expectEqual(@as(u32, 500), r[0].lo);
    try testing.expectEqual(@as(?u32, 599), r[0].hi);
    try testing.expect(r[r.len - 1].hi == null);
    const h = split(.{ .lo = 500, .hi = 599 }).?;
    try testing.expectEqual(@as(?u32, 549), h[0].hi);
    try testing.expectEqual(@as(u32, 550), h[1].lo);
    try testing.expect(split(.{ .lo = 700, .hi = 700 }) == null);
    const open = split(.{ .lo = 40000, .hi = null }).?;
    try testing.expect(open[1].hi == null);
}

test "parsePage keeps only real, released, established projects" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const body =
        \\{"data":{"search":{"repositoryCount":1234,"pageInfo":{"hasNextPage":true,"endCursor":"abc"},"nodes":[
        \\{"name":"good","owner":{"login":"o"},"stargazerCount":900,"createdAt":"2020-01-01T00:00:00Z","isFork":false,"isArchived":false,"isMirror":false,"isTemplate":false,"isDisabled":false,"latestRelease":{"isPrerelease":false,"isDraft":false,"releaseAssets":{"totalCount":6}}},
        \\{"name":"fork","owner":{"login":"o"},"stargazerCount":900,"createdAt":"2020-01-01T00:00:00Z","isFork":true,"latestRelease":{"isPrerelease":false,"releaseAssets":{"totalCount":6}}},
        \\{"name":"young","owner":{"login":"o"},"stargazerCount":900,"createdAt":"2026-10-01T00:00:00Z","latestRelease":{"isPrerelease":false,"releaseAssets":{"totalCount":6}}},
        \\{"name":"norelease","owner":{"login":"o"},"stargazerCount":900,"createdAt":"2020-01-01T00:00:00Z","latestRelease":null},
        \\{"name":"sourceonly","owner":{"login":"o"},"stargazerCount":900,"createdAt":"2020-01-01T00:00:00Z","latestRelease":{"isPrerelease":false,"releaseAssets":{"totalCount":0}}},
        \\{"name":"beta","owner":{"login":"o"},"stargazerCount":900,"createdAt":"2020-01-01T00:00:00Z","latestRelease":{"isPrerelease":true,"releaseAssets":{"totalCount":6}}},
        \\{"name":"few","owner":{"login":"o"},"stargazerCount":10,"createdAt":"2020-01-01T00:00:00Z","latestRelease":{"isPrerelease":false,"releaseAssets":{"totalCount":6}}},
        \\{"name":"bad name","owner":{"login":"o"},"stargazerCount":900,"createdAt":"2020-01-01T00:00:00Z","latestRelease":{"isPrerelease":false,"releaseAssets":{"totalCount":6}}}
        \\]}}}
    ;
    const page = try parsePage(a, body, 500, epochDay("2026-10-24").?);
    try testing.expectEqual(@as(u32, 1234), page.count);
    try testing.expect(page.has_next);
    try testing.expectEqualStrings("abc", page.cursor.?);
    try testing.expectEqual(@as(usize, 1), page.repos.len);
    try testing.expectEqualStrings("good", page.repos[0].name);
    try testing.expectError(error.GraphQLError, parsePage(a, "{\"errors\":[{\"type\":\"RATE_LIMITED\"}]}", 500, 0));
}

test "render: most stars first, hand-written sources win, names never clash" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    var found = [_]Repo{
        .{ .owner = "alice", .name = "Tool", .stars = 800 },
        .{ .owner = "bob", .name = "tool", .stars = 5000 },
        .{ .owner = "BurntSushi", .name = "ripgrep", .stars = 50000 },
        .{ .owner = "carol", .name = "jq", .stars = 900 },
        .{ .owner = "bob", .name = "tool", .stars = 5000 },
    };
    var none = std.StringHashMap([]const u8).init(a);
    const out = try render(a, &found, &.{ "ripgrep", "jq" }, &.{"BurntSushi/ripgrep"}, &none, "2026-10-24");
    const body = out[std.mem.indexOf(u8, out, "\ntool ").? + 1 ..];
    try testing.expectEqualStrings("tool bob/tool\ncarol-jq carol/jq\nalice-tool alice/Tool\n", body);
}

test "render keeps last week's names, even when a more popular namesake appears" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const previous = try parsePrevious(a, "# old\ntool alice/Tool\nother carol/other\n");
    var found = [_]Repo{
        .{ .owner = "alice", .name = "Tool", .stars = 800 },
        .{ .owner = "bob", .name = "tool", .stars = 5000 },
    };
    const out = try render(a, &found, &.{}, &.{}, &previous, "2026-10-24");
    const body = out[std.mem.indexOf(u8, out, "\nbob-tool ").? + 1 ..];
    try testing.expectEqualStrings("bob-tool bob/tool\ntool alice/Tool\n", body);

    // A search that stopped early keeps the old projects, after the new ones.
    const old = try previousRepos(a, &previous, "tool alice/Tool\nother carol/other\n");
    try testing.expectEqual(@as(usize, 2), old.len);
    try testing.expectEqualStrings("carol", old[1].owner);
}
