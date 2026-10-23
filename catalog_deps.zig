//! The slice of abv0's own sources that tools/build-catalog.zig reuses.
//!
//! Zig forbids `@import("../src/x.zig")` from outside a module's root, and a
//! source file may belong to only one module. The catalog tool needs the
//! release-asset picker, the archive extractor and the registry validator, and
//! those files import each other. So they are exposed through this one module,
//! whose root sits at the repository root and therefore contains both `src/`
//! and `tools/`. Nothing else uses this file.

pub const ghrelease = @import("src/ghrelease.zig");
pub const archive = @import("src/archive.zig");
pub const registry = @import("src/registry.zig");
pub const safepath = @import("src/safepath.zig");
pub const net = @import("src/net.zig");
pub const bindetect = @import("src/bindetect.zig");
pub const ghverify = @import("src/ghverify.zig");
pub const winapp = @import("src/winapp.zig");
