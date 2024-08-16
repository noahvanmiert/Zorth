//  Copyright (c) Noah Van Miert 2024
//  Licensed under the MIT license. Use at your own risk!
//  12/08/2024 

const std = @import("std");

const print = std.debug.print;


pub const Location = struct {
    line: usize,
    col: usize,
    filepath: []const u8,

    pub fn init(line: usize, col: usize, filepath: []const u8) Location {
        return Location {
            .line = line,
            .col = col,
            .filepath = filepath
        };
    }
};

pub fn compilerDiagnostic(loc: Location, tag: []const u8,  comptime message: []const u8, args: anytype) void {
    var buffer: [256]u8 = undefined;

    const writer = std.fmt.bufPrint(&buffer, message, args) catch {
        std.debug.panic("Failed to format string", .{});
    };

    print("{s}:{d}:{d}: {s}: {s}\n", .{loc.filepath, loc.line, loc.col, tag, writer});
}


pub fn compilerError(loc: Location, comptime message: []const u8, args: anytype) void {
    const red_bold = "\x1b[1;31m";
    const reset = "\x1b[0m";

    print("{s}", .{red_bold});
    compilerDiagnostic(loc, "ERROR", message, args);
    print("{s}", .{reset});
}


pub fn compilerNote(loc: Location, comptime message: []const u8, args: anytype) void {
    const green_bold = "\x1b[1;32m";
    const reset = "\x1b[0m"; 

    print("{s}", .{green_bold});
    compilerDiagnostic(loc, "NOTE", message, args);
    print("{s}", .{reset});
}
