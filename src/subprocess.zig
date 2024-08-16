//  Copyright (c) Noah Van Miert 2024
//  Licensed under the MIT license. Use at your own risk!
//  12/08/2024 

const std = @import("std");

pub const Subprocess = struct {
   
    pub fn call(command: []const []const u8) !void {
        var child = std.process.Child.init(command, std.heap.page_allocator);

        try child.spawn();
        const exit_code = try child.wait();

        if (exit_code.Exited != 0) {
            const red_bold = "\x1b[1;31m"; // Red and bold
            const reset = "\x1b[0m";

            std.debug.print("{s}", .{red_bold});
            std.debug.print("Subprocess ({s}) failed with exit code {?}\n", .{command[0], exit_code.Exited});
            std.debug.print("{s}", .{reset});
        }
    }

};
