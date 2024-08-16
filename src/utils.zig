//  Copyright (c) Noah Van Miert 2024
//  Licensed under the MIT license. Use at your own risk!
//  12/08/2024 

const std = @import("std");
const operationModule = @import("operation.zig");

const OpType = operationModule.OpType;


const MapEntry = struct {
    key: []const u8,
    value: OpType,
};


const instrinsic_map = [_]MapEntry{
    MapEntry{ .key = "+", .value = OpType.Plus },
    MapEntry{ .key = "-", .value = OpType.Minus },
    MapEntry{ .key = "=", .value = OpType.Eq },
    MapEntry{ .key = "dump", .value = OpType.Dump },
    MapEntry{ .key = ">", .value = OpType.Gt },
    MapEntry{ .key = "<", .value = OpType.St },
    MapEntry{ .key = "dup", .value = OpType.Dup },
    MapEntry{ .key = "2dup", .value = OpType.Dup2 },
    MapEntry{ .key = "drop", .value = OpType.Drop },
    MapEntry{ .key = "swap", .value = OpType.Swap },
    MapEntry{ .key = "over", .value = OpType.Over },
    MapEntry{ .key = "load8", .value = OpType.Load },
    MapEntry{ .key = "store8", .value = OpType.Store },
    MapEntry{ .key = "syscall1", .value = OpType.Syscall1 },
    MapEntry{ .key = "syscall3", .value = OpType.Syscall3 },
    MapEntry{ .key = "shl", .value = OpType.Shl },
    MapEntry{ .key = "shr", .value = OpType.Shr },
    MapEntry{ .key = "bor", .value = OpType.Bor },
    MapEntry{ .key = "band", .value = OpType.Band },
};


const keyword_map = [_]MapEntry{
    MapEntry{ .key = "if", .value = OpType.If },
    MapEntry{ .key = "else", .value = OpType.Else },
    MapEntry{ .key = "while", .value = OpType.While },
    MapEntry{ .key = "do", .value = OpType.Do },
    MapEntry{ .key = "end", .value = OpType.End },
    MapEntry{ .key = "const", .value = OpType.Const },
    MapEntry{ .key = "include", .value = OpType.Include },
    MapEntry{ .key = "proc", .value = OpType.Proc },
    MapEntry{ .key = "in", .value = OpType.In },
    MapEntry{ .key = "memory", .value = OpType.Memory },
    MapEntry{ .key = "offset", .value = OpType.Offset },
    MapEntry{ .key = "reset", .value = OpType.Reset },
};


pub fn isIntrinsic(value: []const u8) bool {
    for (instrinsic_map) |entry| {
        if (std.mem.eql(u8, entry.key, value)) {
            return true;
        }
    }

    return false;
}


pub fn isKeyword(value: []const u8) bool {
    for (keyword_map) |entry| {
        if (std.mem.eql(u8, entry.key, value)) {
            return true;
        }
    }

    return false;
}


pub fn getIntrinsicType(value: []const u8) OpType {
    for (instrinsic_map) |entry| {
        if (std.mem.eql(u8, entry.key, value)) {
            return entry.value;
        }
    }

    return OpType.Unknown;
}


pub fn getKeywordType(value: []const u8) OpType {
    for (keyword_map) |entry| {
        if (std.mem.eql(u8, entry.key, value)) {
            return entry.value;
        }
    }

    return OpType.Unknown;
}


pub fn isValidBase10(s: []const u8) bool {
    if (s.len == 0) return false; // Empty string is not a valid number

    var start: usize = 0;
    if (s[0] == '-') {
        if (s.len == 1) return false; // "-" alone is not a valid number
        start = 1; // Skip the minus sign if present
    }

    for (start..s.len) |i| {
        const c = s[i];
        if (c < '0' or c > '9') {
            return false; // Not a digit
        }
    }

    return true; // All characters are valid digits
}
