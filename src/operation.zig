//  Copyright (c) Noah Van Miert 2024
//  Licensed under the MIT license. Use at your own risk!
//  12/08/2024 

const diagnostics = @import("diagnostics.zig");

pub const OpType = enum {
    Push,
    PushStr,
    Str,
    Plus,
    Minus,
    Eq,
    Dup,
    Dup2,
    Drop,
    Swap,
    Over,
    Gt,
    St,
    Dump,
    If,
    Else,
    While,
    Do,
    End,
    Mem,
    Load,   // 1 byte 
    Store,   // 1 byte
    Syscall1,
    Syscall3,
    Shr,
    Shl,
    Bor,
    Band,
    Const,
    Identifier,
    Offset,
    Reset,
    Include,
    Proc,
    In,
    Call,
    Return,
    Memory,
    Unknown,
};



pub const Op = struct {
    type: OpType,
    arg: ?i64,
    stringArg: ?[]const u8,
    loc: diagnostics.Location,

    pub fn init(op_type: OpType, loc: diagnostics.Location) Op {
        return Op {
            .type = op_type,
            .arg = null,
            .stringArg = null,
            .loc = loc,
        };
    }

    pub fn initWithArg(op_type: OpType, loc: diagnostics.Location, arg: ?i64, stringArg: ?[]const u8) Op {
        return Op {
            .type = op_type,
            .arg = arg,
            .stringArg = stringArg,
            .loc = loc
        };
    }
};
