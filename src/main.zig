//  Copyright (c) Noah Van Miert 2024
//  Licensed under the MIT license. Use at your own risk!
//  12/08/2024 

const std = @import("std");

const diagnostics = @import("diagnostics.zig");
const subprocessModule = @import("subprocess.zig");
const tokenModule = @import("token.zig");
const operationModule = @import("operation.zig");
const utils = @import("utils.zig");

const subprocess = subprocessModule.Subprocess;

const TokenType = tokenModule.TokenType;
const Token = tokenModule.Token;

const OpType = operationModule.OpType;
const Op = operationModule.Op;

const print = std.debug.print;
const exit = std.process.exit;

const Globals = enum(i32) {
    MemoryCapacity = 640000,
    ReturnStackCapacity = 4096,
};


const Const = struct {
    name: []const u8,
    loc: diagnostics.Location,
    value: i64,

    fn init(name: []const u8, loc: diagnostics.Location, value: i64) Const {
        return Const {
            .name = name,
            .loc = loc,
            .value = value
        };
    }
};


const Proc = struct {
    name: []const u8,
    loc: diagnostics.Location,
    addr: usize,
    body_size: usize,

    fn init(name: []const u8, loc: diagnostics.Location, addr: usize, body_size: usize) Proc {
        return Proc {
            .name = name,
            .loc = loc,
            .addr = addr,
            .body_size = body_size
        };
    }
};


const Memory = struct {
    name: []const u8,
    size: usize,
    offset: usize,
    loc: diagnostics.Location,

    fn init(name: []const u8, size: usize, offset: usize, loc: diagnostics.Location) Memory {
        return Memory {
            .name = name,
            .size = size,
            .offset = offset,
            .loc = loc
        };
    }
};


const Context = struct {
    const_definitions: std.StringHashMap(Const),
    proc_definitions: std.StringHashMap(Proc),
    memory_definitions: std.StringHashMap(Memory),
    iota: i64 = 0,
    current_proc: ?Proc = null,
    memory_offset: usize = 0,

    fn init() Context {
        return Context {
            .const_definitions = std.StringHashMap(Const).init(std.heap.page_allocator),
            .proc_definitions = std.StringHashMap(Proc).init(std.heap.page_allocator),
            .memory_definitions = std.StringHashMap(Memory).init(std.heap.page_allocator),
        };
    }

    fn deinit(self: *Context) void {
        self.const_definitions.deinit();
        self.proc_definitions.deinit();
        self.memory_definitions.deinit();
    }

    fn addConst(self: *Context, name: []const u8, cdef: Const) void {
        self.const_definitions.put(name, cdef) catch |err| {
            print("error occured while trying to put value into map: {?}\n", .{err});
            exit(1);
        };
    }

    fn addProc(self: *Context, name: []const u8, proc: Proc) void {
        self.proc_definitions.put(name, proc) catch |err| {
            print("error occured while trying to put value into map: {?}\n", .{err});
            exit(1);
        };
    }

    fn addMemory(self: *Context, name: []const u8, mem: Memory) void {
        self.memory_definitions.put(name, mem) catch |err| {
            print("error occured while trying to put value into map: {?}\n", .{err});
            exit(1);
        };
    }
};


fn compile_program(program: std.ArrayList(Op), outFilepath: []const u8) !void { 
    const file = try std.fs.cwd().createFile(
        outFilepath,
        .{ .read = true },
    );
    defer file.close();

    _ = try file.write("BITS 64\n");
    _ = try file.write("segment .text\n");
    try file.writer().print("print:\n", .{});
    try file.writer().print("    mov     r9, -3689348814741910323\n", .{});
    try file.writer().print("    sub     rsp, 40\n", .{});
    try file.writer().print("    mov     BYTE [rsp+31], 10\n", .{});
    try file.writer().print("    lea     rcx, [rsp+30]\n", .{});
    try file.writer().print(".L2:\n", .{});
    try file.writer().print("    mov     rax, rdi\n", .{});
    try file.writer().print("    lea     r8, [rsp+32]\n", .{});
    try file.writer().print("    mul     r9\n", .{});
    try file.writer().print("    mov     rax, rdi\n", .{});
    try file.writer().print("    sub     r8, rcx\n", .{});
    try file.writer().print("    shr     rdx, 3\n", .{});
    try file.writer().print("    lea     rsi, [rdx+rdx*4]\n", .{});
    try file.writer().print("    add     rsi, rsi\n", .{});
    try file.writer().print("    sub     rax, rsi\n", .{});
    try file.writer().print("    add     eax, 48\n", .{});
    try file.writer().print("    mov     BYTE [rcx], al\n", .{});
    try file.writer().print("    mov     rax, rdi\n", .{});
    try file.writer().print("    mov     rdi, rdx\n", .{});
    try file.writer().print("    mov     rdx, rcx\n", .{});
    try file.writer().print("    sub     rcx, 1\n", .{});
    try file.writer().print("    cmp     rax, 9\n", .{});
    try file.writer().print("    ja      .L2\n", .{});
    try file.writer().print("    lea     rax, [rsp+32]\n", .{});
    try file.writer().print("    mov     edi, 1\n", .{});
    try file.writer().print("    sub     rdx, rax\n", .{});
    try file.writer().print("    xor     eax, eax\n", .{});
    try file.writer().print("    lea     rsi, [rsp+32+rdx]\n", .{});
    try file.writer().print("    mov     rdx, r8\n", .{});
    try file.writer().print("    mov     rax, 1\n", .{});
    try file.writer().print("    syscall\n", .{});
    try file.writer().print("    add     rsp, 40\n", .{});
    try file.writer().print("    ret\n", .{});
    _ = try file.write("global _start\n");
    _ = try file.write("_start:\n");
    _ = try file.write("    mov rax, ret_stack_end\n");
    _ = try file.write("    mov [ret_stack_rsp], rax\n");

    var strings = std.ArrayList([]const u8).init(std.heap.page_allocator);
    defer strings.deinit();

    var ip: usize = 0;
    while (ip < program.items.len) {
        const op = program.items[ip];
 
        try file.writer().print("addr_{}:\n", .{ip});
        switch (op.type) {
            OpType.Push => {
                try file.writer().print("    ;; -- push int --\n", .{});
                try file.writer().print("    push {?}\n", .{op.arg});
            },

            OpType.PushStr => {
                try file.writer().print("    ;; -- push str --\n", .{});
                try file.writer().print("    mov rax, {d}\n", .{op.stringArg.?.len}); 
                try file.writer().print("    push rax\n", .{});
                try file.writer().print("    push str_{d}\n", .{strings.items.len});
                try strings.append(op.stringArg.?);
            },

            OpType.Plus => {
                try file.writer().print("    ;; -- plus --\n", .{});
                try file.writer().print("    pop rax\n", .{});
                try file.writer().print("    pop rbx\n", .{});
                try file.writer().print("    add rax, rbx\n", .{});
                try file.writer().print("    push rax\n", .{});
            },

            OpType.Minus => {
                try file.writer().print("    ;; -- minus --\n", .{});
                try file.writer().print("    pop rax\n", .{});
                try file.writer().print("    pop rbx\n", .{});
                try file.writer().print("    sub rbx, rax\n", .{});
                try file.writer().print("    push rbx\n", .{});
            },

            OpType.Eq => {
                try file.writer().print("    ;; -- eq --\n", .{});
                try file.writer().print("    mov rcx, 0\n", .{});
                try file.writer().print("    mov rdx, 1\n", .{});
                try file.writer().print("    pop rax\n", .{});
                try file.writer().print("    pop rbx\n", .{});
                try file.writer().print("    cmp rax, rbx\n", .{});
                try file.writer().print("    cmove rcx, rdx\n", .{});
                try file.writer().print("    push rcx\n", .{});
            },

            OpType.Gt => {
                try file.writer().print("    ;; -- gt --\n", .{});
                try file.writer().print("    mov rcx, 0\n", .{});
                try file.writer().print("    mov rdx, 1\n", .{});
                try file.writer().print("    pop rbx\n", .{});
                try file.writer().print("    pop rax\n", .{});
                try file.writer().print("    cmp rax, rbx\n", .{});
                try file.writer().print("    cmovg rcx, rdx\n", .{});
                try file.writer().print("    push rcx\n", .{});
                
            },

            OpType.St => {
                try file.writer().print("    ;; -- st --\n", .{});
                try file.writer().print("    mov rcx, 0\n", .{});
                try file.writer().print("    mov rdx, 1\n", .{});
                try file.writer().print("    pop rbx\n", .{});
                try file.writer().print("    pop rax\n", .{});
                try file.writer().print("    cmp rax, rbx\n", .{});
                try file.writer().print("    cmovl rcx, rdx\n", .{});
                try file.writer().print("    push rcx\n", .{});
                
            },

            OpType.Dup => {
                try file.writer().print("    ;; -- dup --\n", .{});
                try file.writer().print("    pop rax\n", .{});
                try file.writer().print("    push rax\n", .{});
                try file.writer().print("    push rax\n", .{});
            },

            OpType.Dup2 => {
                try file.writer().print("    ;; -- 2dup --\n", .{});
                try file.writer().print("    pop rbx\n", .{});
                try file.writer().print("    pop rax\n", .{});
                try file.writer().print("    push rax\n", .{});
                try file.writer().print("    push rbx\n", .{});
                try file.writer().print("    push rax\n", .{});
                try file.writer().print("    push rbx\n", .{});
            },

            OpType.Drop => {
                try file.writer().print("    ;; -- drop --\n", .{});
                try file.writer().print("    pop rax\n", .{});
            },

            OpType.Swap => {
                try file.writer().print("    ;; -- swap --\n", .{});
                try file.writer().print("    pop rax\n", .{});
                try file.writer().print("    pop rbx\n", .{});
                try file.writer().print("    push rax\n", .{});
                try file.writer().print("    push rbx\n", .{});
            },

            OpType.Over => {
                try file.writer().print("    ;; -- over --\n", .{});
                try file.writer().print("    pop rax\n", .{});
                try file.writer().print("    pop rbx\n", .{});
                try file.writer().print("    push rbx\n", .{});
                try file.writer().print("    push rax\n", .{});
                try file.writer().print("    push rbx\n", .{});
            },

            OpType.If => {
                try file.writer().print("    ;; -- if --\n", .{});
                try file.writer().print("    pop rax\n", .{});
                try file.writer().print("    test rax, rax\n", .{});

                if (op.arg == null) {
                    diagnostics.compilerError(op.loc, "`if` instruction does not have a reference to the end of its block", .{});
                    exit(1);
                }

                try file.writer().print("    jz addr_{?}\n", .{op.arg});
            },

            OpType.Else => {
                if (op.arg == null) {
                    diagnostics.compilerError(op.loc, "`else` instruction does not have a reference to the end of its block", .{});
                    exit(1);
                }
                
                try file.writer().print("    ;; -- else --\n", .{});
                try file.writer().print("    jmp addr_{?}\n", .{op.arg});
            },

            OpType.While => {
                try file.writer().print("    ;; -- while --\n", .{});
            },

            OpType.Do => {
                try file.writer().print("    ;; -- do --\n", .{});
                try file.writer().print("    pop rax\n", .{});
                try file.writer().print("    test rax, rax\n", .{});

                if (op.arg == null) {
                    print("{s}:{d}:{d}: `if` instruction does not have a reference to the end of its block\n", .{op.loc.filepath, op.loc.line, op.loc.col});
                    exit(1);
                }
                
                try file.writer().print("    jz addr_{?}\n", .{op.arg.?});
            },

            OpType.End => {
                if (op.arg == null) {
                    diagnostics.compilerError(op.loc, "`end` instruction does not have a reference to the next instruction to jump to", .{});
                    exit(1);
                }

                try file.writer().print("    ;; -- end --\n", .{});
                if (ip + 1 != op.arg.?) {
                    try file.writer().print("    jmp addr_{?}\n", .{op.arg});
                }
            },

            OpType.Mem => {
                try file.writer().print("    ;; -- mem --\n", .{});
                try file.writer().print("    mov rax, mem\n", .{});
                try file.writer().print("    add rax, {d}\n", .{op.arg.?});
                try file.writer().print("    push rax\n", .{});
             },

            OpType.Dump => {
                try file.writer().print("    ;; -- dump --\n", .{});
                try file.writer().print("    pop rdi\n", .{});
                try file.writer().print("    call print\n", .{});
            },

            OpType.Load => {
                try file.writer().print("    ;; -- load8 --\n", .{});
                try file.writer().print("    pop rax\n", .{});
                try file.writer().print("    xor rbx, rbx\n", .{});
                try file.writer().print("    mov bl, [rax]\n", .{});
                try file.writer().print("    push rbx\n", .{});
            },

            OpType.Store => {
                try file.writer().print("    ;; -- store8 --\n", .{});
                try file.writer().print("    pop rbx\n", .{});
                try file.writer().print("    pop rax\n", .{});
                try file.writer().print("    mov [rax], bl\n", .{});
            },

            OpType.Syscall1 => {
                try file.writer().print("    ;; -- syscall1 --\n", .{});
                try file.writer().print("    pop rax\n", .{});
                try file.writer().print("    pop rdi\n", .{});
                try file.writer().print("    syscall\n", .{});
            },

            OpType.Syscall3 => {
                try file.writer().print("    ;; -- syscall3 --\n", .{});
                try file.writer().print("    pop rax\n", .{});
                try file.writer().print("    pop rdi\n", .{});
                try file.writer().print("    pop rsi\n", .{});
                try file.writer().print("    pop rdx\n", .{});
                try file.writer().print("    syscall\n", .{});
            },

            OpType.Shr => {
                try file.writer().print("    ;; -- shr --\n", .{});
                try file.writer().print("    pop rcx\n", .{});
                try file.writer().print("    pop rbx\n", .{});
                try file.writer().print("    shr rbx, cl\n", .{});
                try file.writer().print("    push rbx\n", .{});
            },

            OpType.Shl => {
                try file.writer().print("    ;; -- shl --\n", .{});
                try file.writer().print("    pop rcx\n", .{});
                try file.writer().print("    pop rbx\n", .{});
                try file.writer().print("    shl rbx, cl\n", .{});
                try file.writer().print("    push rbx\n", .{});
            },

            OpType.Bor => {
                try file.writer().print("    ;; -- bor --\n", .{});
                try file.writer().print("    pop rax\n", .{});
                try file.writer().print("    pop rbx\n", .{});
                try file.writer().print("    or rbx, rax\n", .{});
                try file.writer().print("    push rbx\n", .{});
            },

            OpType.Band => {
                try file.writer().print("    ;; -- band --\n", .{});
                try file.writer().print("    pop rax\n", .{});
                try file.writer().print("    pop rbx\n", .{});
                try file.writer().print("    and rbx, rax\n", .{});
                try file.writer().print("    push rbx\n", .{});
            },

            OpType.Proc => {
                try file.writer().print("    ;; -- proc --\n", .{});
                try file.writer().print("    jmp addr_{d}\n", .{op.arg.?}); 
            },

            OpType.In => {
                try file.writer().print("    ;; -- proc (in) --\n", .{});
                try file.writer().print("    mov [ret_stack_rsp], rsp\n", .{}); 
                try file.writer().print("    mov rsp, rax\n", .{}); 
            },

            OpType.Call => {
                try file.writer().print("    ;; -- call --\n", .{});
                try file.writer().print("    mov rax, rsp\n", .{}); 
                try file.writer().print("    mov rsp, [ret_stack_rsp]\n", .{});
                try file.writer().print("    call addr_{}\n", .{op.arg.?});
                try file.writer().print("    mov [ret_stack_rsp], rsp\n", .{});
                try file.writer().print("    mov rsp, rax\n", .{});
            },

            OpType.Return => {
                try file.writer().print("    ;; -- return --\n", .{});
                try file.writer().print("    mov rax, rsp\n", .{}); 
                try file.writer().print("    mov rsp, [ret_stack_rsp]\n", .{}); 
                try file.writer().print("    ret\n", .{}); 
            },

            else => {}
        }

        ip += 1;
    }
    
    try file.writer().print("addr_{}:\n", .{program.items.len});
    _ = try file.write("    mov rax, 60\n");
    _ = try file.write("    mov rdi, 0\n");
    _ = try file.write("    syscall\n");

    _ = try file.write("segment .data\n");

    for (0..strings.items.len) |index| {
        const string = strings.items[index];
        try file.writer().print("str_{d}: ", .{index});

        // Convert the string to a series of bytes
        try file.writer().print("    db ", .{});
            
        // Write each byte in hexadecimal format
        for (string) |c| {
            try file.writer().print("0x{x}, ", .{c});
        }
            
        // Add null terminator at the end
        try file.writer().print("0\n", .{}); // Newline after the null terminator  
    }

    _ = try file.write("segment .bss\n");
    try file.writer().print("ret_stack_rsp: resq 1\n", .{});
    try file.writer().print("ret_stack: resb {d}\n", .{@intFromEnum(Globals.ReturnStackCapacity)});
    try file.writer().print("ret_stack_end: resq 1\n", .{});
    try file.writer().print("mem: resb {d}\n", .{@intFromEnum(Globals.MemoryCapacity)});
}


fn checkRedefinition(name: []const u8, loc: diagnostics.Location, entity: anytype, entity_type: []const u8) void {
    if (entity) |e| {
        diagnostics.compilerError(loc, "redefinition of a {s} `{s}`", .{entity_type, name});
        diagnostics.compilerNote(e.loc, "the original definition is located here", .{});
        exit(1);
    }
}


fn checkNameRedefinition(ctx: *Context, name: []const u8, loc: diagnostics.Location) void {
    checkRedefinition(name, loc, ctx.const_definitions.get(name), "constant");
    checkRedefinition(name, loc, ctx.proc_definitions.get(name), "procedure");
    checkRedefinition(name, loc, ctx.memory_definitions.get(name), "memory region");
}


fn evalConstValue(ctx: *Context, loc: diagnostics.Location, index: *usize, tokens: *const std.ArrayList(Token)) !i64 {
    var i = index.*; 

    var stack = std.ArrayList(i64).init(std.heap.page_allocator);
    defer stack.deinit();

    while (i < tokens.items.len) {
        const token = tokens.items[i];
        
        switch (token.type) {
            .Intrinsic => {
                const op_type = utils.getIntrinsicType(token.value);

                switch (op_type) {
                    .Plus => {
                        if (stack.items.len < 2) {
                            diagnostics.compilerError(token.location, "not enough argument for `+` operation", .{});
                            exit(1);
                        }

                        const a = stack.pop();
                        const b = stack.pop();
                        try stack.append(a + b);
                    },

                    .Minus => {
                        if (stack.items.len < 2) {
                            diagnostics.compilerError(token.location, "not enough argument for `-` operation", .{});
                            exit(1);
                        }

                        const a = stack.pop();
                        const b = stack.pop();
                        try stack.append(b - a);
                    },

                    .Eq => {
                        if (stack.items.len < 2) {
                            diagnostics.compilerError(token.location, "not enough argument for `=` operation", .{});
                            exit(1);
                        }

                        const a = stack.pop();
                        const b = stack.pop();
                        try stack.append(@intFromBool(a == b));
                    },

                    .Drop => {
                        if (stack.items.len < 1) {
                            diagnostics.compilerError(token.location, "not enough argument for `drop` operation", .{});
                            exit(1);
                        }

                        _ = stack.pop();
                    },

                    else => {
                        diagnostics.compilerError(token.location, "{} is unsupported in compile time evaluation", .{op_type});
                        exit(1);
                    }
                }   
            },

            .Keyword => {
                const op_type = utils.getKeywordType(token.value);

                switch (op_type) {
                    .End => {
                        i += 1; // so we skip over `end`
                        break;
                    },
 
                    .Offset => {
                        try stack.append(ctx.iota);
                        ctx.iota += 1;
                    },

                    .Reset => {
                        try stack.append(ctx.iota);
                        ctx.iota = 0;
                    },

                    else => {
                        diagnostics.compilerError(token.location, "{} is unsupported in compile time evaluation", .{op_type});
                        exit(1);
                    }
                }
            },

            .Number => {
                const result = std.fmt.parseInt(i64, token.value, 10) catch |err| {
                    diagnostics.compilerError(token.location, "{}", .{err});
                    exit(1);
                };
                
                try stack.append(result);
            },

            .Character => {
                const char = token.value[0];
                try stack.append(@as(i64, char));
            },

            .Word => {
                if (!ctx.const_definitions.contains(token.value)) {
                    diagnostics.compilerError(token.location, "unsupported word `{s}` in compile time evaluation", .{token.value});
                    exit(1);
                }

                try stack.append(ctx.const_definitions.get(token.value).?.value);
            },
            
            else => {
                diagnostics.compilerError(token.location, "unsupported token `{}` in compile time evaluation", .{token.type});
                exit(1);
            }
        }

        i += 1;
    }


    if (stack.items.len != 1) {
        diagnostics.compilerError(loc, "the result of an expression in compile time evaluation must be a single number", .{});
        exit(1);
    }

    index.* = i;

    return stack.pop();
}


fn processProgram(ctx: *Context, program: *std.ArrayList(Op)) !void {
    var stack = std.ArrayList(usize).init(std.heap.page_allocator);
    defer stack.deinit();
 
    var ip: usize = 0;
    while (ip < program.items.len) {
        const op = program.items[ip];

        if (op.type == OpType.If) {
            try stack.append(ip);
        } 

        else if (op.type == OpType.Else) {
            if (stack.items.len < 1) {
                diagnostics.compilerError(op.loc, "`else` can only be used with `if` blocks", .{});
                exit(1);
            }

            const if_ip = stack.pop();

            if (program.items[if_ip].type != OpType.If) {
                diagnostics.compilerError(op.loc, "`else` can only be used with `if` block", .{});
                exit(1);
            }

            program.items[if_ip].arg = @intCast(ip + 1);
            try stack.append(ip);
        } 

        else if (op.type == OpType.End) {
            if (stack.items.len < 1) {
                diagnostics.compilerError(op.loc, "`end` can only close `if`, `else`, `while`, `const` and `proc` blocks for now", .{});
                exit(1);
            }

            const block_ip = stack.pop();
            
            if (program.items[block_ip].type == OpType.If or program.items[block_ip].type == OpType.Else)  {
                program.items[block_ip].arg = @intCast(ip);
                program.items[ip].arg = @intCast(ip + 1);

            } else if (program.items[block_ip].type == OpType.Do) {
                 if (program.items[block_ip].arg == null) {
                     std.debug.assert(false);
                }
                
                program.items[ip].arg = program.items[block_ip].arg;
                program.items[block_ip].arg = @intCast(ip + 1);

            } else if (program.items[block_ip].type == OpType.Proc) { 
                program.items[block_ip].arg = @intCast(ip + 1);
                program.items[ip].type = OpType.Return;
                ctx.current_proc = null;

            } else {
                // NOTE: const and memory handle `end` by themselves. 

                diagnostics.compilerError(op.loc, "`end` can only close `if`, `else`, `while`, `const` and `proc` blocks for now", .{});
                exit(1);
            }
        } 

        else if (op.type == OpType.While) {
            try stack.append(ip);
        } 

        else if (op.type == OpType.Do) {
            if (stack.items.len < 1) {
                diagnostics.compilerError(op.loc, "`do` can only be used with `while` blocks", .{});
                exit(1);
            }

            const while_ip = stack.pop();
            program.items[ip].arg = @intCast(while_ip);
            try stack.append(ip);
        } 

        
        else if (op.type == OpType.Proc) {
            if (ctx.current_proc != null) {
                diagnostics.compilerError(op.loc, "defining procedures inside of procedures is not allowed", .{});
                diagnostics.compilerNote(ctx.current_proc.?.loc, "the current procedure start here", .{});
                exit(1);
            }

            try stack.append(ip);

            if (ctx.proc_definitions.getPtr(op.stringArg.?)) |proc| {
                proc.addr = ip;
                ctx.current_proc = proc.*;
            }
        }
    
        else if (op.type == OpType.Offset) {
            diagnostics.compilerError(op.loc, "keyword `offset` is only supported in compile time evaluation", .{});
            exit(1);
        } 

        else if (op.type == OpType.Reset) {
            diagnostics.compilerError(op.loc, "keyword `reset` is only supported in compile time evaluation", .{});
            exit(1);
        }  

        else if (op.type == OpType.Str) {
            program.items[ip].type = OpType.PushStr;
        }

        else if (op.type == OpType.Call) {
            if (ctx.proc_definitions.get(op.stringArg.?)) |proc| {
                program.items[ip].arg = @intCast(proc.addr + 1);
            }
        }
    
        ip += 1;
    }
            
}




fn createProgramFromTokens(allocator: *std.mem.Allocator, tokens: *std.ArrayList(Token), ctx: *Context) !std.ArrayList(Op) {
    var program = std.ArrayList(Op).init(allocator.*);

    var i: usize = 0;
    while (i < tokens.items.len) {
        const token = tokens.items[i];
        
        switch (token.type) {
            .Intrinsic => {
                try program.append(Op.init(utils.getIntrinsicType(token.value), token.location));
            },


            .Keyword => {
                const keywordType = utils.getKeywordType(token.value);

                if (keywordType == OpType.Const) {
                    i += 1; // skip over `const`
            
                    if (tokens.items[i].type != TokenType.Word) {
                        diagnostics.compilerError(tokens.items[i].location, "expected const name to be {} but found {}", .{TokenType.Word, tokens.items[i].type});
                        exit(1);
                    }

                    const const_name = tokens.items[i].value;
                    const const_location = tokens.items[i].location;
                    i += 1; // skip over the name
                    checkNameRedefinition(ctx, const_name, const_location);

                    const const_value = try evalConstValue(ctx, const_location, &i, tokens);
                    ctx.addConst(const_name, Const.init(const_name, const_location, const_value));

                    continue;
                }


                if (keywordType == OpType.Include) {
                    i += 1; // skip over `include`

                    if (tokens.items[i].type != TokenType.String) {
                        diagnostics.compilerError(
                            token.location,
                            "expected path to the include file to be of type {} but found {}", .{TokenType.String, tokens.items[i].type}
                        );
                        exit(1);
                    }

                    var toks = try loadTokensFromFile(allocator, tokens.items[i].value);
                    defer toks.deinit();

                    try tokens.insertSlice(i + 1, toks.items);
                }


                if (keywordType == OpType.Memory) {
                    i += 1; // skip over `memory` keyword

                    if (i >= tokens.items.len) {
                        diagnostics.compilerError(token.location, "expected memory name but found nothing", .{});
                        exit(1);
                    }

                    if (tokens.items[i].type != TokenType.Word) {
                        diagnostics.compilerError(
                            tokens.items[i].location, "expected memory name to be of type {} but found {}", .{TokenType.Word, tokens.items[i].type}
                        );
                        exit(1);
                    }

                    const memory_name = tokens.items[i].value;
                    checkNameRedefinition(ctx, memory_name, tokens.items[i].location);
                    i += 1;

                    if (i >= tokens.items.len) {
                        diagnostics.compilerError(tokens.items[i].location, "expected memory size but found nothing", .{});
                        exit(1);
                    }

                    const memory_size = try evalConstValue(ctx, tokens.items[i].location, &i, tokens);
                    const memory_offset = ctx.memory_offset;
                    ctx.memory_offset += @intCast(memory_size); // TODO: everything should be usize 
                    ctx.addMemory(memory_name, Memory.init(memory_name, @intCast(memory_size), memory_offset, token.location));
                    
                    continue;
                }


                if (keywordType == OpType.Proc) {
                    i += 1; // skip over `proc`
                    if (i >= tokens.items.len) {
                        diagnostics.compilerError(token.location, "expected procedure name but found nothing", .{});
                        exit(1);
                    }

                    if (tokens.items[i].type != TokenType.Word) {
                        diagnostics.compilerError(program.items[i].loc, 
                            "expected procedure name to be {} but found {}", .{TokenType.Word, tokens.items[i].type}
                        );
                        exit(1);
                    } 

                    const proc_name = tokens.items[i].value;
                    const proc_loc = tokens.items[i].location;
                    checkNameRedefinition(ctx, proc_name, tokens.items[i].location);

                    i += 1;
                    if (i >= tokens.items.len) {
                        diagnostics.compilerError(tokens.items[i - 1].location, "expected keyword `in` but found nothing", .{});
                        exit(1);
                    }

                    const token_after_name = tokens.items[i];
                    if (!std.mem.eql(u8, token_after_name.value, "in")) {
                        diagnostics.compilerError(tokens.items[i].location, "expected keyword `in` but found token of `{s}`", .{token_after_name. value});
                        exit(1);
                    }

                    const proc = Proc.init(proc_name, proc_loc, 0, 0);
                    ctx.addProc(proc_name, proc);

                    try program.append(Op.initWithArg(OpType.Proc, token.location, null, proc_name));
                    continue;
                }


                try program.append(Op.init(keywordType, token.location));
            },


            .String => {
                try program.append(Op.initWithArg(OpType.PushStr, token.location, null, token.value));
            },


            .Number => {
                const result = std.fmt.parseInt(i64, token.value, 10) catch |err| {
                    diagnostics.compilerError(token.location, "{}", .{err});
                    exit(1);
                };
                
                try program.append(Op.initWithArg(OpType.Push, token.location, result, null));
            },


            .Character => {
                const char = token.value[0];
                try program.append(Op.initWithArg(OpType.Push, token.location, @as(i64, char), null));
            },


            .Word => {
                // NOTE: we pass in the function name for the function call, we set the call 
                //       address in the crossreference phase.
                
                if (ctx.const_definitions.get(token.value)) |cdef| {
                    try program.append(Op.initWithArg(OpType.Push, token.location, cdef.value, null));

                } else if (ctx.proc_definitions.contains(token.value)) {
                    try program.append(Op.initWithArg(OpType.Call, token.location, null, token.value));

                } else if (ctx.memory_definitions.get(token.value)) |mem| {
                    try program.append(Op.initWithArg(OpType.Mem, token.location, @intCast(mem.offset), null));
                
                } else {
                    diagnostics.compilerError(token.location, "unkown word: {s}", .{token.value});
                    exit(1);
                }

            },


            else => {
                diagnostics.compilerError(token.location, "unkown word: {s}", .{token.value});
                exit(1);
            }
        }

        i += 1;
    }

    return program;
}


fn loadTokensFromFile(allocator: *std.mem.Allocator, path: []const u8) !std.ArrayList(Token) {
    var file = try std.fs.cwd().openFile(path, .{});
    defer file.close();

    var tokens = std.ArrayList(Token).init(allocator.*);
    var reader = std.io.bufferedReader(file.reader());
    var line_number: usize = 1;

    while (true) {
        const line = try reader.reader().readUntilDelimiterOrEofAlloc(allocator.*, '\n', 255);

        // If EOF is reached, stop
        if (line == null) break;

        const line_slice = line.?[0..];
        var index: usize = 0;
        var in_string = false;
        var current_string = std.ArrayList(u8).init(allocator.*);
        var token_start_col: usize = 0;
        var in_char = false;

        while (index < line_slice.len) {
            const c = line_slice[index];

            // Handle comments
            if (!in_string and index + 1 < line_slice.len and line_slice[index] == '/' and line_slice[index + 1] == '/') {
                break; // Skip the rest of the line as it's a comment
            }

            if (in_string) {
                if (c == '"' and (index == 0 or line_slice[index - 1] != '\\')) {
                    // End of string
                    in_string = false;
                    
                    const complete_string = try current_string.toOwnedSlice();
                    const col = token_start_col;
                    const location = diagnostics.Location.init(line_number, col, path);

                    const tok = Token.init(TokenType.String, complete_string, location);
                    try tokens.append(tok);

                    current_string.clearAndFree(); // Reset for the next string
                } else {
                    // Handle escape sequences within strings
                    if (c == '\\' and index + 1 < line_slice.len) {
                        const next_char = line_slice[index + 1];
                        switch (next_char) {
                            '\\' => try current_string.append('\\'),
                            'n' => try current_string.append('\n'),
                            't' => try current_string.append('\t'),
                            '"' => try current_string.append('"'),
                            else => try current_string.append(c),
                        }
                        index += 1; // Skip the next character
                    } else {
                        try current_string.append(c);
                    }
                }
            } else if (in_char) {
                // '*'
                if (c != '\'') {
                    var char_value = c; 
                    
                    if (c == '\\') {
                        const escape = line_slice[index + 1];
                        switch (escape) {
                            '\\' => char_value = '\\',
                            'n' => char_value = '\n',
                            't' => char_value = '\t',
                            '\'' => char_value = '\'',
                            '"' => char_value = '"',
                            'r' => char_value = '\r',
                            '0' => char_value = '\x00', // Null character
                            else => {
                                const location = diagnostics.Location.init(line_number, token_start_col, path);
                                diagnostics.compilerError(location, "unrecognized escape sequence '\\{c}'", .{escape});
                                exit(1);
                            },
                        }

                        index += 1;
                    }

                    // Convert the character to a string
                    const char_string = try std.fmt.allocPrint(std.heap.page_allocator, "{c}", .{char_value});

                    const location = diagnostics.Location.init(line_number, token_start_col, path);    
                    const tok = Token.init(TokenType.Character, char_string, location);
                    try tokens.append(tok);
                    
                    index += 1; // skip over the last '
                    in_char = false;
                    current_string.clearAndFree();

                    if (index < line_slice.len and line_slice[index] != '\'') {
                        diagnostics.compilerError(location, "character literals may only have one character", .{});
                        exit(1);
                    }
                }
            } else if (c == '"') {
                // Start of string
                in_string = true;
                token_start_col = index + 1; // Start column for the string
            } else if (c == '\'' and !in_char) {
                in_char = true;
                token_start_col = index + 1;
            } else if (std.ascii.isWhitespace(c)) {
                // Handle whitespace as delimiter
                if (current_string.items.len > 0) {
                    // Emit the previous token if it exists
                    const token_str = try current_string.toOwnedSlice();

                    const location = diagnostics.Location.init(line_number, token_start_col, path);
                    var tok = Token.init(TokenType.Word, token_str, location);

                    if (utils.isValidBase10(token_str)) {
                        tok.type = TokenType.Number;
                    } else if (utils.isIntrinsic(token_str)) {
                        tok.type = TokenType.Intrinsic;
                    } else if (utils.isKeyword(token_str)) {
                        tok.type = TokenType.Keyword;
                    }

                    try tokens.append(tok);

                    current_string.clearAndFree(); // Reset for the next token
                }
                token_start_col = index + 1; // Start column for the next token
            } else {
                // Append character to the current token
                try current_string.append(c);
            }

            index += 1;
        }

        // If there's any remaining token or string
        if (current_string.items.len > 0) {
            const token_str = try current_string.toOwnedSlice();

            const location = diagnostics.Location.init(line_number, token_start_col, path);
            var tok = Token.init(TokenType.Word, token_str, location);

            if (utils.isValidBase10(token_str)) {
                tok.type = TokenType.Number;
            } else if (utils.isIntrinsic(token_str)) {
                tok.type = TokenType.Intrinsic;
            } else if (utils.isKeyword(token_str)) {
                tok.type = TokenType.Keyword;
            }

            try tokens.append(tok);
        }

        line_number += 1;
        allocator.free(line.?);
    }

    return tokens;
}


fn usage() void {
    print("Usage: zorth [options] [file]\n\n", .{});
    print("Options:\n", .{});
    print("    -h, --help     Prints this help message.\n", .{});
    print("    -r, --run      Runs the program directly after compilation.\n", .{});
    print("    -s, --asm      Only generate assembly, no executable\n", .{});
    print("    --unsafe       Disables type checking.\n\n", .{});
    print("For more information, visit https://github.com/noahvanmiert/Zorth\n", .{});
}


fn checkFlag(flag: []const u8, f1: []const u8, f2: []const u8) bool {
    return std.mem.eql(u8, flag, f1) or std.mem.eql(u8, flag, f2);
}


const Flags = struct {
    unsafe: bool = false,
    run: bool = false,
    assembly: bool = false,
};


pub fn main() !void {
    var allocator = std.heap.page_allocator;

    const args = try std.process.argsAlloc(allocator);
    defer std.process.argsFree(allocator, args);

    var arguments = args;
    var flags: Flags = Flags{};
    var filepath: []const u8 = "";

    if (args.len < 2) {
        print("ERROR: no file provided\n\n", .{});
        usage();
        return;
    }

    arguments = arguments[1..]; // skip over program name

    for (arguments) |arg| {
        if (arg[0] == '-') {
            // parse flag
            const flag = arg;

            if (checkFlag(flag, "--unsafe", "--unsafe")) {
                flags.unsafe = true;
            } else if (checkFlag(flag, "-r", "--run")) {
                flags.run = true;
            } else if (checkFlag(flag, "-s", "--asm")) {
                flags.assembly = true;
            } else if (checkFlag(flag, "-h", "--help")) {
                usage();
                return;
            } else {
                print("ERROR: unkown flag: {s}\n\n", .{flag});
                usage();
                return;
            }

        } else {
            // parse filepath
            filepath = arg;
        }
    }

    var tokens = try loadTokensFromFile(&allocator, filepath);
    defer tokens.deinit();

    var ctx = Context.init();
    defer ctx.deinit();

    var program = try createProgramFromTokens(&allocator, &tokens, &ctx);
    defer program.deinit();

    try processProgram(&ctx, &program);
    try compile_program(program, "output.asm");

    if (!flags.assembly) {
        try subprocess.call(&.{"nasm", "-felf64", "output.asm"});
        try subprocess.call(&.{"ld", "-o", "output", "output.o"});
    
        if (flags.run) {
            try subprocess.call(&.{"./output"});
        }
    }
}


pub fn main2() !void {
    var allocator = std.heap.page_allocator;

    const args = try std.process.argsAlloc(allocator);
    defer std.process.argsFree(allocator, args);

    var argv = args;
        
    if (args.len < 2) {
        print("ERROR: no subcommand provided!\n", .{});
        usage();
        std.process.exit(1);
    }

    argv = argv[1..]; // remove program

    const subcommand = args[1];
    argv = argv[1..]; // remove subcommand
        
    if (std.mem.eql(u8, subcommand, "com")) {
        if (argv.len < 1) {
            usage();
            print("ERROR: no input file is  provided for the compilation\n", .{});
            exit(1);
        }

        var tokens = try loadTokensFromFile(&allocator, argv[0]);
        defer tokens.deinit();

        var ctx = Context.init();
        defer ctx.deinit();

        var program = try createProgramFromTokens(&allocator, &tokens, &ctx);
        defer program.deinit();

        try processProgram(&ctx, &program);
        try compile_program(program, "output.asm");

        try subprocess.call(&.{"nasm", "-felf64", "output.asm"});
        try subprocess.call(&.{"ld", "-o", "output", "output.o"});
    } else {
        print("ERROR: unkown subcommand: {s}\n", .{subcommand});
        usage();
        exit(1);
    }
}

