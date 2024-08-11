const std = @import("std");

const print = std.debug.print;
const exit = std.process.exit;

const Globals = enum(i32) {
    MemoryCapacity = 640000,
};

const OpType = enum {
    Push,
    PushStr,
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
    Band
};


const Location = struct {
    line: i32,
    col: i32,
    filepath: []const u8,

    pub fn init(line: i32, col: i32, filepath: []const u8) Location {
        return Location {
            .line = line,
            .col = col,
            .filepath = filepath
        };
    }
};


const Op = struct {
    type: OpType,
    arg: ?i32,
    stringArg: ?[]const u8,
    loc: Location,

    pub fn init(op_type: OpType) Op {
        return Op {
            .type = op_type,
            .arg = null,
            .stringArg = null,
            .loc = Location.init(0, 0, "")
        };
    }

    pub fn initWithArg(op_type: OpType, arg: ?i32, stringArg: ?[]const u8) Op {
        return Op {
            .type = op_type,
            .arg = arg,
            .stringArg = stringArg,
            .loc = Location.init(0, 0, "")
        };
    }
};


const TokenType = enum {
    Word,
    Int,
    String,
    Char
};


const Token = struct {
    value: []const u8,
    type: TokenType,

    fn init(value: []const u8, _type: TokenType) Token {
        return Token {
            .value = value,
            .type = _type,
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
                    print("{s}:{d}:{d}: `if` instruction does not have a reference to the end of its block\n", .{op.loc.filepath, op.loc.line, op.loc.col});
                    exit(1);
                }

                try file.writer().print("    jz addr_{?}\n", .{op.arg});
            },

            OpType.Else => {
                if (op.arg == null) {
                    print("{s}:{d}:{d}: `else` instruction does not have a reference to the end of its block\n", .{op.loc.filepath, op.loc.line, op.loc.col});
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
                    print("{s}:{d}:{d}: `end` instruction does not have a reference to the next instruction to jump to\n", .{op.loc.filepath, op.loc.line, op.loc.col});
                    exit(1);
                }

                try file.writer().print("    ;; -- end --\n", .{});
                if (ip + 1 != op.arg.?) {
                    try file.writer().print("    jmp addr_{?}\n", .{op.arg});
                }
            },

            OpType.Mem => {
                try file.writer().print("    ;; -- mem --\n", .{});
                try file.writer().print("    push mem\n", .{});
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

        }

        ip += 1;
    }
    
    try file.writer().print("addr_{}:\n", .{program.items.len});
    _ = try file.write("    ;; exit with non-zero exit code\n");
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
    try file.writer().print("mem: resb {d}\n", .{@intFromEnum(Globals.MemoryCapacity)});
}


fn crossreferenceProgram(program: *std.ArrayList(Op)) !void {
    var stack = std.ArrayList(usize).init(std.heap.page_allocator);
    defer stack.deinit();
    
    var ip: usize = 0;
    while (ip < program.items.len) {
        const op = program.items[ip];

        if (op.type == OpType.If) {
            try stack.append(ip);
        } else if (op.type == OpType.Else) {
            if (stack.items.len < 1) {
                print("{s}:{d}:{d}: `else` can only be used with if-blocks\n", .{op.loc.filepath, op.loc.line, op.loc.col});
                exit(1);
            }

            const if_ip = stack.pop();

            if (program.items[if_ip].type != OpType.If) {
                print("{s}:{d}:{d}: `else` can only be used with `if` blocks\n", .{op.loc.filepath, op.loc.line, op.loc.col});
                exit(1);
            }

            program.items[if_ip].arg = @intCast(ip + 1);
            try stack.append(ip);
        } else if (op.type == OpType.End) {
            if (stack.items.len < 1) {
                print("{s}:{d}:{d}: `else` can only be used with `if` blocks\n", .{op.loc.filepath, op.loc.line, op.loc.col});
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
            } else {
                print("{s}:{d}:{d}: `end` can only close `if`, `else` and `while` blocks for now\n", .{op.loc.filepath, op.loc.line, op.loc.col});
                exit(1);
            }
        } else if (op.type == OpType.While) {
            try stack.append(ip);
        } else if (op.type == OpType.Do) {
            if (stack.items.len < 1) {
                print("{s}:{d}:{d}: `do` can only be used with `while` blocks\n", .{op.loc.filepath, op.loc.line, op.loc.col});
                exit(1);
            }

            const while_ip = stack.pop();
            program.items[ip].arg = @intCast(while_ip);
            try stack.append(ip);
        }
    
        ip += 1;
    }
            
}


fn mapInsert(key: []const u8, value: OpType, map: *std.StringHashMap(OpType)) void {
    map.put(key, value) catch |err| {
        print("error occured while trying to put value into map: {?}\n", .{err});
        exit(1);
    };
}


fn parseWordAsOperation(token: Token, line: i32, col: i32, filepath: []const u8) Op {
    if (token.type == TokenType.Word) { 
        var map = std.StringHashMap(OpType).init(std.heap.page_allocator);
        defer map.deinit();

        mapInsert("+", OpType.Plus, &map);
        mapInsert("-", OpType.Minus, &map);
        mapInsert("=", OpType.Eq, &map);
        mapInsert("dump", OpType.Dump, &map);
        mapInsert(">", OpType.Gt, &map);
        mapInsert("<", OpType.St, &map);
        mapInsert("dup", OpType.Dup, &map);
        mapInsert("2dup", OpType.Dup2, &map);
        mapInsert("drop", OpType.Drop, &map);
        mapInsert("swap", OpType.Swap, &map);
        mapInsert("over", OpType.Over, &map);
        mapInsert("if", OpType.If, &map);
        mapInsert("else", OpType.Else, &map);
        mapInsert("while", OpType.While, &map);
        mapInsert("do", OpType.Do, &map);
        mapInsert("end", OpType.End, &map);
        mapInsert("mem", OpType.Mem, &map);
        mapInsert("load8", OpType.Load, &map);
        mapInsert("store8", OpType.Store, &map);
        mapInsert("syscall1", OpType.Syscall1, &map);
        mapInsert("syscall3", OpType.Syscall3, &map);
        mapInsert("shl", OpType.Shl, &map);
        mapInsert("shr", OpType.Shr, &map);
        mapInsert("bor", OpType.Bor, &map);
        mapInsert("band", OpType.Band, &map);
    
        if (map.get(token.value)) |op_type| {
            return Op.init(op_type);
        } else {
            print("{s}:{d}:{d}: Unkown word: {s}\n", .{filepath, line, col, token.value});
            exit(1);
        }
        
    } else if (token.type == TokenType.Int) {
        const result = std.fmt.parseInt(i32, token.value, 10) catch |err| {
            if (err == std.fmt.ParseIntError.Overflow) {
                print("{s}:{d}:{d}: {?}", .{filepath, line, col, err});
            }

            exit(1);
        };

        return Op.initWithArg(OpType.Push, result, null);
    } else if (token.type == TokenType.String){
        return Op.initWithArg(OpType.PushStr, null, token.value); 
    } else { 
        // character
        const char = token.value[0]; 
        return Op.initWithArg(OpType.Push, @as(i32, char), null);
    }
}


fn isValidBase10(s: []const u8) bool {
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


fn loadProgramFromFile(allocator: *std.mem.Allocator, path: []const u8) !std.ArrayList(Op) {
    var file = try std.fs.cwd().openFile(path, .{});
    defer file.close();

    var tokens = std.ArrayList(Op).init(allocator.*);
    var reader = std.io.bufferedReader(file.reader());
    var line_number: i32 = 1;

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
                    const tok = Token.init(complete_string, TokenType.String);

                    var operation = parseWordAsOperation(tok, line_number, @intCast(col), path);
                    operation.loc = Location.init(line_number, @intCast(col), path);
                    try tokens.append(operation);

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
                                print("{s}:{d}:{d}: unrecognized escape sequence '\\{c}'\n", .{path, line_number, token_start_col, escape});
                            },
                        }

                        index += 1;
                    }

                    // Convert the character to a string
                    const char_string = try std.fmt.allocPrint(std.heap.page_allocator, "{c}", .{char_value});

                    const tok = Token.init(char_string, TokenType.Char);

                    var operation = parseWordAsOperation(tok, line_number, @intCast(token_start_col), path);
                    operation.loc = Location.init(line_number, @intCast(token_start_col), path);
                    try tokens.append(operation);
                    
                    index += 1; // skip over the last '
                    in_char = false;
                    current_string.clearAndFree();

                    if (index < line_slice.len and line_slice[index] != '\'') {
                        print("{s}:{d}:{d}: character literals may not have more than one character",.{path, line_number, token_start_col});
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
                    const col = token_start_col;
                    var tok = Token.init(token_str, TokenType.Word);
                    
                    if (isValidBase10(token_str)) {
                        tok.type = TokenType.Int;
                    }

                    var operation = parseWordAsOperation(tok, line_number, @intCast(col), path);
                    operation.loc = Location.init(line_number, @intCast(col), path);
                    try tokens.append(operation);

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
            const col = token_start_col;
            var tok = Token.init(token_str, TokenType.Word);

            if (isValidBase10(token_str)) {
                tok.type = TokenType.Int;
            }

            var operation = parseWordAsOperation(tok, line_number, @intCast(col), path);
            operation.loc = Location.init(line_number, @intCast(col), path);
            try tokens.append(operation);
        }

        line_number += 1;
        allocator.free(line.?);
    }

    return tokens;
}


fn runCommand(command: []const []const u8) !void {
    const allocator = std.heap.page_allocator;
    var child = std.process.Child.init(command, allocator);

    try child.spawn();
    const exit_code = try child.wait();

    if (exit_code.Exited != 0) {
        print("Subprocess ({s}) failed with exit code {?}\n", .{command[0], exit_code.Exited});
    }
}   


fn usage() void {
    print("Usage: zorth <SUBCOMMAND> [ARGS]\n", .{});
    print("SUBCOMMANDS:\n", .{});
    print("    com <file>    Compile the program\n", .{});
}


pub fn main() !void {
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

        var program = try loadProgramFromFile(&allocator, argv[0]);
        defer program.deinit();

        try crossreferenceProgram(&program);
        try compile_program(program, "output.asm");

        try runCommand(&.{"nasm", "-felf64", "output.asm"});
        try runCommand(&.{"ld", "-o", "output", "output.o"});
    } else {
        print("ERROR: unkown subcommand: {s}\n", .{subcommand});
        usage();
        exit(1);
    }
}

