//  Copyright (c) Noah Van Miert 2024
//  Licensed under the MIT license. Use at your own risk!
//  12/08/2024 

const diagnostics = @import("diagnostics.zig");

pub const TokenType = enum {
    Intrinsic,
    Keyword,
    Word,
    Number,
    String,
    Character,
    Unkown,
};


pub const Token = struct {
    type: TokenType,
    value: []const u8,
    location: diagnostics.Location,


    pub fn init(t: TokenType, value: []const u8, location: diagnostics.Location) Token {
        return Token {
            .type = t,
            .value = value,
            .location = location,
        };
    }


    pub fn toString(self: Token) []const u8 {
        return switch (self.type) {
            .Intrinsic => "Intrinsic",
            .Keyword   => "Keyword",
            .Word      => "Word",
            .Number    => "Number",
            .String    => "String",
            .Character => "Character",
            .Unkown    => "Unkown",
        };
    }
};
