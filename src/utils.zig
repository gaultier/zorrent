const std = @import("std");

pub fn divCeil(comptime T: type, numerator: T, denumerator: T) T {
    return 1 + (numerator - 1) / denumerator;
}

pub fn bitArraySet(array: []u8, index: usize) void {
    const byte = index / 8;
    std.debug.assert(byte < array.len);
    const bit: u3 = @intCast(u3, index % 8);
    const mask: u8 = @as(u8, 1) << bit;

    array[byte] |= mask;
}

pub fn bitArrayClear(array: []u8, index: usize) void {
    const byte = index / 8;
    std.debug.assert(byte < array.len);
    const bit: u3 = @intCast(u3, index % 8);
    const mask: u8 = @as(u8, 1) << bit;

    array[byte] &= ~mask;
}

pub fn bitArrayIsSet(array: []const u8, index: usize) bool {
    const byte = index / 8;
    std.debug.assert(byte < array.len);
    const bit: u3 = @intCast(u3, index % 8);
    const mask: u8 = @as(u8, 1) << bit;

    return (array[byte] & mask) != 0;
}

test "bitArraySet on pristine bitfield" {
    var bitArray = [3]u8{ 0, 0, 0 };
    bitArraySet(bitArray[0..], 6);

    std.testing.expectEqual(@as(u8, 0b0100_0000), bitArray[0]);
    std.testing.expectEqual(@as(u8, 0), bitArray[1]);
    std.testing.expectEqual(@as(u8, 0), bitArray[2]);
}

test "bitArraySet on non-zero bitfield" {
    var bitArray = [3]u8{ 0b0000_0101, 0b0000_0100, 0b0000_0111 };
    bitArraySet(bitArray[0..], 1);

    std.testing.expectEqual(@as(u8, 0b0000_0111), bitArray[0]);
    std.testing.expectEqual(@as(u8, 4), bitArray[1]);
    std.testing.expectEqual(@as(u8, 7), bitArray[2]);
}

test "bitArrayClear" {
    var bitArray = [3]u8{ 0b0000_0101, 0b0000_0100, 0b0000_0111 };
    bitArrayClear(bitArray[0..], 17);

    std.testing.expectEqual(@as(u8, 0b0000_0101), bitArray[0]);
    std.testing.expectEqual(@as(u8, 0b0000_0100), bitArray[1]);
    std.testing.expectEqual(@as(u8, 0b0000_0101), bitArray[2]);
}

test "bitArrayIsSet" {
    const bitArray = [3]u8{ 0b0000_0101, 0b0000_0100, 0b0000_0111 };

    std.testing.expectEqual(true, bitArrayIsSet(bitArray[0..], 0));
    std.testing.expectEqual(false, bitArrayIsSet(bitArray[0..], 1));
    std.testing.expectEqual(true, bitArrayIsSet(bitArray[0..], 2));
    std.testing.expectEqual(false, bitArrayIsSet(bitArray[0..], 3));
    std.testing.expectEqual(false, bitArrayIsSet(bitArray[0..], 4));
    std.testing.expectEqual(false, bitArrayIsSet(bitArray[0..], 5));
    std.testing.expectEqual(false, bitArrayIsSet(bitArray[0..], 6));
    std.testing.expectEqual(false, bitArrayIsSet(bitArray[0..], 7));
    std.testing.expectEqual(false, bitArrayIsSet(bitArray[0..], 8));
    std.testing.expectEqual(false, bitArrayIsSet(bitArray[0..], 9));
    std.testing.expectEqual(true, bitArrayIsSet(bitArray[0..], 10));
    std.testing.expectEqual(false, bitArrayIsSet(bitArray[0..], 11));
    std.testing.expectEqual(false, bitArrayIsSet(bitArray[0..], 12));
    std.testing.expectEqual(false, bitArrayIsSet(bitArray[0..], 13));
    std.testing.expectEqual(false, bitArrayIsSet(bitArray[0..], 14));
    std.testing.expectEqual(false, bitArrayIsSet(bitArray[0..], 15));
    std.testing.expectEqual(true, bitArrayIsSet(bitArray[0..], 16));
    std.testing.expectEqual(true, bitArrayIsSet(bitArray[0..], 17));
    std.testing.expectEqual(true, bitArrayIsSet(bitArray[0..], 18));
    std.testing.expectEqual(false, bitArrayIsSet(bitArray[0..], 19));
    std.testing.expectEqual(false, bitArrayIsSet(bitArray[0..], 20));
    std.testing.expectEqual(false, bitArrayIsSet(bitArray[0..], 21));
    std.testing.expectEqual(false, bitArrayIsSet(bitArray[0..], 22));
    std.testing.expectEqual(false, bitArrayIsSet(bitArray[0..], 23));
}
