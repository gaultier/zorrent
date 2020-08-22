pub fn ceil(comptime T: type, numerator: T, denumerator: T) T {
    return @floatToInt(T, std.math.ceil(f64, @intToFloat(f64, numerator) / @intToFloat(f64, denumerator)));
}
