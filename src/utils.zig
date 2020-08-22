pub fn ceil(comptime T: type, numerator: T, denumerator: T) T {
    return 1 + (numerator - 1) / denumerator;
}
