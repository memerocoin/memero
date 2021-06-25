#pragma once


namespace tools
{
  consteval uint64_t powerof(const uint64_t x, const uint64_t y) {
    if (x == 0) return 0;
    if (y == 0) return 1;
    return x * powerof(x, y - 1);
  }
}
