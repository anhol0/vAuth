#pragma once

#include <cstdint>

class StoreGenerationCounter {
  public:
    virtual ~StoreGenerationCounter() = default;
    [[nodiscard]] virtual uint64_t read() = 0;
    virtual void increment() = 0;
};
