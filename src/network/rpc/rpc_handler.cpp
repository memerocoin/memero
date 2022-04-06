
#include "cryptonote/core/cryptonote_core.h"



namespace cryptonote
{
namespace rpc
{
  namespace
  {
    output_distribution_data
      process_distribution(bool cumulative, std::uint64_t start_height, std::vector<std::uint64_t> distribution, std::uint64_t base)
    {
      if (!cumulative && !distribution.empty())
      {
        for (std::size_t n = distribution.size() - 1; 0 < n; --n)
          distribution[n] -= distribution[n - 1];
        distribution[0] -= base;
      }

      return {std::move(distribution), start_height, base};
    }
  }

  std::optional<output_distribution_data>
    RpcHandler::get_output_distribution(const std::function<bool(uint64_t, uint64_t, uint64_t, uint64_t&, std::vector<uint64_t>&, uint64_t&)> &f, uint64_t amount, uint64_t from_height, uint64_t to_height, bool cumulative)
  {
      std::vector<std::uint64_t> distribution;
      std::uint64_t start_height, base;

      if (!f(amount, from_height, to_height, start_height, distribution, base)) {
        return {};
      }

      return process_distribution(cumulative, start_height, std::move(distribution), base);
  }
} // rpc
} // cryptonote
