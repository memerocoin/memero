// Copyright (c) 2021, The Memero Project
// Copyright (c) 2014-2020, The Monero Project
//
// A minimal, non-custodial wallet JSON-RPC server for Memero.
//
// Exposes a small JSON-RPC API over HTTP (localhost by default) so that a
// desktop/mobile shell (Electron/Tauri/Capacitor) can drive the wallet while
// keeping keys strictly on the user's device.
//
// This is intentionally thin: it links wallet_api (wallet2) and calls the
// existing non-custodial wallet logic directly. Keys never leave the process.

#include "wallet/api/wallet2.h"
#include "wallet/mnemonics/electrum-words.h"
#include "network/rpc/rpc_args.h"
#include "config/lol.hpp"

#include <boost/beast/core.hpp>
#include <boost/beast/http.hpp>
#include <boost/beast/version.hpp>
#include <boost/asio.hpp>
#include <boost/program_options.hpp>

#include <nlohmann/json.hpp>

#include <iostream>
#include <memory>
#include <mutex>
#include <optional>
#include <string>

namespace beast = boost::beast;
namespace http = beast::http;
namespace asio = boost::asio;
using tcp = asio::ip::tcp;
using json = nlohmann::json;

namespace
{
  std::unique_ptr<tools::wallet2> g_wallet;
  std::mutex g_wallet_mutex;
  std::string g_daemon_address = "127.0.0.1:50709";

  // ============ wallet helpers ============

  std::string coin_to_str(uint64_t amount)
  {
    // COIN == 10^11
    constexpr uint64_t COIN = 100000000000ULL;
    std::string s = std::to_string(amount);
    if (s.size() <= 11)
      s = std::string(11 - s.size(), '0') + s;
    std::string out = s.substr(0, s.size() - 11) + "." + s.substr(s.size() - 11);
    while (!out.empty() && out.back() == '0') out.pop_back();
    if (!out.empty() && out.back() == '.') out.pop_back();
    return out.empty() ? "0" : out;
  }

  bool parse_amount(const std::string& s, uint64_t& out)
  {
    constexpr uint64_t COIN = 100000000000ULL;
    try {
      size_t dot = s.find('.');
      if (dot == std::string::npos) {
        out = std::stoull(s) * COIN;
        return true;
      }
      std::string whole = s.substr(0, dot);
      std::string frac = s.substr(dot + 1);
      if (frac.size() > 11) frac = frac.substr(0, 11);
      frac.append(11 - frac.size(), '0');
      out = std::stoull(whole) * COIN + std::stoull(frac);
      return true;
    } catch (...) { return false; }
  }

  json make_error(int code, const std::string& msg)
  {
    return {{"error", {{"code", code}, {"message", msg}}}};
  }

  json handle_create_wallet(const json& params)
  {
    std::string name = params.value("name", "default");
    std::string password = params.value("password", "");
    g_wallet = std::make_unique<tools::wallet2>();
    auto key = g_wallet->generate(name, epee::wipeable_string(password), std::nullopt);
    g_wallet->init(g_daemon_address);
    g_wallet->store();
    // address
    std::string addr = g_wallet->get_address_as_str();
    // seed
    epee::wipeable_string seed;
    g_wallet->get_seed(seed);
    std::string seed_str(seed.data(), seed.size());
    return {{"address", addr}, {"seed", seed_str}};
  }

  json handle_restore_wallet(const json& params)
  {
    std::string name = params.value("name", "default");
    std::string password = params.value("password", "");
    std::string seed = params.value("seed", "");
    crypto::secret_key recovery;
    std::string language;
    if (!crypto::ElectrumWords::words_to_bytes(epee::wipeable_string(seed), recovery, language))
      return make_error(-1, "invalid seed");
    g_wallet = std::make_unique<tools::wallet2>();
    g_wallet->generate(name, epee::wipeable_string(password), recovery);
    g_wallet->init(g_daemon_address);
    g_wallet->store();
    return {{"address", g_wallet->get_address_as_str()}};
  }

  json handle_load_wallet(const json& params)
  {
    std::string name = params.value("name", "default");
    std::string password = params.value("password", "");
    g_wallet = std::make_unique<tools::wallet2>();
    g_wallet->load(name, epee::wipeable_string(password));
    g_wallet->init(g_daemon_address);
    return {{"address", g_wallet->get_address_as_str()}};
  }

  json handle_get_address()
  {
    return {{"address", g_wallet->get_address_as_str()}};
  }

  json handle_get_balance()
  {
    uint64_t bal = g_wallet->balance_all(true);
    uint64_t unlocked = g_wallet->unlocked_balance_all(true);
    return {{"balance", coin_to_str(bal)}, {"unlocked_balance", coin_to_str(unlocked)}};
  }

  json handle_refresh()
  {
    g_wallet->refresh();
    g_wallet->store();
    return {{"status", "ok"}};
  }

  json handle_transfer(const json& params)
  {
    std::string address = params.value("address", "");
    std::string amount_str = params.value("amount", "");
    uint64_t amount;
    if (!parse_amount(amount_str, amount))
      return make_error(-2, "invalid amount");

    cryptonote::address_parse_info info;
    if (!cryptonote::get_account_address_from_str(info, cryptonote::MAINNET, address))
      return make_error(-3, "invalid address");

    std::vector<cryptonote::tx_destination_entry> dsts;
    cryptonote::tx_destination_entry de;
    de.addr = info.address;
    de.amount = amount;
    de.is_subaddress = info.is_subaddress;
    dsts.push_back(de);

    auto ptx = g_wallet->create_transactions(dsts, 0, 0, 0, {}, 0, {});
    g_wallet->commit_tx(ptx);
    g_wallet->store();
    if (ptx.empty())
      return make_error(-4, "failed to create transaction");
    return {{"txid", epee::string_tools::pod_to_hex(cryptonote::get_transaction_hash(ptx[0].tx))}};
  }

  json handle_get_seed()
  {
    epee::wipeable_string seed;
    g_wallet->get_seed(seed);
    return {{"seed", std::string(seed.data(), seed.size())}};
  }

  // ============ HTTP server ============

  void handle_request(http::request<http::string_body>& req, http::response<http::string_body>& res)
  {
    res.version(req.version());
    res.set(http::field::content_type, "application/json");
    res.set(http::field::server, "memero-wallet-rpc");

    if (req.method() != http::verb::post || req.target() != "/json_rpc") {
      res.result(http::status::not_found);
      res.body() = make_error(-32600, "not found").dump();
      res.prepare_payload();
      return;
    }

    json reqj;
    try { reqj = json::parse(req.body()); }
    catch (...) {
      res.result(http::status::bad_request);
      res.body() = make_error(-32700, "parse error").dump();
      res.prepare_payload();
      return;
    }

    std::string method = reqj.value("method", "");
    json params = reqj.value("params", json::object());
    json result;

    std::lock_guard<std::mutex> lock(g_wallet_mutex);
    try {
      if (!g_wallet && method != "create_wallet" && method != "restore_wallet" && method != "load_wallet")
        throw std::runtime_error("no wallet loaded");
      if (method == "create_wallet") result = handle_create_wallet(params);
      else if (method == "restore_wallet") result = handle_restore_wallet(params);
      else if (method == "load_wallet") result = handle_load_wallet(params);
      else if (method == "get_address") result = handle_get_address();
      else if (method == "get_balance") result = handle_get_balance();
      else if (method == "get_seed") result = handle_get_seed();
      else if (method == "refresh") result = handle_refresh();
      else if (method == "transfer") result = handle_transfer(params);
      else if (method == "get_version") result = {{"version", "0.1.0"}};
      else result = make_error(-32601, "unknown method: " + method);
    } catch (const std::exception& e) {
      result = make_error(-32000, e.what());
    }

    json out = {{"jsonrpc", "2.0"}, {"id", reqj.value("id", json())}, {"result", result}};
    if (result.contains("error"))
      out = {{"jsonrpc", "2.0"}, {"id", reqj.value("id", json())}, "error", result["error"]};

    res.result(http::status::ok);
    res.body() = out.dump();
    res.prepare_payload();
  }

  void do_session(tcp::socket socket)
  {
    try {
      beast::flat_buffer buffer;
      http::request<http::string_body> req;
      http::read(socket, buffer, req);
      http::response<http::string_body> res;
      handle_request(req, res);
      http::write(socket, res);
      socket.shutdown(tcp::socket::shutdown_send);
    } catch (const std::exception&) {
      // connection closed / error — ignore
    }
  }
}

int main(int argc, char** argv)
{
  namespace po = boost::program_options;
  po::options_description desc("memero-wallet-rpc options");
  desc.add_options()
    ("help", "produce help message")
    ("wallet-file", po::value<std::string>(), "wallet file to open")
    ("password", po::value<std::string>(), "wallet password")
    ("daemon-address", po::value<std::string>()->default_value("127.0.0.1:50709"), "daemon host:port")
    ("rpc-bind-ip", po::value<std::string>()->default_value("127.0.0.1"), "IP to bind RPC")
    ("rpc-bind-port", po::value<std::string>()->default_value("18082"), "RPC port");

  po::variables_map vm;
  po::store(po::parse_command_line(argc, argv, desc), vm);
  po::notify(vm);

  if (vm.count("help")) { std::cout << desc << std::endl; return 0; }

  if (vm.count("daemon-address"))
    g_daemon_address = vm["daemon-address"].as<std::string>();

  // optionally pre-load a wallet at startup
  if (vm.count("wallet-file")) {
    std::string password = vm.count("password") ? vm["password"].as<std::string>() : "";
    g_wallet = std::make_unique<tools::wallet2>();
    g_wallet->load(vm["wallet-file"].as<std::string>(), epee::wipeable_string(password));
    g_wallet->init(g_daemon_address);
  }

  std::string ip = vm["rpc-bind-ip"].as<std::string>();
  uint16_t port = std::stoi(vm["rpc-bind-port"].as<std::string>());

  asio::io_context ioc{1};
  tcp::acceptor acceptor{ioc, {asio::ip::make_address(ip), port}};
  std::cout << "memero-wallet-rpc listening on " << ip << ":" << port << std::endl;

  for (;;) {
    tcp::socket socket{ioc};
    acceptor.accept(socket);
    std::thread(do_session, std::move(socket)).detach();
  }

  return 0;
}
