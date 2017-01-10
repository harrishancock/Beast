//
// Copyright (c) 2016 Harris Hancock
//
// Distributed under the Boost Software License, Version 1.0. (See accompanying
// file LICENSE_1_0.txt or copy at http://www.boost.org/LICENSE_1_0.txt)
//

// Proof of concept implementation of `asio::read_until`'s string delimiter
// search functionality in terms of `asio::read`, which can operate on non-
// dynamic buffers.

#include <boost/asio.hpp>
#include <boost/convert.hpp>
#include <boost/convert/strtol.hpp>

#include <beast/core.hpp>

#include <algorithm>
#include <iostream>
#include <iterator>
#include <limits>
#include <string>

#include <cstdint>



template <class Iter>
struct until_delimiter_condition {
    Iter& cursor;
    const std::string delim;
    const size_t left_pad;
    size_t prev_n = 0;

    until_delimiter_condition(Iter& cursor, std::string delim, size_t left_pad)
        : cursor(cursor), delim(std::move(delim)), left_pad(left_pad) {}

    size_t operator()(const beast::error_code& ec, size_t n);
};

// Create a CompletionCondition suitable for use in a call to
// `asio::(async_)read`. The completion condition will halt the read
// operation when it sees the substring `delim` in the range:
//
//   [cursor_0 - left_pad, cursor_0 + n_i)
//
// where `cursor_0` is the initial value of `cursor` and `n_i` is the total
// number of bytes the read operation has read at any given time.
//
// `cursor` is an in/out parameter. It will be left pointing to either
// the first occurrence of `delim` in the range specified above, or to
// `cursor_0 + n`, where `n` is the final result of `asio::(async_)read`.
template <class Iter>
until_delimiter_condition<Iter>
until_delimiter(Iter& cursor, std::string delim, size_t left_pad = 0) {
    return {cursor, std::move(delim), left_pad};
}



struct boost::cnv::by_default: boost::cnv::strtol {};  // for boost::convert

int main (int argc, char** argv) {
    const auto usage = "read-until-delim <port> <header buffer size> <body buffer size>\n";

    if (argc < 4) {
        std::cerr << usage;
        return 1;
    }

    auto port = boost::convert<int>(argv[1]).value_or(-1);
    auto header_buf_size = boost::convert<int>(argv[2]).value_or(-1);
    auto body_buf_size = boost::convert<int>(argv[3]).value_or(-1);

    if (port < 1 || port > std::numeric_limits<uint16_t>::max()
            || header_buf_size < 0
            || body_buf_size < 0) {
        std::cerr << usage;
        return 1;
    }


    namespace asio = boost::asio;

    // Set up our socket.
    asio::io_service ios;
    const auto server_ep = asio::ip::tcp::endpoint{
            asio::ip::address::from_string("127.0.0.1"), uint16_t(port)};
    boost::asio::ip::tcp::endpoint client_ep;
    auto acceptor = asio::ip::tcp::acceptor{ios, server_ep};

    std::cout << "Listening on port " << port
            << " with header buffer size " << header_buf_size
            << ", body buffer size " << body_buf_size << '\n';

    auto s = asio::ip::tcp::socket{ios};
    acceptor.accept(s, client_ep);

    std::cout << "Accepted connection from " << client_ep << '\n';


    // PART ONE: Reading the header into a contiguous buffer.
    // ======================================================

    const auto header_delim = std::string("\r\n\r\n");

    // Set up our buffer and other args for the read call.
    auto header_vec = std::vector<char>(header_buf_size);
    auto header_buf = asio::buffer(header_vec);

    const auto header_cursor_0 = asio::buffers_begin(header_buf);
    auto header_cursor = header_cursor_0;

    auto ec = beast::error_code{};

    // Make a single call to read. It will stop once it sees the header delimiter.
    auto n = asio::read(s, header_buf,
            until_delimiter(header_cursor, header_delim), ec);
    std::cout << "\nRead " << n << " bytes\n";

    if (ec && ec != asio::error::eof) {
        std::cout << "IO error: " << ec.message() << '\n';
    }

    if (header_cursor == header_cursor_0 + n) {
        std::cout << "Never saw CRLF CRLF\n";
        if (n == asio::buffer_size(header_buf)) {
            std::cout << "Buffer overflow reading header\n";
        }
        return 0;
    }

    // Slurp the header delimiter.
    header_cursor += header_delim.size();

    // Calculate header and body prefix sub-buffers.
    auto header_size = std::distance(header_cursor_0, header_cursor);
    auto body_prefix_size = n - header_size;

    auto header = asio::buffer(header_buf, header_size);
    auto body_prefix = asio::buffer(header_buf + header_size, body_prefix_size);

    // Display.
    const auto rule = "--------------------\n";
    std::cout << "\nHEADER IS " << header_size << " BYTES:\n" << rule;
    std::cout << beast::to_string(header) << '\n' << rule;

    std::cout << "BODY PREFIX IS " << body_prefix_size << " BYTES:\n" << rule;
    std::cout << beast::to_string(body_prefix) << '\n' << rule;


    // PART TWO: Reading the body suffix into a second buffer,
    // while pattern matching across discontiguous buffers.
    // ======================================================

    // I'm not going to actually parse the header, so to detect the end of
    // the body, I'll just look for a magic substring.
    const auto body_delim = std::string("01234567890123456789");

    if (!until_delimiter(header_cursor, body_delim)({}, body_prefix_size)) {
        std::cout << "Body prefix IS the body. Done.\n";
        return 0;
    }

    // Our second read will be backed by a second buffer ...
    auto body_suffix_vec = std::vector<char>(body_buf_size);
    auto body_suffix_buf = asio::buffer(body_suffix_vec);

    // ... but our completion condition needs a cursor that can access the
    // first buffer.
    auto body_buf = beast::buffer_cat(body_prefix, body_suffix_buf);
    const auto body_cursor_0 = asio::buffers_begin(body_buf) + body_prefix_size;
    auto body_cursor = body_cursor_0;

    // Make a single call to read. It will stop once it sees the body delimiter,
    // even if that delimiter straddles the boundary between the header
    // buffer and the body buffer.
    n = asio::read(s, body_suffix_buf,
            until_delimiter(body_cursor, body_delim, body_prefix_size), ec);
    std::cout << "\nRead " << n << " bytes\n";

    if (ec && ec != asio::error::eof) {
        std::cout << "IO error: " << ec.message() << '\n';
    }

    if (body_cursor == body_cursor_0 + n) {
        std::cout << "Never saw " << body_delim << '\n';
        if (n == asio::buffer_size(body_suffix_buf)) {
            std::cout << "Buffer overflow reading body\n";
        }
        return 0;
    }

    // Slurp the body delimiter.
    body_cursor += body_delim.size();

    // Calculate the buffer sequence containing the full body and any overread.
    auto body_suffix_size = std::distance(body_cursor_0, body_cursor);
    auto full_body_size = body_prefix_size + body_suffix_size;
    auto full_body = beast::prepare_buffers(full_body_size, body_buf);

    auto overread_size = n - body_suffix_size;
    auto overread = asio::buffer(body_suffix_buf + body_suffix_size, overread_size);

    // Display.
    std::cout << "\nFULL BODY IS " << full_body_size << " BYTES:\n" << rule;
    std::cout << beast::to_string(full_body) << '\n' << rule;

    if (overread_size) {
        // This shouldn't happen unless you put something in the body after
        // the magic body delimiter.
        std::cout << "OVERREAD IS " << overread_size << " BYTES:\n" << rule;
        std::cout << beast::to_string(overread) << '\n' << rule;
    }

    return 0;
}



template <class Iter>
size_t
until_delimiter_condition<Iter>::
operator()(const beast::error_code& ec, size_t n) {
    // Backtrack at least the length of our delimiter minus one, so we
    // can find the delimiter if we read part of it on the last call.
    // Clamp if this would take us past the leftmost limit of the buffer.
    auto first = cursor - (std::min)(delim.size() - 1, prev_n + left_pad);
    auto last = cursor + (n - prev_n);
    prev_n = n;

    // TODO: Naive! Benchmark against Boost.Algorithm.
    cursor = std::search(first, last, delim.begin(), delim.end());
    if (cursor != last) {
        // Match
        return 0;
    }

    // No match, keep reading. Return 1 here to test that the backtracking
    // logic above holds water.
    return boost::asio::transfer_all()(ec, n);
}
