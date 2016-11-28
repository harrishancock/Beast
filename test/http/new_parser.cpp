//
// Copyright (c) 2013-2016 Vinnie Falco (vinnie dot falco at gmail dot com)
//
// Distributed under the Boost Software License, Version 1.0. (See accompanying
// file LICENSE_1_0.txt or copy at http://www.boost.org/LICENSE_1_0.txt)
//

#include <beast/unit_test/suite.hpp>
#include <beast/test/string_stream.hpp>
#include <beast/test/yield_to.hpp>

#include <beast/core/error.hpp>
#include <beast/http/fields.hpp>
#include <beast/http/message.hpp>
#include <beast/http/rfc7230.hpp>
#include <beast/http/string_body.hpp>
#include <beast/core/detail/ci_char_traits.hpp>
#include <beast/core/detail/clamp.hpp>
#include <beast/core/detail/type_traits.hpp>
#include <boost/algorithm/searching/boyer_moore.hpp>
#include <boost/version.hpp>
#include <algorithm>

namespace beast {
namespace http {

enum class error
{
    /** More input is necessary to continue parsing.
    */
    need_more = 1,

    /// The method is invalid.
    bad_method,

    /// The request-target is invalid.
    bad_path,

    /// The HTTP-version is invalid.
    bad_version,

    /// The status-code is invalid.
    bad_status,

    /// The reason-phrase is invalid.
    bad_reason,

    /// The field name is invalid.
    bad_field,

    /// The field value is invalid.
    bad_value,

    /// The Content-Length is invalid.
    bad_content_length,

    /// The Transfer-Encoding is invalid.
    bad_transfer_encoding,

    /// The chunk size is invalid.
    bad_chunk_size,

    /// The chunk extension is invalid.
    bad_chunk_extension,

    /// The chunk data is invalid.
    bad_chunk_data,

    /// Unexpected end of message
    short_read
};

} // http
} // beast

namespace boost {
namespace system {
template<>
struct is_error_code_enum<beast::http::error>
{
    static bool const value = true;
};
} // system
} // boost

namespace beast {
namespace http {

namespace detail {

class http_error_category : public error_category
{
public:
    const char*
    name() const noexcept override
    {
        return "http";
    }

    std::string
    message(int ev) const override
    {
        switch(static_cast<error>(ev))
        {
        default:
        case error::need_more: return "more input needed";
        case error::bad_method: return "bad method";
        case error::bad_path: return "bad path";
        case error::bad_version: return "bad version";
        case error::bad_status: return "bad status";
        case error::bad_reason: return "bad reason";
        case error::bad_field: return "bad field";
        case error::bad_value: return "bad value";
        case error::bad_content_length: return "bad Content-Length";
        case error::bad_transfer_encoding: return "bad Transfer-Encoding";
        case error::bad_chunk_size: return "bad chunk size";
        case error::bad_chunk_extension: return "bad chunk extension";
        case error::bad_chunk_data: return "bad chunk data";
        case error::short_read: return "unexpected end of message";
        }
    }

    error_condition
    default_error_condition(int ev) const noexcept override
    {
        return error_condition{ev, *this};
    }

    bool
    equivalent(int ev,
        error_condition const& condition
            ) const noexcept override
    {
        return condition.value() == ev &&
            &condition.category() == this;
    }

    bool
    equivalent(error_code const& error, int ev) const noexcept override
    {
        return error.value() == ev &&
            &error.category() == this;
    }
};

inline
error_category const&
get_http_error_category()
{
    static http_error_category const cat{};
    return cat;
}

} // detail

inline
error_code
make_error_code(error ev)
{
    return error_code{
        static_cast<std::underlying_type<error>::type>(ev),
            detail::get_http_error_category()};
}

//------------------------------------------------------------------------------

class parse_buffer
{
    std::size_t pos_ = 0;
    std::size_t len_ = 0;
    std::size_t cap_ = 0;
    std::unique_ptr<std::uint8_t[]> p_;

public:
    using buffers_type =
        boost::asio::mutable_buffers_1;

    std::size_t
    size() const
    {
        return len_;
    }

    buffers_type
    data()
    {
        return {p_.get() + pos_, len_};
    }

    buffers_type
    prepare(std::size_t n)
    {
        if(n < 1)
            n = 1;
        if(cap_ < pos_ + len_ + n)
        {
            if(cap_ >= len_ + n)
            {
                std::memmove(
                    p_.get(), p_.get() + pos_, len_);
                pos_ = 0;
                return {p_.get() + len_, n};
            }

            std::unique_ptr<std::uint8_t[]> p;
            p.reset(new std::uint8_t[len_ + n]);
            std::memcpy(p.get(), p_.get() + pos_, len_);
            std::swap(p, p_);
            pos_ = 0;
            cap_ = len_ + n;
            return {p_.get() + len_, n};
        }
        return {p_.get() + pos_ + len_, n};
    }

    void
    commit(std::size_t n)
    {
        len_ += beast::detail::clamp(
            n, cap_ - (pos_ + len_));
    }

    void
    consume(std::size_t n)
    {
        if(n < len_)
        {
            pos_ += n;
            len_ -= n;
            return;
        }
        pos_ = 0;
        len_ = 0;
    }
};

//------------------------------------------------------------------------------

struct new_basic_parser_v1_base
{
    // any OCTET except CTLs and LWS
    static
    inline
    bool
    is_value_char(char c)
    {
        static std::array<bool, 256> constexpr tab = {{
            0, 0, 0, 0,  0, 0, 0, 0,  0, 0, 0, 0,  0, 0, 0, 0, // 0
            0, 0, 0, 0,  0, 0, 0, 0,  0, 0, 0, 0,  0, 0, 0, 0, // 16
            0, 1, 1, 1,  1, 1, 1, 1,  1, 1, 1, 1,  1, 1, 1, 1, // 32
            1, 1, 1, 1,  1, 1, 1, 1,  1, 1, 1, 1,  1, 1, 1, 1, // 48
            1, 1, 1, 1,  1, 1, 1, 1,  1, 1, 1, 1,  1, 1, 1, 1, // 64
            1, 1, 1, 1,  1, 1, 1, 1,  1, 1, 1, 1,  1, 1, 1, 1, // 80
            1, 1, 1, 1,  1, 1, 1, 1,  1, 1, 1, 1,  1, 1, 1, 1, // 96
            1, 1, 1, 1,  1, 1, 1, 1,  1, 1, 1, 1,  1, 1, 1, 0, // 112
            1, 1, 1, 1,  1, 1, 1, 1,  1, 1, 1, 1,  1, 1, 1, 1, // 128
            1, 1, 1, 1,  1, 1, 1, 1,  1, 1, 1, 1,  1, 1, 1, 1, // 144
            1, 1, 1, 1,  1, 1, 1, 1,  1, 1, 1, 1,  1, 1, 1, 1, // 160
            1, 1, 1, 1,  1, 1, 1, 1,  1, 1, 1, 1,  1, 1, 1, 1, // 176
            1, 1, 1, 1,  1, 1, 1, 1,  1, 1, 1, 1,  1, 1, 1, 1, // 192
            1, 1, 1, 1,  1, 1, 1, 1,  1, 1, 1, 1,  1, 1, 1, 1, // 208
            1, 1, 1, 1,  1, 1, 1, 1,  1, 1, 1, 1,  1, 1, 1, 1, // 224
            1, 1, 1, 1,  1, 1, 1, 1,  1, 1, 1, 1,  1, 1, 1, 1  // 240
        }};
        return tab[static_cast<std::uint8_t>(c)];
    }
};

template<class Unsigned>
bool
parse_dec(char const* it, char const* last, Unsigned& v)
{
    if(! detail::is_digit(*it))
        return false;
    v = *it - '0';
    for(;;)
    {
        if(! detail::is_digit(*++it))
            break;
        auto const d = *it - '0';
        if(v > ((std::numeric_limits<
                Unsigned>::max)() - 10) / 10)
            return false;
        v = 10 * v + d;
    }
    return true;
}

template<class Unsigned>
bool
parse_hex(char const*& it, Unsigned& v)
{
    auto d = detail::unhex(*it);
    if(d == -1)
        return false;
    v = d;
    for(;;)
    {
        d = detail::unhex(*++it);
        if(d == -1)
            break;
        if(v > ((std::numeric_limits<
                Unsigned>::max)() - 16) / 16)
            return false;
        v = 16 * v + d;
    }
    return true;
}

template<bool isRequest, class Derived>
class new_basic_parser_v1 : private new_basic_parser_v1_base
{
    static unsigned constexpr flagContentLength = 1;
    static unsigned constexpr flagChunked = 2;
    static unsigned constexpr flagUpgrade = 4;
    static unsigned constexpr flagHeader = 8;
    static unsigned constexpr flagComplete = 16;
    static unsigned constexpr flagNextChunk = 32;
    static unsigned constexpr flagFinalChunk = 64;
    static unsigned constexpr flagSkipBody = 128;

    std::uint64_t length_;
    std::size_t skip_ = 0; // this could be a std::uint32_t
    std::uint8_t f_ = 0;

public:
    /** Returns `true` if a complete message has been received.
    */
    bool
    complete() const
    {
        return f_ & flagComplete;
    }

    /** Returns the optional value of Content-Length if known.

        The return value is undefined until `on_header` is called.
    */
    boost::optional<std::uint64_t>
    content_length() const
    {
        if(! (f_ & flagContentLength))
            return boost::none;
        return length_;
    }

    /** Returns `true` if the message body is chunk encoded.

        The return value is undefined until `on_header` is called.
    */
    bool
    chunked() const
    {
        return f_ & flagChunked;
    }

    /** Returns the number of body bytes remaining in this chunk.
    */
    std::uint64_t
    remain() const
    {
        if(f_ & (flagContentLength | flagChunked))
            return length_;
        return 65536;
    }

    /** Returns `true` if eof is needed to determine the end of message.
    */
    bool
    needs_eof() const
    {
        return ! (f_ & (flagChunked + flagContentLength));
    }

    template<class ParseBuffer>
    void
    write(ParseBuffer& buffer, error_code& ec)
    {
        if(! (f_ & flagHeader))
            return parse_header(buffer, ec);
        if(! (f_ & flagChunked))
            return;
        parse_chunked(buffer, ec);
    }

    /** Indicate that the end of stream is reached.
    */
    void
    write_eof(error_code& ec)
    {
        if(f_ & (flagContentLength | flagChunked))
        {
            if(! (f_ & flagComplete))
            {
                ec = error::short_read;
                return;
            }
        }
        else
        {
            f_ |= flagComplete;
        }
    }

    /** Transfer body octets from buffer to the reader
    */
    template<class Reader, class ParseBuffer>
    void
    write_body(Reader& r, ParseBuffer& buffer, error_code& ec)
    {
        using boost::asio::buffer_copy;
        auto const n = beast::detail::clamp(
            length_,  buffer.size());
        auto const b = r.prepare(n, ec);
        if(ec)
            return;
        auto const len = buffer_copy(
            b, buffer.data(), n);
        r.commit(len, ec);
        if(ec)
            return;
        buffer.consume(len);
        if(f_ & flagContentLength)
        {
            length_ -= len;
            if(length_ == 0)
                f_ |= flagComplete;
        }
        else if(f_ & flagChunked)
        {
            length_ -= len;
        }
    }

    /** Consume body bytes from the current chunk.
    */
    void
    consume(std::uint64_t n)
    {
        length_ -= n;
    }

private:
    template<class T, class = beast::detail::void_t<>>
    struct check_on_method : std::false_type {};

    template<class T>
    struct check_on_method<T, beast::detail::void_t<decltype(
        //std::declval<T>().on_method()
        std::declval<int>()
            )>> : std::true_type {};

    static_assert(check_on_method<Derived>::value,
        "Missing void Derived::on_method(boost::string_ref, error_code&)");

    inline
    Derived&
    impl()
    {
        return *static_cast<Derived*>(this);
    }

    static
    inline
    boost::string_ref
    str(char const* first, char const* last)
    {
        return {first, static_cast<
            std::size_t>(last - first)};
    }

    static
    inline
    bool
    is_print(char c)
    {
        return static_cast<unsigned char>(c-33) < 94;
    }

    static
    inline
    bool
    is_pathchar(char c)
    {
        // TEXT = <any OCTET except CTLs, and excluding LWS>
        static std::array<char, 256> constexpr tab = {{
            0, 0, 0, 0,  0, 0, 0, 0,  0, 0, 0, 0,  0, 0, 0, 0, // 0
            0, 0, 0, 0,  0, 0, 0, 0,  0, 0, 0, 0,  0, 0, 0, 0, // 16
            0, 1, 1, 1,  1, 1, 1, 1,  1, 1, 1, 1,  1, 1, 1, 1, // 32
            1, 1, 1, 1,  1, 1, 1, 1,  1, 1, 1, 1,  1, 1, 1, 1, // 48
            1, 1, 1, 1,  1, 1, 1, 1,  1, 1, 1, 1,  1, 1, 1, 1, // 64
            1, 1, 1, 1,  1, 1, 1, 1,  1, 1, 1, 1,  1, 1, 1, 1, // 80
            1, 1, 1, 1,  1, 1, 1, 1,  1, 1, 1, 1,  1, 1, 1, 1, // 96
            1, 1, 1, 1,  1, 1, 1, 1,  1, 1, 1, 1,  1, 1, 1, 0, // 112
            1, 1, 1, 1,  1, 1, 1, 1,  1, 1, 1, 1,  1, 1, 1, 1, // 128
            1, 1, 1, 1,  1, 1, 1, 1,  1, 1, 1, 1,  1, 1, 1, 1, // 144
            1, 1, 1, 1,  1, 1, 1, 1,  1, 1, 1, 1,  1, 1, 1, 1, // 160
            1, 1, 1, 1,  1, 1, 1, 1,  1, 1, 1, 1,  1, 1, 1, 1, // 176
            1, 1, 1, 1,  1, 1, 1, 1,  1, 1, 1, 1,  1, 1, 1, 1, // 192
            1, 1, 1, 1,  1, 1, 1, 1,  1, 1, 1, 1,  1, 1, 1, 1, // 208
            1, 1, 1, 1,  1, 1, 1, 1,  1, 1, 1, 1,  1, 1, 1, 1, // 224
            1, 1, 1, 1,  1, 1, 1, 1,  1, 1, 1, 1,  1, 1, 1, 1  // 240
        }};
        return tab[static_cast<std::uint8_t>(c)] != 0;
    }

    static
    std::pair<char const*, char const*>
    find_crlf(
        char const* first, char const* last)
    {
        static char const pat[] = "\r\n";
        static boost::algorithm::boyer_moore<
            char const*> const bm(pat, pat+2);
    #if BOOST_VERSION >= 106200
        return bm(first, last);
    #else
        auto const it = bm(first, last);
        return {it, it+2};
    #endif
    }

    static
    std::pair<char const*, char const*>
    find_2x_crlf(
        char const* first, char const* last)
    {
        static char const pat[] = "\r\n\r\n";
        static boost::algorithm::boyer_moore<
            char const*> const bm(pat, pat+4);
    #if BOOST_VERSION >= 106200
        return bm(first, last);
    #else
        auto const it = bm(first, last);
        return {it, it+2};
    #endif
    }

    static
    bool
    get_crlf(char const*& it)
    {
        if(*it != '\r')
            return false;
        if(*++it != '\n')
            return false;
        ++it;
        return true;
    }

    template<class F>
    static
    std::pair<char const*, char const*>
    get_token(char const*& it, F const& f)
    {
        auto const first = it;
        while(f(*it))
            ++it;
        if(*it != ' ')
            return { it, it };
        return { first, it };
    }

    static
    int
    get_version(char const*& it)
    {
        if(*it != 'H')
            return -1;
        if(*++it != 'T')
            return -1;
        if(*++it != 'T')
            return -1;
        if(*++it != 'P')
            return -1;
        if(*++it != '/')
            return -1;
        if(! detail::is_digit(*++it))
            return -1;
        int v = 10 * (*it - '0');
        if(*++it != '.')
            return -1;
        if(! detail::is_digit(*++it))
            return -1;
        v += *it++ - '0';
        return v;
    }

    static
    int
    get_status(char const*& it)
    {
        int v;
        if(! detail::is_digit(*it))
            return -1;
        v = 100 * (*it - '0');
        if(! detail::is_digit(*++it))
            return -1;
        v += 10 * (*it - '0');
        if(! detail::is_digit(*++it))
            return -1;
        v += (*it++ - '0');
        return v;
    }
    
    static
    boost::string_ref
    get_reason(char const*& it)
    {
        auto const first = it;
        while(*it != '\r')
        {
            if(! detail::is_text(*it))
                return {};
            ++it;
        }
        return {first, static_cast<
            std::size_t>(it - first)};
    }

    void
    parse_startline(char const*& it,
        error_code& ec, std::true_type)
    {
        // method
        {
            auto const t = get_token(it, &detail::is_tchar);
            if(t.first == t.second)
            {
                ec = error::bad_method;
                return;
            }
            impl().on_method(str(t.first, t.second), ec);
            if(ec)
                return;
            it = t.second + 1;
        }

        // path
        {
            auto const t = get_token(it, &is_pathchar);
            if(t.first == t.second)
            {
                ec = error::bad_path;
                return;
            }
            impl().on_path(str(t.first, t.second), ec);
            if(ec)
                return;
            it = t.second + 1;
        }

        // version
        auto const v = get_version(it);
        if(v < 0 || ! get_crlf(it))
        {
            ec = error::bad_version;
            return;
        }
        impl().on_version(v, ec);
        if(ec)
            return;
    }

    void
    parse_startline(char const*& it,
        error_code& ec, std::false_type)
    {
        // version
        {
            auto const v = get_version(it);
            if(v < 0 || *it != ' ')
            {
                ec = error::bad_version;
                return;
            }
            impl().on_version(v, ec);
            if(ec)
                return;
            ++it;
        }

        // status
        {
            auto const s = get_status(it);
            if( s < 0 || *it != ' ')
            {
                ec = error::bad_status;
                return;
            }
            impl().on_status(s, ec);
            if(ec)
                return;
            ++it;
        }

        // reason
        {
            auto const r = get_reason(it);
            if(r.empty() || ! get_crlf(it))
            {
                ec = error::bad_reason;
                return;
            }
            impl().on_reason(r, ec);
            if(ec)
                return;
        }
    }

    void
    parse_fields(char const*& it, error_code& ec)
    {
        for(;;)
        {
            if(*it == '\r')
            {
                if(*++it != '\n')
                {
                    ec = error::bad_field;
                    return;
                }
                ++it;
                return;
            }
            auto first = it;
            boost::string_ref name;
            for(;;)
            {
                if(*it == ':')
                {
                    name = str(first, it++);
                    break;
                }
                if(! detail::to_field_char(*it))
                {
                    ec = error::bad_field;
                    return;
                }
                ++it;
            }
            while(*it == ' ' || *it == '\t')
                ++it;
            first = it;
            auto last = it;
            for(;;)
            {
                if(*it == '\r')
                {
                    if(*++it != '\n')
                    {
                        ec = error::bad_field;
                        return;
                    }
                    ++it;
                    break;
                }
                if(is_value_char(*it))
                {
                    last = ++it;
                }
                else if(*it == ' ' || *it == '\t')
                {
                    ++it;
                }
                else
                {
                    ec = error::bad_value;
                    return;
                }
            }
            auto const value = str(first, last);
            handle_field(name, value, ec);
            if(ec)
                return;
            impl().on_field(name, str(first, last), ec);
            if(ec)
                return;
        }
    }

    void
    handle_field(boost::string_ref name, boost::string_ref value,
        error_code& ec)
    {
        // Content-Length
        if(beast::detail::ci_equal(name, "Content-Length"))
        {
            if(f_ & flagChunked)
            {
                ec = error::bad_content_length;
                return;
            }

            if(f_ & flagContentLength)
            {
                ec = error::bad_content_length;
                return;
            }

            std::uint64_t v;
            if(! parse_dec(value.begin(), value.end(), v))
            {
                ec = error::bad_content_length;
                return;
            }
            length_ = v;
            f_ |= flagContentLength;
            return;
        }

        // Connection
        if(beast::detail::ci_equal(name, "Connection"))
        {
            ec = {};
            return;
        }

        // Transfer-Encoding
        if(beast::detail::ci_equal(name, "Transfer-Encoding"))
        {
            if(f_ & flagContentLength)
            {
                ec = error::bad_transfer_encoding;
                return;
            }

            if(f_ & flagChunked)
            {
                ec = error::bad_transfer_encoding;
                return;
            }

            auto const v = token_list{value};
            auto const it = std::find_if(v.begin(), v.end(),
                [&](typename token_list::value_type const& s)
                {
                    return beast::detail::ci_equal(s, "chunked");
                });
            if(std::next(it) != v.end())
            {
                ec = error::bad_transfer_encoding;
                return;
            }
            f_ |= flagChunked;
            return;
        }
        if(beast::detail::ci_equal(name, "Upgrade"))
        {
            ec = {};
            return;
        }
        if(beast::detail::ci_equal(name, "Proxy-Connection"))
        {
            ec = {};
            return;
        }
    }

    template<class ParseBuffer>
    void
    parse_header(ParseBuffer& buffer, error_code& ec)
    {
        using boost::asio::buffer_cast;
        auto const n = buffer.size();
        auto const first = buffer_cast<char const*>(buffer.data());
        auto const last = first + n;
        auto const result = find_2x_crlf(first + skip_, last);
        if(result.first == last)
        {
            if(n)
                skip_ = n - 3;
            ec = error::need_more;
            return;
        }
        skip_ = 0;

        auto it = first;
        parse_startline(it, ec,
            std::integral_constant<bool, isRequest>{});
        if(ec)
            return;
        parse_fields(it, ec);
        if(ec)
            return;
        if(it != result.second)
        {
            ec = error::bad_value;
            return;
        }
        impl().on_header(ec);
        if(ec)
            return;
        buffer.consume(static_cast<
            std::size_t>(result.second - first));
        f_ |= flagHeader;
    }

    template<class ParseBuffer>
    void
    parse_chunked(
        ParseBuffer& buffer, error_code& ec)
    {
    /*
        chunked-body   = *chunk
                         last-chunk
                         trailer-part
                         CRLF

        chunk          = chunk-size [ chunk-ext ] CRLF
                         chunk-data CRLF
        chunk-size     = 1*HEXDIG
        last-chunk     = 1*("0") [ chunk-ext ] CRLF

        chunk-data     = 1*OCTET ; a sequence of chunk-size octets

        5;x=1;y=z\r\n

            <size> *(;<ext>) CRLF<data>CRLF
        
        CRLF<size> *(;<ext>) CRLF<data>CRLF

             1*("0") *(;<ext>) CRLF *(<trailer>CRLF) CRLF

        CRLF 1*("0") *(;<ext>) CRLF *(<trailer>CRLF) CRLF
    */

        using boost::asio::buffer_cast;
        if(f_ & flagNextChunk)
        {
            BOOST_ASSERT(skip_ == 0);
            auto const n = buffer.size();
            if(n < 2)
            {
                ec = error::need_more;
                return;
            }
            auto it = buffer_cast<
                char const*>(buffer.data());
            if(! get_crlf(it))
            {
                ec = error::bad_chunk_data;
                return;
            }
            buffer.consume(2);
            f_ &= ~flagNextChunk;
        }

        if(! (f_ & flagFinalChunk))
        {
            auto const n = buffer.size();
            auto const first = buffer_cast<
                char const*>(buffer.data());
            auto const last = first + n;
            auto const m =
                find_crlf(first + skip_, last);
            if(m.first == last)
            {
                if(n > 1)
                    skip_ = n - 1;
                ec = error::need_more;
                return;
            }

            auto it = first;
            std::uint64_t v;
            if(! parse_hex(it, v))
            {
                ec = error::bad_chunk_size;
                return;
            }
            skip_ = 0;

            if(v != 0)
            {
                if(*it == '\r')
                {
                    if(*++it != '\n')
                    {
                        ec = error::bad_chunk_size;
                        return;
                    }
                }
                else if(*it == ';')
                {
                    impl().on_chunk_extension(str(it, m.first), ec);
                    if(ec)
                        return;

                }
                else if(! get_crlf(it))
                {
                    ec = error::bad_chunk_size;
                    return;
                }
                length_ = v;
                f_ |= flagNextChunk;
                buffer.consume(static_cast<
                    std::size_t>(m.second - first));
            }
            else
            {
                buffer.consume(static_cast<
                    std::size_t>(it - first));
                f_ |= flagFinalChunk;
                goto final_chunk;
            }
        }
        else
        {
        final_chunk:
            auto const n = buffer.size();
            auto const first = buffer_cast<
                char const*>(buffer.data());
            auto const last = first + n;
            auto const m =
                find_2x_crlf(first + skip_, last);
            if(m.first == last)
            {
                if(n > 3)
                    skip_ = n - 3;
                ec = error::need_more;
                return;
            }

            auto it = first;
            if(*it == '\r')
            {
                if(*++it != '\n')
                {
                    ec = error::bad_chunk_size;
                    return;
                }
            }
            else if(*it == ';')
            {
                impl().on_chunk_extension(str(it, m.first), ec);
                if(ec)
                    return;

            }
            f_ |= flagComplete;
        }
    }
};

//------------------------------------------------------------------------------

template<bool isRequest, class Body, class Fields>
class new_parser_v1
    : public new_basic_parser_v1<isRequest,
        new_parser_v1<isRequest, Body, Fields>>
{
    message<isRequest, Body, Fields> m_;

public:
    /// The type of message this parser produces.
    using message_type =
        message<isRequest, Body, Fields>;

    /// Default constructor
    new_parser_v1() = default;

    /// Copy constructor (disallowed)
    new_parser_v1(new_parser_v1 const&) = delete;

    /// Move assignment (disallowed)
    new_parser_v1& operator=(new_parser_v1&&) = delete;

    /// Copy assignment (disallowed)
    new_parser_v1& operator=(new_parser_v1 const&) = delete;

    /** Returns the parsed message.

        Only valid if @ref complete would return `true`.
    */
    message_type const&
    get() const
    {
        return m_;
    }

    /** Returns the parsed message.

        Only valid if @ref complete would return `true`.
    */
    message_type&
    get()
    {
        return m_;
    }

    /** Returns ownership of the parsed message.

        Ownership is transferred to the caller. Only
        valid if @ref complete would return `true`.

        Requires:
            `message<isRequest, Body, Fields>` is @b MoveConstructible
    */
    message_type
    release()
    {
        static_assert(std::is_move_constructible<decltype(m_)>::value,
            "MoveConstructible requirements not met");
        return std::move(m_);
    }

private:
    friend class new_basic_parser_v1<isRequest, new_parser_v1>;

    void
    on_version(int v, error_code& ec)
    {
        m_.version = v;
    }

    void
    on_method(boost::string_ref const& s, error_code& ec)
    {
        m_.method = std::string(s.data(), s.size());
    }

    void
    on_path(boost::string_ref const& s, error_code& ec)
    {
        m_.url = std::string(s.data(), s.size());
    }

    void
    on_status(int s, error_code& ec)
    {
        m_.status = s;
    }

    void
    on_reason(boost::string_ref const& s, error_code& ec)
    {
        m_.reason = std::string(s.data(), s.size());
    }

    void
    on_field(boost::string_ref const& name, boost::string_ref value,
        error_code& ec)
    {
        m_.fields.insert(name, value);
    }

    void
    on_header(error_code& ec)
    {
    }

    void
    on_chunk_extension(boost::string_ref const& s, error_code& ec)
    {
    }
};

//------------------------------------------------------------------------------

struct str_body
{
    using value_type = std::string;

    class reader
    {
        std::size_t len_ = 0;
        value_type& body_;

    public:
        template<bool isRequest, class Fields>
        reader(message<isRequest, str_body, Fields>& msg,
            boost::optional<std::uint64_t> content_length)
            : body_(msg.body)
        {
            if(content_length)
            {
                if(*content_length >
                        (std::numeric_limits<std::size_t>::max)())
                    throw std::domain_error{"Content-Length overflow"};
                body_.reserve(*content_length);
            }
        }

        boost::asio::mutable_buffers_1
        prepare(std::size_t n, error_code& ec)
        {
            body_.resize(len_ + n);
            return {&body_[len_], n};
        }

        void
        commit(std::size_t n, error_code& ec)
        {
            if(body_.size() > len_ + n)
            {
                body_.resize(len_ + n);
                len_ += n;
            }
            else
            {
                len_ = body_.size();
            }
        }

        void
        finish(error_code& ec)
        {
            body_.resize(len_);
        }
    };
};

//------------------------------------------------------------------------------

template<class SyncReadStream,
    bool isRequest, class Body, class Fields>
void
read(SyncReadStream& stream, parse_buffer& buffer,
    message<isRequest, Body, Fields>& msg, error_code& ec)
{
    using boost::asio::buffer_copy;

    new_parser_v1<isRequest, Body, Fields> p;

    // Read and parse header
    for(;;)
    {
        p.write(buffer, ec);
        if(! ec)
            break;
        if(ec != error::need_more)
            return;
        ec = {};
        auto const bytes_transferred =
            stream.read_some(buffer.prepare(
                buffer.size() + 1), ec);
        if(ec)
            return;
        buffer.commit(bytes_transferred);
    }

    typename Body::reader r{p.get(), p.content_length()};

    // Read and parse body
    while(! p.complete())
    {
        // maybe read chunk delimiter
        for(;;)
        {
            p.write(buffer, ec);
            if(! ec)
                break;
            if(ec != error::need_more)
                return;
            ec = {};
            auto const bytes_transferred =
                stream.read_some(buffer.prepare(
                    buffer.size() + 1), ec);
            if(ec)
                return;
            buffer.commit(bytes_transferred);
        }

        // copy body bytes in buffer
        p.write_body(r, buffer, ec);
        if(ec)
            return;

        // read remaining part of chunk
        auto const remain = p.remain();
        if(remain > 0)
        {
            auto const b = r.prepare(remain, ec);
            if(ec)
                return;
            auto const bytes_transferred =
                stream.read_some(b, ec);
            if(ec == boost::asio::error::eof)
            {
                ec = {};
                p.write_eof(ec);
                if(ec)
                    return;
                BOOST_ASSERT(p.complete());
            }
            else
            {
                if(ec)
                    return;
                r.commit(bytes_transferred, ec);
                if(ec)
                    return;
                p.consume(bytes_transferred);
            }
        }
    }
    r.finish(ec);
    if(ec)
        return;
    msg = p.release();
}

//------------------------------------------------------------------------------

class new_parser_test
    : public beast::unit_test::suite
    , public beast::test::enable_yield_to
{
public:
    template<bool isRequest, class Pred>
    void
    testMatrix(std::string const& s, Pred const& pred)
    {
        beast::test::string_stream ss{get_io_service(), s};
        error_code ec;
        parse_buffer buffer;
        message<isRequest, str_body, fields> m;
        read(ss, buffer, m, ec);
        if(! BEAST_EXPECTS(! ec, ec.message()))
            return;
        pred(m);
    }

    void
    testRead()
    {
        testMatrix<false>(
            "HTTP/1.0 200 OK\r\n"
            "Server: test\r\n"
            "\r\n"
            "*******",
            [&](message<false, str_body, fields> const& m)
            {
                BEAST_EXPECT(m.body == "*******");
            }
        );
        testMatrix<false>(
            "HTTP/1.0 200 OK\r\n"
            "Server: test\r\n"
            "Transfer-Encoding: chunked\r\n"
            "\r\n"
            "5\r\n"
            "*****\r\n"
            "2;a;b=1;c=\"2\"\r\n"
            "--\r\n"
            "0;d;e=3;f=\"4\"\r\n"
            "Expires: never\r\n"
            "MD5-Fingerprint: -\r\n"
            "\r\n",
            [&](message<false, str_body, fields> const& m)
            {
                BEAST_EXPECT(m.body == "*****--");
            }
        );
        testMatrix<false>(
            "HTTP/1.0 200 OK\r\n"
            "Server: test\r\n"
            "Content-Length: 5\r\n"
            "\r\n"
            "*****",
            [&](message<false, str_body, fields> const& m)
            {
                BEAST_EXPECT(m.body == "*****");
            }
        );
#if 0
        testMatrix<true>(
            "GET / HTTP/1.1\r\n"
            "User-Agent: test\r\n"
            "\r\n");
        testMatrix<true>(
            "GET / HTTP/1.1\r\n"
            "User-Agent: test\r\n"
            "X: \t x \t \r\n"
            "\r\n");
        //BEAST_EXPECT(p.get().fields["X"] == "x");
#endif
    }

    void run() override
    {
        testRead();
        pass();
    }
};

BEAST_DEFINE_TESTSUITE(new_parser,http,beast);

} // http
} // beast
