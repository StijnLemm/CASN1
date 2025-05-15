#include <algorithm>
#include <array>
#include <cassert>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <gsl/span>
#include <memory>
#include <string>
#include <type_traits>
#include <vector>

#include "gsl/span_ext"

#define REQUIRES(concept) typename = std::enable_if_t<concept>
#define MEMBER_T(obj, member) decltype(((obj*)(nullptr))->member)

#define HAS_BITS(v, mask) ((v & mask) == mask)

using byte = unsigned char;

enum class endianness
{
    little = 0,
    big = 1,
};

inline endianness get_system_endianness()
{
    const int value{0x01};
    const void* address{static_cast<const void*>(&value)};
    const unsigned char* least_significant_address{static_cast<const unsigned char*>(address)};

    return (*least_significant_address == 0x01) ? endianness::little : endianness::big;
}

template <typename... Ts>  // (7)
struct Overload : Ts...
{
    using Ts::operator()...;
};
template <class... Ts>
Overload(Ts...) -> Overload<Ts...>;

// template <typename Decoder>
// struct TLV : private Decoder
// {
//     using iterator_category = std::forward_iterator_tag;
//     using difference_type = std::ptrdiff_t;
//     using value_type = TLV;
//     using pointer = TLV*;
//     using reference = TLV&;
//
//     using Decoder::parse;
//
//     TLV begin() const
//     {
//         return *this;
//     }
//
//     TLV end() const
//     {
//         return TLV{tag, Range<byte>::empty(), _parent_data};
//     }
//
//     TLV& operator*()
//     {
//         return *this;
//     }
//
//     TLV& operator++()
//     {
//         // end of parent data
//         if (_data.end() >= _parent_data.end())
//         {
//             _data = Range<byte>::empty();
//             return *this;
//         }
//
//         size_t bytes_left = (_parent_data.end() - _data.end());
//         *this = parse(Range<byte>(_data.end(), _parent_data.end() - _data.end()));
//         return *this;
//     }
//
//     TLV operator++(int)
//     {
//         // end of parent data
//         if (_data.end() >= _parent_data.end())
//         {
//             _data = Range<byte>::empty();
//             return *this;
//         }
//
//         size_t bytes_left = (_parent_data.end() - _data.end());
//         *this = parse(Range<byte>(_data.end(), _parent_data.end() - _data.end()));
//         return *this;
//     }
//
//     TLV valueAsTlv() const
//     {
//         return parse(_data);
//     }
//
//     Range<byte> value() const
//     {
//         return _data;
//     }
//
//     std::vector<TLV> findTag(typename Decoder::tag_type tag) const
//     {
//         std::vector<TLV> values;
//
//         TLV iter = (*this);
//         while (auto found = iter.findFirst(tag))
//         {
//             values.push_back(*found);
//             iter = (*found)++;
//         }
//
//         return values;
//     }
//
//     std::optional<TLV> findFirst(typename Decoder::tag_type tag) const
//     {
//         for (auto value : (*this))
//         {
//             if (value.tag == tag)
//             {
//                 return value;
//             }
//         }
//
//         return {};
//     }
//
//     struct Select
//     {
//         typename Decoder::tag_type tag;
//     };
//
//     struct Dig
//     {
//     };
//
//     using Op = std::variant<Select, Dig>;
//
//     std::vector<TLV> fromOps(std::vector<Op> ops)
//     {
//         auto selected = std::vector<TLV>{(*this)};
//
//         for (const auto& op : ops)
//         {
//             std::visit(Overload{
//                            // search through selected
//                            [&selected](const Select& s) {
//                                std::vector<TLV> next_selected;
//                                for (const auto& v : selected)
//                                {
//                                    auto found = v.findTag(s.tag);
//                                    next_selected.insert(next_selected.end(), found.begin(),
//                                                         found.end());
//                                }
//
//                                std::swap(selected, next_selected);
//                            },
//                            // dig into the selected
//                            [&selected](const Dig&) {
//                                std::vector<TLV> next_selected;
//                                std::transform(selected.begin(), selected.end(),
//                                               std::back_inserter(next_selected),
//                                               [](const TLV& v) { return v.valueAsTlv(); });
//                                std::swap(selected, next_selected);
//                            },
//                        },
//                        op);
//         }
//
//         return selected;
//     }
//
//     friend bool operator==(const TLV& a, const TLV& b)
//     {
//         return a._data.data() == b._data.data();
//     };
//
//     friend bool operator!=(const TLV& a, const TLV& b)
//     {
//         return a._data.data() != b._data.data();
//     };
//
//     inline void dump() const
//     {
//         fprintf(stderr, "TLV\n\tTag:\t0x%02x\n\tLen:\t%zu\ndata:\n", tag, _data.len());
//         // for (byte b : _data)
//         // {
//         //     fprintf(stderr, "0x%02x ", b);
//         // }
//         // fprintf(stderr, "\n\n");
//     }
//
//     typename Decoder::tag_type tag;
//
// private:
//     constexpr TLV(size_t tag, Range<byte> data, Range<byte> parent_data)
//         : tag(tag), _data(data), _parent_data(parent_data)
//     {
//     }
//
//     Range<byte> _data;
//     Range<byte> _parent_data;
//
//     friend Decoder;
// };

struct TLV
{
    inline void dump(bool print_data = false) const
    {
        fprintf(stderr, "TLV\n\tTag:\t0x%02x\n\tLen:\t%zu\n", tag, data.size());
        if (print_data)
        {
            fprintf(stderr, "data:\n");
            for (byte b : data)
            {
                fprintf(stderr, "0x%02x ", b);
            }
            fprintf(stderr, "\n\n");
        }
    }

    template <typename Decoder>
    constexpr TLV value_as_tlv() const
    {
        return Decoder::parse(data);
    }

    uint tag;
    gsl::span<byte> data;
};

struct TLV_lexer
{
    TLV_lexer(gsl::span<byte> buffer) : head(buffer.begin()), buffer(buffer) {}

    template <typename Decoder>
    constexpr std::optional<TLV> pop()
    {
        if (head == buffer.end()) return {};
        auto tlv = Decoder::parse(buffer.last(buffer.end() - head));

        // have to go unsafe because the containers are different here.
        head.current_ = tlv.data.end().current_;
        return tlv;
    }

    gsl::span<byte>::iterator head;
    gsl::span<byte> buffer;
};

struct DER
{
    static constexpr byte EXTENDED_LEN_MARKER = 0x80;
    static constexpr byte EXTENDED_LEN_SIZE_MASK = 0x0f;

    using tag_type = byte;

    static constexpr TLV parse(gsl::span<byte> bytes)
    {
        assert(bytes.size() >= 2 && "TODO parsing errors");

        if (!HAS_BITS(bytes[1], EXTENDED_LEN_MARKER))
        {
            // byte 0: tag
            // byte 1: len 0-127
            // bytes 2-len: data
            return TLV{bytes[0], gsl::span<byte>(&bytes.data()[2], bytes[1])};
        }

        const byte len_field_size = (bytes[1] & EXTENDED_LEN_SIZE_MASK);
        assert(len_field_size + 2 < bytes.size() && "TODO parsing errors");
        assert(len_field_size <= sizeof(size_t) && "field size is too big for parser");

        // big endian -> little endian
        size_t len = 0;

        const auto endianness = get_system_endianness();
        if (endianness == endianness::little)
        {
            std::reverse_copy(&bytes[2], &bytes[2 + len_field_size], (byte*)&len);
        }
        else  // if (endianness == endianness::big)
        {
            std::copy(&bytes[2], &bytes[2 + len_field_size], (byte*)&len);
        }

        assert(len + 2 < bytes.size() && "TODO parsing errors");
        return TLV{bytes[0], bytes.subspan(len_field_size + 2, len)};
    }
};

static inline std::vector<byte> fromHexString(std::string hex)
{
    assert(hex.length() % 2 == 0 && "Hex string must have an even number of chars!");
    std::vector<byte> bytes;

    for (unsigned int i = 0; i < hex.length(); i += 2)
    {
        std::string byteString = hex.substr(i, 2);
        char byte = (char)strtol(byteString.c_str(), NULL, 16);
        bytes.push_back(byte);
    }

    return bytes;
}

// template <typename Container>
// struct ASN1_int
// {
//     ASN1_int()
//     {
//         static_cast<Container>(this)->set(10);
//     }

// bool parse(const TLV<DER>& tlv)
// {
//     tlv.dump();
//     // todo this parser must be set somehow?
//     auto data = tlv.value();
//
//     assert(data.len() <= sizeof(int));
//     std::reverse_copy(data.begin(), data.end(), &fillMe);
//     return tlv.tag == 2;
// }
// };

// template <typename... Members>
// struct ASN1
// {
//     ASN1(Members&... args)
//     {
//         bool result = true;
//         ([&] { result &= Members::parse(); }(), ...);
//
//         assert(result);
//     }
// };

//
// namespace File
// {

// template <typename... Members>
// void fill_asn(TLV root, Members&... members)
// {
//     ([&] { members = 10; }(), ...);
// }

namespace ASN1
{

template <typename T>
static constexpr size_t aligned_sizeof()
{
    return (sizeof(T) + sizeof(size_t) - 1) & ~(sizeof(size_t) - 1);
}

enum class Type
{
    BOOLEAN = 01,
    INTEGER = 02,
    BIT_STRING = 03,
    OCTET_STRING = 04,
    NILL = 05,
    OID = 06,
    UTF8_STRING = 12,
    PRINTABLE_STRING = 19,
    UTC_TIME = 23,
    SEQUENCE = 0x30,
    SET = 0x31,
};

using integer = int64_t;
using boolean = bool;
using Octet_string = std::vector<byte>;
using Printable_string = std::string;

struct Bit_string
{
    integer unused_bits;
    Octet_string data;
};

struct Set
{
    template <typename Decoder, typename T>
    constexpr std::unique_ptr<T> as_at(const size_t index);
    std::vector<TLV> items;
};

// template <byte Tag, typename T>
// struct context_specific
// {
//     static_assert(Tag & 0b10000000, "Context specific tag must be ");
//     const byte tag = Tag;
//     T data;
// };

struct OID
{
    Printable_string oid;  // TODO: do thing
};

struct UTC_time
{
    std::array<byte, 13> data;
};

struct Visitor
{
    virtual ~Visitor() = default;
    virtual bool step_boolean(const TLV& tlv) = 0;
    virtual bool step_integer(const TLV& tlv) = 0;
    virtual bool step_oid(const TLV& tlv) = 0;
    virtual bool step_utc_time(const TLV& tlv) = 0;
    virtual bool step_nill(const TLV& tlv) = 0;

    virtual bool step_bit_string(const TLV& tlv) = 0;
    virtual bool step_octet_string(const TLV& tlv) = 0;
    virtual bool step_printable_string(const TLV& tlv) = 0;
    virtual bool step_utf8_string(const TLV& tlv) = 0;

    virtual bool step_in_sequence(const TLV& tlv) = 0;
    virtual bool step_out_sequence(const TLV& tlv) = 0;

    virtual bool step_in_set(const TLV& tlv) = 0;
    virtual bool step_out_set(const TLV& tlv) = 0;

    bool option_step_in_set = true;
    bool option_step_in_sequence = true;
};

template <typename T>
static constexpr void operator<<=(gsl::span<T>& span, size_t amount)
{
    span = span.last(span.size() - amount);
}

template <typename T>
static constexpr void operator>>=(gsl::span<T>& span, size_t amount)
{
    span = span.first(span.size() - amount);
}

template <typename T>
static constexpr T* span_as(const gsl::span<byte>& span)
{
    return ((T*)span.data());
}

struct Printer : public Visitor
{
    bool step_boolean(const TLV& tlv) override
    {
        fprintf(stderr, "%sASN1::boolean boolean%d;\n", indent.c_str(), get_uuid());
        return true;
    }

    bool step_integer(const TLV& tlv) override
    {
        fprintf(stderr, "%sASN1::integer integer%d;\n", indent.c_str(), get_uuid());
        return true;
    }

    bool step_oid(const TLV& tlv) override
    {
        fprintf(stderr, "%sASN1::OID oid%d;\n", indent.c_str(), get_uuid());
        return true;
    }

    bool step_utc_time(const TLV& tlv) override
    {
        fprintf(stderr, "%sASN1::UTC_time utc_time%d;\n", indent.c_str(), get_uuid());
        return true;
    }

    bool step_nill(const TLV& tlv) override
    {
        return true;
    }

    bool step_bit_string(const TLV& tlv) override
    {
        fprintf(stderr, "%sASN1::Bit_string bit_string%d;\n", indent.c_str(), get_uuid());
        return true;
    }

    bool step_octet_string(const TLV& tlv) override
    {
        fprintf(stderr, "%sASN1::Octet_string octet_string%d;\n", indent.c_str(), get_uuid());
        return true;
    }

    bool step_printable_string(const TLV& tlv) override
    {
        fprintf(stderr, "%sASN1::Printable_string printable_string%d;\n", indent.c_str(),
                get_uuid());
        return true;
    }

    bool step_utf8_string(const TLV& tlv) override
    {
        fprintf(stderr, "%sASN1::Utf8_string utf8_string%d;\n", indent.c_str(), get_uuid());
        return true;
    }

    bool step_in_sequence(const TLV& tlv) override
    {
        fprintf(stderr, "%sstruct\n%s{\n", indent.c_str(), indent.c_str());
        add_indent();
        return true;
    }

    bool step_out_sequence(const TLV& tlv) override
    {
        remove_indent();
        fprintf(stderr, "%s} sequence%d;\n", indent.c_str(), get_uuid());
        return true;
    }

    bool step_in_set(const TLV& tlv) override
    {
        fprintf(stderr, "%sASN1::Set set%d;\n", indent.c_str(), get_uuid());
        add_indent();
        return true;
    }

    bool step_out_set(const TLV& tlv) override
    {
        remove_indent();
        return true;
    }

    void add_indent()
    {
        indent = indent + "\t";
    }

    void remove_indent()
    {
        indent = indent.substr(0, indent.size() - 1);
    }

    int get_uuid()
    {
        return uuid++;
    }

    template <typename Decoder>
    static void run(gsl::span<byte> data);

    int uuid = 0;
    std::string indent;
};

template <typename Decoder>
struct StructBuilder : public Visitor
{
    bool step_boolean(const TLV& tlv) override
    {
        if (struct_data_to_fill.size() < aligned_sizeof<boolean>())
        {
            fprintf(stderr, "Struct ended, but ASN1 not done, append: %s\n",
                    typeid(boolean).name());
            return false;
        }

        if (tlv.data.size() > aligned_sizeof<boolean>())
        {
            fprintf(stderr, "TLV data is larger (%zu bytes) than boolean struct field!\n",
                    tlv.data.size());
            return false;
        }

        std::fill(struct_data_to_fill.begin(),
                  struct_data_to_fill.begin() + aligned_sizeof<boolean>(), 0);
        std::reverse_copy(tlv.data.begin(), tlv.data.end(), struct_data_to_fill.begin());
        struct_data_to_fill <<= aligned_sizeof<boolean>();
        return true;
    }

    bool step_integer(const TLV& tlv) override
    {
        if (struct_data_to_fill.size() < aligned_sizeof<integer>())
        {
            fprintf(stderr, "Struct ended, but ASN1 not done, append: %s\n",
                    typeid(integer).name());
            return false;
        }

        if (tlv.data.size() > aligned_sizeof<integer>())
        {
            fprintf(stderr, "TLV data is larger (%zu bytes) than integer struct field!\n",
                    tlv.data.size());
            return false;
        }

        std::fill(struct_data_to_fill.begin(),
                  struct_data_to_fill.begin() + aligned_sizeof<integer>(), 0);
        std::reverse_copy(tlv.data.begin(), tlv.data.end(), struct_data_to_fill.begin());
        struct_data_to_fill <<= aligned_sizeof<integer>();
        return true;
    }

    bool step_oid(const TLV& tlv) override
    {
        if (struct_data_to_fill.size() < aligned_sizeof<OID>())
        {
            fprintf(stderr, "Struct ended, but ASN1 not done, append: oid\n");
            return false;
        }

        if (struct_data_to_fill.empty())
        {
            fprintf(stderr, "Invalid oid, length 0\n");
            return false;
        }

        new (span_as<OID>(struct_data_to_fill))
            OID{Printable_string(tlv.data.begin(), tlv.data.end())};
        Printable_string& str = span_as<OID>(struct_data_to_fill)->oid;
        str.reserve(15);

        auto iter = tlv.data.begin();
        const byte front = *iter++;
        str += std::to_string(front / 40) + "." + std::to_string(front % 40);

        while (iter != tlv.data.end())
        {
            size_t value = (*iter & 0b01111111);
            while (HAS_BITS(*iter, 0b10000000))
            {
                if (iter >= tlv.data.end() - 1)
                {
                    fprintf(stderr, "Bad oid encoding!");
                    return false;
                }

                value <<= 7;
                value += (*++iter & 0b01111111);
            }

            str += "." + std::to_string(value);
            iter++;
        }

        struct_data_to_fill <<= aligned_sizeof<OID>();
        return true;
    }

    bool step_utc_time(const TLV& tlv) override
    {
        fprintf(stderr, "utc_time unimplemented!\n");
        struct_data_to_fill <<= aligned_sizeof<UTC_time>();
        return true;
    }

    bool step_nill(const TLV& tlv) override
    {
        return true;
    }

    bool step_bit_string(const TLV& tlv) override
    {
        if (struct_data_to_fill.size() < aligned_sizeof<Octet_string>() + aligned_sizeof<integer>())
        {
            fprintf(stderr, "Struct ended, but ASN1 not done, append: bit_string\n");
            return false;
        }

        if (tlv.data.size() < 1)
        {
            fprintf(stderr, "Bit string size less than 1!\n");
            return false;
        }

        // set unused bits
        new (span_as<integer>(struct_data_to_fill)) integer{tlv.data.front()};
        struct_data_to_fill <<= aligned_sizeof<integer>();

        new (span_as<Octet_string>(struct_data_to_fill))
            Octet_string(tlv.data.begin() + 1, tlv.data.end());
        struct_data_to_fill <<= aligned_sizeof<Octet_string>();
        return true;
    }

    bool step_octet_string(const TLV& tlv) override
    {
        if (struct_data_to_fill.size() < aligned_sizeof<Octet_string>())
        {
            fprintf(stderr, "Struct ended, but ASN1 not done, append: octet_string\n");
            return false;
        }

        new (span_as<Octet_string>(struct_data_to_fill))
            Octet_string(tlv.data.begin(), tlv.data.end());
        struct_data_to_fill <<= aligned_sizeof<Octet_string>();
        return true;
    }

    bool step_printable_string(const TLV& tlv) override
    {
        if (struct_data_to_fill.size() < aligned_sizeof<Printable_string>())
        {
            fprintf(stderr, "Struct ended, but ASN1 not done, append: printable_string\n");
            return false;
        }

        new (span_as<Printable_string>(struct_data_to_fill))
            Printable_string(tlv.data.begin(), tlv.data.end());
        struct_data_to_fill <<= aligned_sizeof<Printable_string>();
        return true;
    }

    bool step_utf8_string(const TLV& tlv) override
    {
        fprintf(stderr, "utf8_string unimplemented!\n");
        // struct_data_to_fill <<= aligned_sizeof<Printable_string>();
        return false;
    }

    bool step_in_sequence(const TLV& tlv) override
    {
        return true;
    }

    bool step_out_sequence(const TLV& tlv) override
    {
        return true;
    }

    bool step_in_set(const TLV& tlv) override
    {
        if (struct_data_to_fill.size() < aligned_sizeof<Set>())
        {
            fprintf(stderr, "Struct ended, but ASN1 not done, append: Set\n");
            return false;
        }

        // loop over all items in SET
        new (span_as<Set>(struct_data_to_fill)) Set();
        auto lexer = TLV_lexer(tlv.data);

        // TODO: this feels off? We should have decoder here somehow.
        while (auto result = lexer.pop<Decoder>())
        {
            span_as<Set>(struct_data_to_fill)->items.push_back(*result);
        }

        struct_data_to_fill <<= aligned_sizeof<Set>();
        return true;
    }

    bool step_out_set(const TLV& tlv) override
    {
        // fprintf(stderr, "set unimplemented!\n");
        return true;
    }

    template <typename T>
    static std::unique_ptr<T> build(gsl::span<byte> data);

private:
    StructBuilder(gsl::span<byte> data) : struct_data_to_fill(data)
    {
        option_step_in_set = false;
    }

    gsl::span<byte> struct_data_to_fill;
};

// template <typename T>
// bool fill_asn(const TLV& tlv, gsl::span<byte>& struct_data_to_fill)
// {
//     if (struct_data_to_fill.size() < aligned_sizeof<T>())
//     {
//         fprintf(stderr, "Struct ended, but ASN1 not done, append: %s\n", typeid(T).name());
//         return false;
//     }
//
//     if (tlv.data.size() > aligned_sizeof<T>())
//     {
//         return false;
//     }
//
//     std::fill(struct_data_to_fill.begin(), struct_data_to_fill.begin() + aligned_sizeof<T>(), 0);
//     std::reverse_copy(tlv.data.begin(), tlv.data.end(), struct_data_to_fill.begin());
//     struct_data_to_fill <<= aligned_sizeof<T>();
//     return true;
// }

// template <>
// bool fill_asn<Octet_string>(const TLV& tlv, gsl::span<byte>& struct_data_to_fill)
// {
//     if (struct_data_to_fill.size() < aligned_sizeof<Octet_string>())
//     {
//         fprintf(stderr, "Struct ended, but ASN1 not done, append: octet_string\n");
//         return false;
//     }
//
//     new (span_as<Octet_string>(struct_data_to_fill)) Octet_string(tlv.data.begin(),
//     tlv.data.end()); struct_data_to_fill <<= aligned_sizeof<Octet_string>(); return true;
// }

// template <>
// bool fill_asn<Printable_string>(const TLV& tlv, gsl::span<byte>& struct_data_to_fill)
// {
//     if (struct_data_to_fill.size() < aligned_sizeof<Printable_string>())
//     {
//         fprintf(stderr, "Struct ended, but ASN1 not done, append: printable_string\n");
//         return false;
//     }
//
//     new (span_as<Printable_string>(struct_data_to_fill))
//         Printable_string(tlv.data.begin(), tlv.data.end());
//     struct_data_to_fill <<= aligned_sizeof<Printable_string>();
//     return true;
// }

// template <>
// bool fill_asn<OID>(const TLV& tlv, gsl::span<byte>& struct_data_to_fill)
// {
//     if (struct_data_to_fill.size() < aligned_sizeof<OID>())
//     {
//         fprintf(stderr, "Struct ended, but ASN1 not done, append: oid\n");
//         return false;
//     }
//
//     if (struct_data_to_fill.empty())
//     {
//         fprintf(stderr, "Invalid oid, length 0\n");
//         return false;
//     }
//
//     new (span_as<OID>(struct_data_to_fill)) OID{Printable_string(tlv.data.begin(),
//     tlv.data.end())}; Printable_string& str = span_as<OID>(struct_data_to_fill)->oid;
//     str.reserve(15);
//
//     auto iter = tlv.data.begin();
//     const byte front = *iter++;
//     str += std::to_string(front / 40) + "." + std::to_string(front % 40);
//
//     while (iter != tlv.data.end())
//     {
//         size_t value = (*iter & 0b01111111);
//         while (HAS_BITS(*iter, 0b10000000))
//         {
//             if (iter >= tlv.data.end() - 1)
//             {
//                 fprintf(stderr, "Bad oid encoding!");
//                 return false;
//             }
//
//             value <<= 7;
//             value += (*++iter & 0b01111111);
//         }
//
//         str += "." + std::to_string(value);
//         iter++;
//     }
//
//     struct_data_to_fill <<= aligned_sizeof<OID>();
//     return true;
// }

// template <>
// bool fill_asn<Bit_string>(const TLV& tlv, gsl::span<byte>& struct_data_to_fill)
// {
//     if (struct_data_to_fill.size() < aligned_sizeof<Octet_string>() + aligned_sizeof<integer>())
//     {
//         fprintf(stderr, "Struct ended, but ASN1 not done, append: bit_string\n");
//         return false;
//     }
//
//     if (tlv.data.size() < 1)
//     {
//         return false;
//     }
//
//     // set unused bits
//     new (span_as<integer>(struct_data_to_fill)) integer{tlv.data.front()};
//     struct_data_to_fill <<= aligned_sizeof<integer>();
//
//     new (span_as<Octet_string>(struct_data_to_fill)) Octet_string(tlv.data.begin() + 1,
//     tlv.data.end()); struct_data_to_fill <<= aligned_sizeof<Octet_string>(); return true;
// }

template <typename Decoder>
bool start_visit(TLV tlv, Visitor& visitor)
{
    if ((tlv.tag & 0b10000000))
    {
        // tlv.dump();
        // fprintf(stderr, "Found context specific tag: 0x%02x\n", tlv.tag);
        tlv = tlv.value_as_tlv<Decoder>();
    }

    // tlv.dump();

    switch (static_cast<Type>(tlv.tag))
    {
        case Type::BOOLEAN:
            if (!visitor.step_boolean(tlv)) return false;
            break;
        case Type::INTEGER:
            if (!visitor.step_integer(tlv)) return false;
            break;
        case Type::BIT_STRING:
            if (!visitor.step_bit_string(tlv)) return false;
            break;
        case Type::OCTET_STRING:
            if (!visitor.step_octet_string(tlv)) return false;
            break;
        case Type::NILL:
            if (!visitor.step_nill(tlv)) return false;
            break;
        case Type::PRINTABLE_STRING:
            if (!visitor.step_printable_string(tlv)) return false;
            break;
        case Type::UTF8_STRING:
            if (!visitor.step_utf8_string(tlv)) return false;
            break;
        case Type::OID:
            if (!visitor.step_oid(tlv)) return false;
            break;
        case Type::UTC_TIME:
            if (!visitor.step_utc_time(tlv)) return false;
            break;
        case Type::SEQUENCE:
            if (!visitor.step_in_sequence(tlv)) return false;

            if (visitor.option_step_in_sequence)
            {
                // loop over all members of SEQUENCE
                auto lexer = TLV_lexer(tlv.data);
                while (auto result = lexer.pop<Decoder>())
                {
                    if (!start_visit<Decoder>(*result, visitor)) return false;
                }
            }

            if (!visitor.step_out_sequence(tlv)) return false;
            break;
        case Type::SET:
            if (!visitor.step_in_set(tlv)) return false;

            if (visitor.option_step_in_set)
            {
                // loop over all items in SET
                auto lexer = TLV_lexer(tlv.data);
                while (auto result = lexer.pop<Decoder>())
                {
                    // span_as<Set>(struct_data_to_fill)->items.push_back(*result);
                    if (!start_visit<Decoder>(*result, visitor)) return false;
                }
            }

            if (!visitor.step_out_set(tlv)) return false;
            break;
        default:
            fprintf(stderr, "Got unimplemented tag: 0x%02x\n", tlv.tag);
            return false;
    }

    return true;
}

template <typename Decoder>
void Printer::run(gsl::span<byte> data)
{
    Printer p;
    start_visit<Decoder>(Decoder::parse(data), p);
}

template <typename Decoder>
template <typename T>
std::unique_ptr<T> StructBuilder<Decoder>::build(gsl::span<byte> data)
{
    static_assert(std::is_standard_layout_v<T>, "Non standard layout not supported");

    auto mem = std::make_unique<byte[]>(sizeof(T));
    new (mem.get()) T();  // call constructor for memory?

    StructBuilder<Decoder> visitor{gsl::make_span(mem.get(), sizeof(T))};

    if (!start_visit<Decoder>(DER::parse(data), visitor)) return nullptr;

    if (!visitor.struct_data_to_fill.empty())
    {
        fprintf(
            stderr,
            "Warning: not the complete struct is filled, struct is %zu bytes bigger than ASN1\n",
            visitor.struct_data_to_fill.size());
    }

    // release the successfully parsed memory as the struct.
    return std::unique_ptr<T>((T*)mem.release());
}

// template <typename Decoder, typename T>
// std::unique_ptr<T> parse(const TLV& tlv)
// {
//     static_assert(std::is_standard_layout_v<T>, "Non standard layout not supported");
//
//     // TODO: destructors will fail miserably if parsing fails. we need to allocate the memory for
//     T
//     // for parsing, then interpret memory as T.
//     auto mem = std::make_unique<byte[]>(sizeof(T));
//     new (mem.get()) T();
//
//     auto to_fill = gsl::make_span(mem.get(), sizeof(T));
//     if (!fill<Decoder>(tlv, to_fill)) return nullptr;
//
//     if (!to_fill.empty())
//     {
//         fprintf(
//             stderr,
//             "Warning: not the complete struct is filled, struct is %zu bytes bigger than ASN1\n",
//             to_fill.size());
//     }
//
//     // release the successfully parsed memory as the struct.
//     return std::unique_ptr<T>((T*)mem.release());
// }

// template <typename Decoder, typename T>
// constexpr std::unique_ptr<T> Set::as_at(const size_t index)
// {
//     if (items.size() <= index)
//     {
//         fprintf(stderr, "Index out of bounds!\n");
//         return nullptr;
//     }
//
//     const TLV& item = items[index];
//     if (sizeof(T) < item.data.size())
//     {
//         fprintf(stderr, "Size of item does not match!\n");
//         return nullptr;
//     }
//
//     return parse<Decoder, T>(item);
// }

}  // namespace ASN1

struct Point
{
    ASN1::integer x;
    ASN1::integer y;
};

struct SampleSeq
{
    ASN1::integer id;
    ASN1::integer num;
    ASN1::integer extra;
    ASN1::boolean b;
    ASN1::Printable_string printable_str;
    ASN1::Octet_string octet_str;
    ASN1::Bit_string bit_str;
    ASN1::Set ints;
};

int main()
{
    auto b = std::vector<byte>{0x30, 0,    2,    1,    6,    2,    1,    9,    2,    1,    10,
                               1,    1,    0xff, 19,   11,   0x68, 0x65, 0x6C, 0x6C, 0x6F, 0x20,
                               0x77, 0x6F, 0x72, 0x6C, 0x64, 4,    3,    1,    2,    3,    3,
                               2,    5,    8,    0x31, 6,    2,    1,    40,   2,    1,    50};
    b[1] = b.size() - 2;

    ASN1::Printer::run<DER>(b);
    auto ptr = ASN1::StructBuilder<DER>::build<SampleSeq>(b);

    if (!ptr)
    {
        fprintf(stderr, "Failed to parse!\n");
        return 1;
    }

    fprintf(stderr, "id: %lld, num: %lld, inner: %lld, bool: %d, str: %s, unused: %lld\n", ptr->id,
            ptr->num, ptr->extra, ptr->b, ptr->printable_str.c_str(), ptr->bit_str.unused_bits);

    // auto result = ptr->ints.as_at<DER, ASN1::integer>(0);
    // fprintf(stderr, "set item 1: %lld\n", *result);

    auto bytes = fromHexString(
        "77820AEC30820AE806092A864886F70D010702A0820AD930820AD5020103310D300B0609608648016503040201"
        "308201390606678108010101A082012D0482012930820125020100300B06096086480165030402013082011130"
        "2502010104205120A6F4DB1024677E471BB09909D3D4BE3D52BE5124772E6F432FE2E281CA5630250201050420"
        "B10A570F42441FF308C64F5C7448C2CC164A7D2C99AF3110F3145F28730D57903025020106042080A48BC3F354"
        "6FB562AFD2D00FE581057D0E06ABC446CDC91646B12CA580C23F302502010B04204F35D67FCB9C5D072021AE3A"
        "330393FF5C0FCF6EC5ED48B40926C0735363BD5D302502010C042018E09528EC77197CC46C71F4CF90B003BFA1"
        "38C0615A3B2BC739BE0F2E2A7000302502010D042037564C5A1CE715B6B5EAD93FD33D61640276D454686631AD"
        "8938CE15C998FCA8302502010E042029DE76EFCB6CCD0FF16F2A0B1A5F4B6441CB41CE9A6A2BADB6ECA9607A36"
        "C36CA08206663082066230820416A003020102020806719FFE5521C945304106092A864886F70D01010A3034A0"
        "0F300D06096086480165030402010500A11C301A06092A864886F70D010108300D060960864801650304020105"
        "00A20302012030653118301606035504030C0F4353434120474154204E4C2065444C310B300906035504051302"
        "3032310C300A060355040B0C035244573121301F060355040A0C185374617465206F6620746865204E65746865"
        "726C616E6473310B3009060355040613024E4C301E170D3138303430343134353833315A170D32383039333031"
        "34353833315A3061310B3009060355040613024E4C3121301F060355040A0C185374617465206F662074686520"
        "4E65746865726C616E6473310C300A060355040B0C035244573115301306035504030C0C44532D3032204E4C20"
        "65444C310A3008060355040513013130820222300D06092A864886F70D01010105000382020F003082020A0282"
        "020100EE9A7F79C2C0CE17D5446CF4DEF73A490DEAAB31A435A231822B52F6185640B9543C378503504694EEBB"
        "97973E9AC7E9EF9178294B11DD598B8C2F9B590EA600F81A0C6A4A8E56E14127C4F999BC3EA23CBBC08435FF15"
        "85EC7A6912D9E8C699BA5637F41DC9AE2FAB759970B2465565DB655F50E71FACFAA4AD707FB1093E0B21DB1066"
        "419D2F60701C29C32659B24732EF9D4A3177A6C5E6603C13D370DEBF7AE122B61F190C2A39DC76A36F7857F7A6"
        "6B0C2F7CE09920E0D0F4777A3375B2647D4ECE40B0667BB2073665E76B180BB96B2604CC761112EF46F5A7F331"
        "16037F3977CB1EC723B18B93769C734339517E3A091F3844363D41EBF395672E87BC0D35830E3AB5D76183951F"
        "849DE791815A7EB3B066F048111A9D501D53191C45A189ACCC7777549D34D5B33D0EE6A250D931CCC8C70AA8F2"
        "B40E6B468737304763BFC741274C6A7A36DC8D1DF5929ACB1B98AF9095C489756C9FB53373DA47179F348FDA67"
        "432BC49FFD6F187A79A8BFFF7E455369A588A9E9862B71DED238EC79370C5E780D8778B5858CD87181E0FBAF7F"
        "1B0B6B70EEF769AA5979C27644A06B9C2AF1AA831ABE31FC06CA37C76EA789FFA913E5BDE28943BBE4D4956233"
        "AF57F9F0EC6723F2BABD9640FE0ED49ACE834E7DD9F22469577B93E718B60F889CA77FCBD5B4C45C7CD740A781"
        "EE961039E32FA5DF5907B826CD1E94013C64172B0203010001A381B13081AE301D0603551D0E04160414422ECB"
        "4D9A8CE8686423FC2A21484F168876F047301F0603551D230418301680149285B197E799CDDEAC67058BDBAF11"
        "CB41ECF82630170603551D200410300E300C060A6084100187720201050230430603551D1F043C303A3038A036"
        "A0348632687474703A2F2F7777772D6469656E7374656E2E7264772E6E6C2F63726C2F435343414741544E4C65"
        "444C2D30312E63726C300E0603551D0F0101FF040403020780304106092A864886F70D01010A3034A00F300D06"
        "096086480165030402010500A11C301A06092A864886F70D010108300D06096086480165030402010500A20302"
        "0120038202010087F421793982F461A6AA51F857166EBAB3FD2B2C6F8A32EFCAA843010988D332CA1A227D095A"
        "B7E153DEE4009CC2D22271EB72B0F94A53D8D071F1AF49C931C356EE224A7922BE03193822122592DA61E0D449"
        "B44618CB1F89CF27EB11CB3E63853C402D6AEA59A5F0C37605DD78BA508DDE2C30D63C2780ED6D8141E7B036DA"
        "2BCB2F49CA962BF6D0564E6A2DCC586182702F4D389378EC298390509F64E26A71E84C5B644533BA4410491CF8"
        "DCA67B8D927C7687865A72F6A98F3C98CE8809BA6C3FCA9CE47257370EFCBE8545D593338DA37BF3D9AF7DE491"
        "D0BCBC03A92CB8C9F470B15E2B2D5C920D5AAD0D6D095A3032545262B03235C04A6D588C8294AA4D4C75226126"
        "5419E54060D2847AEE39809F035EC56DD3FA8B33F7A1550B73A23146C0779ECBB672CB374DF61B5B5D8E0A9B13"
        "3B91C5ED261137EF5E15882A81F37E45A3EF7AA685500DF13BC6DA9A8CF3002F1B082320362D4D33FDCA394455"
        "B263C13D47C61B0CEEC34176550CE15709327AE65F0BC37224291726EE2A460554A6EF5459FFCEEE40828B2810"
        "53F3D7E3A22206A8299C12AEEE89A7DA8E57359FB50454E4B4FAB92A36AAB1E05CEC8D27C133D4568E81140C29"
        "66F02431619C7162AE1A605DEAA8665E0F511317EB7E01F2DC0627F6C8DCA1DBF82217FECE7A0695FE30FF49DE"
        "56011EA633358EB6ED0F71B3547D8DF72E2CCCC931D4674B318203183082031402010130713065311830160603"
        "5504030C0F4353434120474154204E4C2065444C310B3009060355040513023032310C300A060355040B0C0352"
        "44573121301F060355040A0C185374617465206F6620746865204E65746865726C616E6473310B300906035504"
        "0613024E4C020806719FFE5521C945300B0609608648016503040201A048301506092A864886F70D0109033108"
        "0606678108010101302F06092A864886F70D010904312204203141F7B811C35F335E1D745C46DD26486B0999E8"
        "5018157D7C117DE51F682753304106092A864886F70D01010A3034A00F300D06096086480165030402010500A1"
        "1C301A06092A864886F70D010108300D06096086480165030402010500A20302012004820200EB1AED0F7AE797"
        "0551DA709158D80209AC2A2BB54EF7971EDB6D82FD7A3878BABDC128B3C7F537193EAE032B2D8160AF364B871A"
        "87676285FA3E442F714C43D5B92AA15883860B1037871476526AA59FE2C8647CB861248D7DB059A8B3608420C5"
        "0B00510C74F4133852C72558B7411DA8274E5456C786C6EBBBB33B2D512DB366F91F19ABA16724858D1D42843E"
        "83F649FB6D5017D152FC85B8FFBC9FBA8827DAA72B9C896198E94413F21EA9818D8FD234581EC3226F298F08EE"
        "B2CA9029565B80FC171D598D94427B1E453D3BDCDA6C1053F16488047660E306333B8195BD55AAEBCABA0BFB77"
        "A7400CA6083AA85557C3C101DF83C7D0F3726F518B30F8AA6312B9A90DF649CF132037999695C2B330A0C72321"
        "430E210A2CD1E7ABA13273AE5699D4A8C3904D362EE9FEB2A6D7945FBDED7C2C00947E7CC8915C76D07AF2E123"
        "96A90112A5AD86BAA98784FAE04CB3CE776E6EAF8E6B86DC646096062E70FBE0FD98B6F25B269452ABFF687E1A"
        "DE330201309F9049DE6BA68D4622EF5A4F066234D4A6F5392F7B5DC9592F81D14EECFAFDF014D421CB0732AECD"
        "6F86634C91EB6284D73EF89F9FCAF0BCCF31BEAD84997B6E1A5114F62F2AF9C38E9160CA12EAC29CA8AD78D07E"
        "68E72BC0B019CE09D71A63ECF0372601BD0640A90CA67888A3A53553386F794769F5E047766F9B4C4BD0DE69E6"
        "30F6772BA23A5DA8E322");

    struct onzin
    {
        char filler[2560];
    };

    struct DL
    {
        ASN1::OID oid;
        struct
        {
            ASN1::integer NAME0;
            ASN1::Set NAME1;
            struct
            {
                ASN1::OID oid;
                ASN1::Octet_string NAME2;
            } NAME3;
            struct
            {
                struct
                {
                    ASN1::integer NAME4;
                    ASN1::integer NAME5;
                    struct
                    {
                        ASN1::OID oid;
                        struct
                        {
                            struct
                            {
                                ASN1::OID oid;
                            } NAME6;
                            struct
                            {
                                ASN1::OID oid;
                                struct
                                {
                                    ASN1::OID oid;
                                } NAME7;
                            } NAME8;
                            ASN1::integer NAME9;
                        } NAME10;
                    } NAME11;
                    struct
                    {
                        ASN1::Set NAME12;
                        ASN1::Set NAME13;
                        ASN1::Set NAME14;
                        ASN1::Set NAME15;
                        ASN1::Set NAME16;
                    } NAME17;
                    struct
                    {
                        ASN1::UTC_time NAME18;
                        ASN1::UTC_time NAME19;
                    } NAME20;
                    struct
                    {
                        ASN1::Set NAME21;
                        ASN1::Set NAME22;
                        ASN1::Set NAME23;
                        ASN1::Set NAME24;
                        ASN1::Set NAME25;
                    } NAME26;
                    struct
                    {
                        struct
                        {
                            ASN1::OID oid;
                        } NAME27;
                        ASN1::Bit_string NAME28;
                    } NAME29;
                    struct
                    {
                        struct
                        {
                            ASN1::OID oid;
                            ASN1::Octet_string NAME30;
                        } NAME31;
                        struct
                        {
                            ASN1::OID oid;
                            ASN1::Octet_string NAME32;
                        } NAME33;
                        struct
                        {
                            ASN1::OID oid;
                            ASN1::Octet_string NAME34;
                        } NAME35;
                        struct
                        {
                            ASN1::OID oid;
                            ASN1::Octet_string NAME36;
                        } NAME37;
                        struct
                        {
                            ASN1::OID oid;
                            ASN1::boolean NAME38;
                            ASN1::Octet_string NAME39;
                        } NAME40;
                    } NAME41;
                } NAME42;
                struct
                {
                    ASN1::OID oid;
                    struct
                    {
                        struct
                        {
                            ASN1::OID oid;
                        } NAME43;
                        struct
                        {
                            ASN1::OID oid;
                            struct
                            {
                                ASN1::OID oid;
                            } NAME44;
                        } NAME45;
                        ASN1::integer NAME46;
                    } NAME47;
                } NAME48;
                ASN1::Bit_string NAME49;
            } NAME50;
            ASN1::Set NAME51;
        } NAME52;
    };

    auto file = DER::parse(bytes);  // unpack file desc
    auto dl = ASN1::StructBuilder<DER>::build<DL>(file.data);

    // std::array<byte, 2048> phantom;
    // auto span = gsl::make_span(phantom);
    // ASN1::Printer p;
    // ASN1::start_visit<DER>(tlv, span, p);

    struct HashGroup
    {
        ASN1::integer NAME54;
        struct
        {
            ASN1::OID oid;
        } NAME55;
        struct
        {
            struct
            {
                ASN1::integer NAME56;
                ASN1::Octet_string NAME57;
            } NAME58;
            struct
            {
                ASN1::integer NAME59;
                ASN1::Octet_string NAME60;
            } NAME61;
            struct
            {
                ASN1::integer NAME62;
                ASN1::Octet_string NAME63;
            } NAME64;
            struct
            {
                ASN1::integer NAME65;
                ASN1::Octet_string NAME66;
            } NAME67;
            struct
            {
                ASN1::integer NAME68;
                ASN1::Octet_string NAME69;
            } NAME70;
            struct
            {
                ASN1::integer NAME71;
                ASN1::Octet_string NAME72;
            } NAME73;
            struct
            {
                ASN1::integer NAME74;
                ASN1::Octet_string NAME75;
            } NAME76;
        } NAME77;
    };

    // check the hash fields
    // auto a = ASN1::parse<DER, HashGroup>(DER::parse(dl->NAME52.NAME3.NAME2));

    // printf("iod: %s\n", dl->oid.oid.c_str());
    //
    // for (byte b : a->NAME77.NAME64.NAME63)
    // {
    //     printf("0x%02x ", b);
    // }

    return 0;
}
