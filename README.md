# CASN1
A library for reading ASN1. They kan be described directly using c++ syntax.

``` cpp
// define some sequence
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

auto b = std::vector<byte>{0x30, 0,    2,    1,    6,    2,    1,    9,    2,    1,    10,
                           1,    1,    0xff, 19,   11,   0x68, 0x65, 0x6C, 0x6C, 0x6F, 0x20,
                           0x77, 0x6F, 0x72, 0x6C, 0x64, 4,    3,    1,    2,    3,    3,
                           2,    5,    8,    0x31, 6,    2,    1,    40,   2,    1,    50};
b[1] = b.size() - 2;

ASN1::Printer<DER>::run(b);
/*
Outputs:
struct
{
        ASN1::integer integer0;
        ASN1::integer integer1;
        ASN1::integer integer2;
        ASN1::boolean boolean3;
        ASN1::Printable_string printable_string4;
        ASN1::Octet_string octet_string5;
        ASN1::Bit_string bit_string6;
        ASN1::Set set7; // sets are more difficult. These can be an arbitrary sized list, with an arbitrary amount of items.
                ASN1::integer integer8;
                ASN1::integer integer9;
} sequence10;
*/


std::unique_ptr<SampleSeq> ptr = ASN1::StructBuilder<DER>::build<SampleSeq>(b);
```
