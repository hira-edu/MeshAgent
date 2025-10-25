#include <algorithm>
#include <array>
#include <chrono>
#include <cctype>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <ctime>
#include <filesystem>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <sstream>
#include <stdexcept>
#include <string>
#include <vector>

namespace
{
namespace fs = std::filesystem;

struct Options
{
    std::string inputPath;
    std::string outputPath;
    std::string symbolName = "g_BinaryBlob";
    std::string headerGuard;
    std::string nameSpace;
    std::string metadataPath;
    std::size_t bytesPerLine = 12;
    bool metadataOnly = false;
};

[[noreturn]] void PrintUsageAndExit(int code)
{
    std::cerr << R"(bin2h - MeshAgent binary to header converter

Usage:
    bin2h --input <file> --output <header> [--symbol <name>]
          [--guard <macro>] [--namespace <ns::nested>]
          [--bytes-per-line <count>] [--metadata <json>]
          [--metadata-only]
)";
    std::exit(code);
}

bool HasSuffix(const std::string& value, const std::string& suffix)
{
    if (suffix.size() > value.size()) { return false; }
    return std::equal(suffix.rbegin(), suffix.rend(), value.rbegin(),
        [](char a, char b) { return std::tolower(static_cast<unsigned char>(a)) == std::tolower(static_cast<unsigned char>(b)); });
}

std::string SanitizeIdentifier(const std::string& value, bool upper)
{
    std::string result;
    result.reserve(value.size());
    for (char ch : value)
    {
        if (std::isalnum(static_cast<unsigned char>(ch)))
        {
            result.push_back(upper ? static_cast<char>(std::toupper(static_cast<unsigned char>(ch)))
                                   : static_cast<char>(std::tolower(static_cast<unsigned char>(ch))));
        }
        else
        {
            result.push_back('_');
        }
    }
    if (result.empty())
    {
        result = "EMBEDDED_PAYLOAD";
    }
    return result;
}

std::string DeriveGuard(const Options& opt)
{
    if (!opt.headerGuard.empty()) { return opt.headerGuard; }
    if (!opt.outputPath.empty())
    {
        auto guard = SanitizeIdentifier(opt.outputPath, true);
        guard += "_INCLUDED";
        return guard;
    }
    return SanitizeIdentifier(opt.symbolName, true) + "_H";
}

std::vector<std::string> SplitNamespace(const std::string& ns)
{
    std::vector<std::string> parts;
    std::string current;
    for (std::size_t i = 0; i < ns.size(); ++i)
    {
        if (ns[i] == ':' && (i + 1) < ns.size() && ns[i + 1] == ':')
        {
            if (!current.empty())
            {
                parts.emplace_back(current);
                current.clear();
            }
            ++i; // Skip second ':'
        }
        else
        {
            current.push_back(ns[i]);
        }
    }
    if (!current.empty())
    {
        parts.emplace_back(current);
    }
    return parts;
}

std::string EscapeJson(const std::string& value)
{
    std::string escaped;
    escaped.reserve(value.size() + 8);
    for (char ch : value)
    {
        switch (ch)
        {
        case '\"': escaped += "\\\""; break;
        case '\\': escaped += "\\\\"; break;
        case '\b': escaped += "\\b"; break;
        case '\f': escaped += "\\f"; break;
        case '\n': escaped += "\\n"; break;
        case '\r': escaped += "\\r"; break;
        case '\t': escaped += "\\t"; break;
        default:
            if (static_cast<unsigned char>(ch) < 0x20)
            {
                std::ostringstream oss;
                oss << "\\u" << std::hex << std::setw(4) << std::setfill('0') << (static_cast<int>(static_cast<unsigned char>(ch)));
                escaped += oss.str();
            }
            else
            {
                escaped += ch;
            }
            break;
        }
    }
    return escaped;
}

std::string FormatTimestampUtc(std::time_t value)
{
    if (value == static_cast<std::time_t>(-1))
    {
        return {};
    }
    std::tm tm{};
#if defined(_WIN32)
    gmtime_s(&tm, &value);
#else
    gmtime_r(&value, &tm);
#endif
    std::ostringstream oss;
    oss << std::put_time(&tm, "%Y-%m-%dT%H:%M:%SZ");
    return oss.str();
}

std::time_t FileTimeToTimeT(const fs::file_time_type& tp)
{
    using namespace std::chrono;
    const auto sctp = time_point_cast<system_clock::duration>(tp - fs::file_time_type::clock::now() + system_clock::now());
    return system_clock::to_time_t(sctp);
}

std::string NormalizePath(const std::string& path)
{
    if (path.empty())
    {
        return path;
    }
    try
    {
        const auto canonical = fs::weakly_canonical(fs::u8path(path));
        return canonical.u8string();
    }
    catch (...)
    {
        return path;
    }
}

std::string GetInputTimestamp(const std::string& path)
{
    if (path.empty())
    {
        return {};
    }
    try
    {
        const auto writeTime = fs::last_write_time(fs::u8path(path));
        return FormatTimestampUtc(FileTimeToTimeT(writeTime));
    }
    catch (...)
    {
        return {};
    }
}

class Sha256
{
public:
    Sha256() { reset(); }

    void update(const uint8_t* data, std::size_t len)
    {
        for (std::size_t i = 0; i < len; ++i)
        {
            data_[datalen_] = data[i];
            datalen_++;
            if (datalen_ == 64)
            {
                transform();
                bitlen_ += 512;
                datalen_ = 0;
            }
        }
    }

    std::array<uint8_t, 32> digest()
    {
        std::array<uint8_t, 32> hash{};
        std::size_t i = datalen_;

        // Pad whatever data is left in the buffer.
        if (datalen_ < 56)
        {
            data_[i++] = 0x80;
            while (i < 56)
            {
                data_[i++] = 0x00;
            }
        }
        else
        {
            data_[i++] = 0x80;
            while (i < 64)
            {
                data_[i++] = 0x00;
            }
            transform();
            std::fill(data_.begin(), data_.begin() + 56, 0);
        }

        bitlen_ += static_cast<uint64_t>(datalen_) * 8;
        data_[63] = static_cast<uint8_t>(bitlen_);
        data_[62] = static_cast<uint8_t>(bitlen_ >> 8);
        data_[61] = static_cast<uint8_t>(bitlen_ >> 16);
        data_[60] = static_cast<uint8_t>(bitlen_ >> 24);
        data_[59] = static_cast<uint8_t>(bitlen_ >> 32);
        data_[58] = static_cast<uint8_t>(bitlen_ >> 40);
        data_[57] = static_cast<uint8_t>(bitlen_ >> 48);
        data_[56] = static_cast<uint8_t>(bitlen_ >> 56);
        transform();

        for (i = 0; i < 4; ++i)
        {
            hash[i]      = static_cast<uint8_t>((state_[0] >> (24 - i * 8)) & 0x000000ff);
            hash[i + 4]  = static_cast<uint8_t>((state_[1] >> (24 - i * 8)) & 0x000000ff);
            hash[i + 8]  = static_cast<uint8_t>((state_[2] >> (24 - i * 8)) & 0x000000ff);
            hash[i + 12] = static_cast<uint8_t>((state_[3] >> (24 - i * 8)) & 0x000000ff);
            hash[i + 16] = static_cast<uint8_t>((state_[4] >> (24 - i * 8)) & 0x000000ff);
            hash[i + 20] = static_cast<uint8_t>((state_[5] >> (24 - i * 8)) & 0x000000ff);
            hash[i + 24] = static_cast<uint8_t>((state_[6] >> (24 - i * 8)) & 0x000000ff);
            hash[i + 28] = static_cast<uint8_t>((state_[7] >> (24 - i * 8)) & 0x000000ff);
        }
        return hash;
    }

private:
    static constexpr std::array<uint32_t, 64> k_{
        0x428a2f98U, 0x71374491U, 0xb5c0fbcfU, 0xe9b5dba5U, 0x3956c25bU, 0x59f111f1U, 0x923f82a4U, 0xab1c5ed5U,
        0xd807aa98U, 0x12835b01U, 0x243185beU, 0x550c7dc3U, 0x72be5d74U, 0x80deb1feU, 0x9bdc06a7U, 0xc19bf174U,
        0xe49b69c1U, 0xefbe4786U, 0x0fc19dc6U, 0x240ca1ccU, 0x2de92c6fU, 0x4a7484aaU, 0x5cb0a9dcU, 0x76f988daU,
        0x983e5152U, 0xa831c66dU, 0xb00327c8U, 0xbf597fc7U, 0xc6e00bf3U, 0xd5a79147U, 0x06ca6351U, 0x14292967U,
        0x27b70a85U, 0x2e1b2138U, 0x4d2c6dfcU, 0x53380d13U, 0x650a7354U, 0x766a0abbU, 0x81c2c92eU, 0x92722c85U,
        0xa2bfe8a1U, 0xa81a664bU, 0xc24b8b70U, 0xc76c51a3U, 0xd192e819U, 0xd6990624U, 0xf40e3585U, 0x106aa070U,
        0x19a4c116U, 0x1e376c08U, 0x2748774cU, 0x34b0bcb5U, 0x391c0cb3U, 0x4ed8aa4aU, 0x5b9cca4fU, 0x682e6ff3U,
        0x748f82eeU, 0x78a5636fU, 0x84c87814U, 0x8cc70208U, 0x90befffaU, 0xa4506cebU, 0xbef9a3f7U, 0xc67178f2U};

    static uint32_t rotr(uint32_t x, uint32_t n) { return (x >> n) | (x << (32 - n)); }

    void reset()
    {
        datalen_ = 0;
        bitlen_ = 0;
        state_ = {0x6a09e667U, 0xbb67ae85U, 0x3c6ef372U, 0xa54ff53aU, 0x510e527fU, 0x9b05688cU, 0x1f83d9abU, 0x5be0cd19U};
        data_.fill(0);
    }

    void transform()
    {
        uint32_t m[64];
        uint32_t a, b, c, d, e, f, g, h;

        for (std::size_t i = 0, j = 0; i < 16; ++i, j += 4)
        {
            m[i] = (static_cast<uint32_t>(data_[j]) << 24) |
                   (static_cast<uint32_t>(data_[j + 1]) << 16) |
                   (static_cast<uint32_t>(data_[j + 2]) <<  8) |
                   (static_cast<uint32_t>(data_[j + 3]));
        }

        for (std::size_t i = 16; i < 64; ++i)
        {
            uint32_t s0 = rotr(m[i - 15], 7) ^ rotr(m[i - 15], 18) ^ (m[i - 15] >> 3);
            uint32_t s1 = rotr(m[i - 2], 17) ^ rotr(m[i - 2], 19) ^ (m[i - 2] >> 10);
            m[i] = m[i - 16] + s0 + m[i - 7] + s1;
        }

        a = state_[0];
        b = state_[1];
        c = state_[2];
        d = state_[3];
        e = state_[4];
        f = state_[5];
        g = state_[6];
        h = state_[7];

        for (std::size_t i = 0; i < 64; ++i)
        {
            uint32_t S1 = rotr(e, 6) ^ rotr(e, 11) ^ rotr(e, 25);
            uint32_t ch = (e & f) ^ (~e & g);
            uint32_t temp1 = h + S1 + ch + k_[i] + m[i];
            uint32_t S0 = rotr(a, 2) ^ rotr(a, 13) ^ rotr(a, 22);
            uint32_t maj = (a & b) ^ (a & c) ^ (b & c);
            uint32_t temp2 = S0 + maj;

            h = g;
            g = f;
            f = e;
            e = d + temp1;
            d = c;
            c = b;
            b = a;
            a = temp1 + temp2;
        }

        state_[0] += a;
        state_[1] += b;
        state_[2] += c;
        state_[3] += d;
        state_[4] += e;
        state_[5] += f;
        state_[6] += g;
        state_[7] += h;
    }

    std::array<uint8_t, 64> data_{};
    uint32_t datalen_{0};
    uint64_t bitlen_{0};
    std::array<uint32_t, 8> state_{};
};

std::array<uint8_t, 32> ComputeSha256(const std::vector<uint8_t>& data)
{
    Sha256 ctx;
    if (!data.empty())
    {
        ctx.update(data.data(), data.size());
    }
    return ctx.digest();
}

std::string BytesToHex(const std::array<uint8_t, 32>& bytes)
{
    std::ostringstream oss;
    for (uint8_t b : bytes)
    {
        oss << std::hex << std::nouppercase << std::setw(2) << std::setfill('0') << static_cast<int>(b);
    }
    return oss.str();
}

Options ParseArguments(int argc, char** argv)
{
    if (argc < 2)
    {
        PrintUsageAndExit(1);
    }

    Options opt;
    for (int i = 1; i < argc; ++i)
    {
        std::string arg = argv[i];
        if ((arg == "-h") || (arg == "--help"))
        {
            PrintUsageAndExit(0);
        }
        else if ((arg == "-i" || arg == "--input") && (i + 1 < argc))
        {
            opt.inputPath = argv[++i];
        }
        else if ((arg == "-o" || arg == "--output") && (i + 1 < argc))
        {
            opt.outputPath = argv[++i];
        }
        else if ((arg == "-s" || arg == "--symbol") && (i + 1 < argc))
        {
            opt.symbolName = argv[++i];
        }
        else if ((arg == "-g" || arg == "--guard") && (i + 1 < argc))
        {
            opt.headerGuard = argv[++i];
        }
        else if (arg == "--namespace" && (i + 1 < argc))
        {
            opt.nameSpace = argv[++i];
        }
        else if (arg == "--metadata" && (i + 1 < argc))
        {
            opt.metadataPath = argv[++i];
        }
        else if (arg == "--metadata-only")
        {
            opt.metadataOnly = true;
        }
        else if (arg == "--bytes-per-line" && (i + 1 < argc))
        {
            opt.bytesPerLine = static_cast<std::size_t>(std::stoul(argv[++i]));
            if (opt.bytesPerLine == 0 || opt.bytesPerLine > 32)
            {
                throw std::invalid_argument("--bytes-per-line must be between 1 and 32");
            }
        }
        else
        {
            std::cerr << "Unknown argument: " << arg << "\n";
            PrintUsageAndExit(1);
        }
    }

    if (opt.inputPath.empty() || opt.outputPath.empty())
    {
        std::cerr << "[ERR ] Both --input and --output are required.\n";
        PrintUsageAndExit(1);
    }
    return opt;
}

std::vector<uint8_t> ReadBinaryFile(const std::string& path)
{
    std::ifstream stream(path, std::ios::binary);
    if (!stream)
    {
        throw std::runtime_error("Unable to open input file: " + path);
    }
    std::vector<uint8_t> buffer((std::istreambuf_iterator<char>(stream)), std::istreambuf_iterator<char>());
    if (buffer.empty())
    {
        throw std::runtime_error("Input file is empty: " + path);
    }
    return buffer;
}

void WriteHeader(const Options& opt, const std::vector<uint8_t>& bytes, const std::string& shaHex, const std::string& guard)
{
    std::ofstream out(opt.outputPath, std::ios::binary);
    if (!out)
    {
        throw std::runtime_error("Unable to open output file: " + opt.outputPath);
    }

    const auto namespaces = SplitNamespace(opt.nameSpace);
    const bool emitExternC = namespaces.empty();

    out << "/*\n";
    out << " * Generated by bin2h\n";
    out << " * Source : " << opt.inputPath << "\n";
    out << " * Size   : " << bytes.size() << " bytes\n";
    out << " * SHA256 : " << shaHex << "\n";
    out << " */\n\n";
    out << "#ifndef " << guard << "\n";
    out << "#define " << guard << "\n\n";
    out << "#include <stddef.h>\n";
    out << "#include <stdint.h>\n\n";

    if (emitExternC)
    {
        out << "#ifdef __cplusplus\n";
        out << "extern \"C\" {\n";
        out << "#endif\n\n";
    }

    for (const auto& ns : namespaces)
    {
        out << "namespace " << ns << " {\n";
    }
    if (!namespaces.empty())
    {
        out << "\n";
    }

    if (!opt.metadataOnly)
    {
        out << "static const uint8_t " << opt.symbolName << "[] = {\n    ";
        std::size_t column = 0;
        for (std::size_t i = 0; i < bytes.size(); ++i)
        {
            out << "0x" << std::hex << std::uppercase << std::setw(2) << std::setfill('0')
                << static_cast<int>(bytes[i]);
            if (i + 1 != bytes.size())
            {
                out << ", ";
                if (++column >= opt.bytesPerLine)
                {
                    out << "\n    ";
                    column = 0;
                }
            }
        }
        out << "\n};\n\n";
        out << std::dec << std::nouppercase << std::setfill(' ');
        out << "static const size_t " << opt.symbolName << "_SIZE = sizeof(" << opt.symbolName << ");\n";
    }
    else
    {
        out << std::dec << std::nouppercase << std::setfill(' ');
        out << "static const size_t " << opt.symbolName << "_SIZE = " << bytes.size() << ";\n";
    }
    out << "static const char " << opt.symbolName << "_SHA256[] = \"" << shaHex << "\";\n\n";

    for (auto it = namespaces.rbegin(); it != namespaces.rend(); ++it)
    {
        out << "} // namespace " << *it << "\n";
    }
    if (!namespaces.empty())
    {
        out << "\n";
    }

    if (emitExternC)
    {
        out << "#ifdef __cplusplus\n";
        out << "} // extern \"C\"\n";
        out << "#endif\n\n";
    }

    out << "#endif /* " << guard << " */\n";
}

void WriteMetadata(
    const Options& opt,
    const std::vector<uint8_t>& bytes,
    const std::string& shaHex,
    const std::string& guard,
    const std::string& normalizedInput,
    const std::string& normalizedOutput,
    const std::string& inputTimestamp)
{
    if (opt.metadataPath.empty())
    {
        return;
    }

    std::ofstream meta(opt.metadataPath, std::ios::binary);
    if (!meta)
    {
        throw std::runtime_error("Unable to open metadata output: " + opt.metadataPath);
    }

    const auto generatedAt = FormatTimestampUtc(std::chrono::system_clock::to_time_t(std::chrono::system_clock::now()));
    const auto inputPathForMetadata = normalizedInput.empty() ? opt.inputPath : normalizedInput;
    const auto outputPathForMetadata = normalizedOutput.empty() ? opt.outputPath : normalizedOutput;

    meta << "{\n";
    meta << "  \"input\": \"" << EscapeJson(inputPathForMetadata) << "\",\n";
    meta << "  \"output\": \"" << EscapeJson(outputPathForMetadata) << "\",\n";
    meta << "  \"symbol\": \"" << EscapeJson(opt.symbolName) << "\",\n";
    meta << "  \"size\": " << bytes.size() << ",\n";
    if (!inputTimestamp.empty())
    {
        meta << "  \"input_last_write_time\": \"" << EscapeJson(inputTimestamp) << "\",\n";
    }
    meta << "  \"sha256\": \"" << EscapeJson(shaHex) << "\",\n";
    meta << "  \"generated_at\": \"" << EscapeJson(generatedAt) << "\",\n";
    meta << "  \"header_guard\": \"" << EscapeJson(guard) << "\",\n";
    meta << "  \"bytes_per_line\": " << opt.bytesPerLine << ",\n";
    meta << "  \"metadata_only\": " << (opt.metadataOnly ? "true" : "false");
    if (!opt.nameSpace.empty())
    {
        meta << ",\n  \"namespace\": \"" << EscapeJson(opt.nameSpace) << "\"";
    }
    meta << "\n}\n";
}

} // namespace

int main(int argc, char** argv)
{
    try
    {
        const auto options = ParseArguments(argc, argv);
        const auto bytes = ReadBinaryFile(options.inputPath);
        const auto sha = ComputeSha256(bytes);
        const auto shaHex = BytesToHex(sha);
        const auto guard = DeriveGuard(options);
        const auto normalizedInput = NormalizePath(options.inputPath);
        const auto normalizedOutput = NormalizePath(options.outputPath);
        const auto inputTimestamp = GetInputTimestamp(options.inputPath);

        WriteHeader(options, bytes, shaHex, guard);
        WriteMetadata(options, bytes, shaHex, guard, normalizedInput, normalizedOutput, inputTimestamp);

        std::cout << "[OK ] Generated header: " << options.outputPath << "\n";
        std::cout << "[INFO] Symbol: " << options.symbolName << " (" << bytes.size() << " bytes)\n";
        return 0;
    }
    catch (const std::exception& ex)
    {
        std::cerr << "[ERR ] " << ex.what() << "\n";
        return 1;
    }
}

