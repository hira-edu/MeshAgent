/*
 * MeshAgent build configuration for the vendored libopus encoder.
 *
 * Upstream: libopus 1.5.2 release tarball
 *   https://downloads.xiph.org/releases/opus/opus-1.5.2.tar.gz
 *   SHA-256 65c1d2f78b9f2fb20082c38cbe47c951ad5839345876e46941612ee87f9a7ce1
 *
 * This is the only MeshAgent-authored file under opus/. Every other file is
 * copied unmodified from the release. It takes the place of the win32/config.h
 * that upstream shipped for Visual Studio before 1.4, and selects the same
 * options that upstream's CMake build selects for MSVC unless noted below.
 * Sources compiled with it define HAVE_CONFIG_H and use opus, opus/include,
 * opus/celt, opus/silk and opus/silk/float as their include path (see the
 * libopus items in meshservice/MeshService-2022.vcxproj).
 *
 * The vendored sources are the subset of upstream's opus_sources.mk,
 * celt_sources.mk and silk_sources.mk lists (floating-point and x86 SSE
 * variants) that the encoder API links against: opus_encoder_create,
 * opus_encoder_ctl, opus_encode, opus_encode_float, opus_encoder_destroy,
 * opus_strerror and opus_get_version_string. The decoder core is part of that
 * set because the encoder's repacketizer calls into src/opus_decoder.c.
 * Multistream, projection, DNN (DRED/OSCE/deep PLC), custom-mode, ARM, MIPS
 * and fixed-point sources are not vendored, nor are upstream's tests, tools
 * and build scripts.
 */
#ifndef MESHAGENT_OPUS_CONFIG_H
#define MESHAGENT_OPUS_CONFIG_H

#define OPUS_BUILD 1
#define PACKAGE_VERSION "1.5.2"

/*
 * Floating-point build on every target. The capture path converts the WASAPI
 * loopback stream to 48 kHz stereo 16-bit PCM and calls opus_encode, and every
 * Windows target (x86, x64, ARM64) has a hardware FPU. Fixed point only pays
 * off on cores without one, and it is not what upstream builds by default.
 */
/* #undef FIXED_POINT */

/*
 * MSVC has no C99 variable-length arrays, so scratch buffers use _alloca
 * (celt/stack_alloc.h selects _alloca for _WIN32), exactly as upstream's
 * Visual Studio configuration did.
 */
#define USE_ALLOCA 1

/* Present in the UCRT and MinGW runtimes; upstream CMake detects and defines both. */
#define HAVE_LRINT 1
#define HAVE_LRINTF 1

/*
 * Upstream's production default since 1.5: cheap internal invariant checks
 * that abort the process instead of continuing with corrupt codec state.
 * The encoder only runs inside the short-lived audio helper process, so an
 * abort ends that helper and the agent reports the stream as failed.
 */
#define ENABLE_HARDENING 1

#if defined(_M_IX86) || defined(_M_X64) || defined(__i386__) || defined(__x86_64__)
/*
 * x86/x64: SSE, SSE2 and SSE4.1 intrinsics. MSVC compiles these without any
 * /arch switch. SSE and SSE2 are presumed whenever the compiler already
 * targets them: always on x64, and on x86 because MSVC defaults to
 * /arch:SSE2 (_M_IX86_FP == 2), which the rest of the service DLL already
 * requires. SSE4.1 is selected at run time through the RTCD tables
 * (celt/x86/x86cpu.c uses __cpuid), so the DLL still loads and encodes on
 * CPUs without it.
 *
 * AVX2 is deliberately not enabled: upstream compiles those sources with a
 * per-file /arch:AVX2, and a single 48 kHz stereo 64 kbps stream is far from
 * CPU-bound with the SSE4.1 paths, so the extra build surface buys nothing
 * measurable.
 */
#define OPUS_X86_MAY_HAVE_SSE 1
#define OPUS_X86_MAY_HAVE_SSE2 1
#define OPUS_X86_MAY_HAVE_SSE4_1 1

#if defined(_M_X64) || defined(__x86_64__) || (defined(_M_IX86_FP) && _M_IX86_FP >= 1) || defined(__SSE__)
#define OPUS_X86_PRESUME_SSE 1
#endif
#if defined(_M_X64) || defined(__x86_64__) || (defined(_M_IX86_FP) && _M_IX86_FP >= 2) || defined(__SSE2__)
#define OPUS_X86_PRESUME_SSE2 1
#endif

#define OPUS_HAVE_RTCD 1

/* MSVC reads CPUID through <intrin.h>; GCC/Clang (used for compile checks) through <cpuid.h>. */
#if !defined(_MSC_VER)
#define CPU_INFO_BY_C 1
#endif
#endif

/*
 * ARM64 builds the portable C implementation without NEON intrinsics or RTCD.
 * The encoder load is small on every Windows ARM64 device, and keeping the
 * ARM64 service DLL on the same C code paths as the reference implementation
 * avoids a separate, separately validated intrinsics build.
 */

#endif /* MESHAGENT_OPUS_CONFIG_H */
