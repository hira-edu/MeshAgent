/*
Copyright 2006 - 2022 Intel Corporation

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

	http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

#ifdef WIN32
#include <winsock2.h>
#include <ws2tcpip.h>

#include <Windows.h>
#include <WinBase.h>
#endif

#include "duktape.h"
#include "ILibDuktape_Helpers.h"
#include "ILibDuktapeModSearch.h"
#include "ILibDuktape_DuplexStream.h"
#include "ILibDuktape_EventEmitter.h"
#include "ILibDuktape_Debugger.h"
#include "../microstack/ILibParsers.h"
#include "../microstack/ILibCrypto.h"
#include "../microstack/ILibRemoteLogging.h"

#ifdef _POSIX
	#ifdef __APPLE__
		#include <util.h>
	#else
		#include <termios.h>
	#endif
#endif


#define ILibDuktape_Timer_Ptrs					"\xFF_DuktapeTimer_PTRS"
#define ILibDuktape_Queue_Ptr					"\xFF_Queue"
#define ILibDuktape_Stream_Buffer				"\xFF_BUFFER"
#define ILibDuktape_Stream_ReadablePtr			"\xFF_ReadablePtr"
#define ILibDuktape_Stream_WritablePtr			"\xFF_WritablePtr"
#define ILibDuktape_Console_Destination			"\xFF_Console_Destination"
#define ILibDuktape_Console_LOG_Destination		"\xFF_Console_Destination"
#define ILibDuktape_Console_WARN_Destination	"\xFF_Console_WARN_Destination"
#define ILibDuktape_Console_ERROR_Destination	"\xFF_Console_ERROR_Destination"
#define ILibDuktape_Console_INFO_Level			"\xFF_Console_INFO_Level"
#define ILibDuktape_Console_SessionID			"\xFF_Console_SessionID"

#define ILibDuktape_DescriptorEvents_ChainLink	"\xFF_DescriptorEvents_ChainLink"
#define ILibDuktape_DescriptorEvents_Table		"\xFF_DescriptorEvents_Table"
#define ILibDuktape_DescriptorEvents_HTable		"\xFF_DescriptorEvents_HTable"
#define ILibDuktape_DescriptorEvents_CURRENT	"\xFF_DescriptorEvents_CURRENT"
#define ILibDuktape_DescriptorEvents_FD			"\xFF_DescriptorEvents_FD"
#define ILibDuktape_DescriptorEvents_Options	"\xFF_DescriptorEvents_Options"
#define ILibDuktape_DescriptorEvents_WaitHandle "\xFF_DescriptorEvents_WindowsWaitHandle"
#define ILibDuktape_ChainViewer_PromiseList		"\xFF_ChainViewer_PromiseList"
#define CP_ISO8859_1							28591

#define ILibDuktape_AltRequireTable				"\xFF_AltRequireTable"
#define ILibDuktape_AddCompressedModule(ctx, name, b64str) duk_push_global_object(ctx);duk_get_prop_string(ctx, -1, "addCompressedModule");duk_swap_top(ctx, -2);duk_push_string(ctx, name);duk_push_global_object(ctx);duk_get_prop_string(ctx, -1, "Buffer"); duk_remove(ctx, -2);duk_get_prop_string(ctx, -1, "from");duk_swap_top(ctx, -2);duk_push_string(ctx, b64str);duk_push_string(ctx, "base64");duk_pcall_method(ctx, 2);duk_pcall_method(ctx, 2);duk_pop(ctx);
#define ILibDuktape_AddCompressedModuleEx(ctx, name, b64str, stamp) duk_push_global_object(ctx);duk_get_prop_string(ctx, -1, "addCompressedModule");duk_swap_top(ctx, -2);duk_push_string(ctx, name);duk_push_global_object(ctx);duk_get_prop_string(ctx, -1, "Buffer"); duk_remove(ctx, -2);duk_get_prop_string(ctx, -1, "from");duk_swap_top(ctx, -2);duk_push_string(ctx, b64str);duk_push_string(ctx, "base64");duk_pcall_method(ctx, 2);duk_push_string(ctx,stamp);duk_pcall_method(ctx, 3);duk_pop(ctx);

extern void* _duk_get_first_object(void *ctx);
extern void* _duk_get_next_object(void *ctx, void *heapptr);
extern duk_ret_t ModSearchTable_Get(duk_context *ctx, duk_idx_t table, char *key, char *id);


typedef enum ILibDuktape_Console_DestinationFlags
{
	ILibDuktape_Console_DestinationFlags_DISABLED		= 0,
	ILibDuktape_Console_DestinationFlags_StdOut			= 1,
	ILibDuktape_Console_DestinationFlags_ServerConsole	= 2,
	ILibDuktape_Console_DestinationFlags_WebLog			= 4,
	ILibDuktape_Console_DestinationFlags_LogFile		= 8
}ILibDuktape_Console_DestinationFlags;

#ifdef WIN32
typedef struct ILibDuktape_DescriptorEvents_WindowsWaitHandle
{
	HANDLE waitHandle;
	HANDLE eventThread;
	void *chain;
	duk_context *ctx;
	void *object;
}ILibDuktape_DescriptorEvents_WindowsWaitHandle;
#endif

int g_displayStreamPipeMessages = 0;
int g_displayFinalizerMessages = 0;
extern int GenerateSHA384FileHash(char *filePath, char *fileHash);

duk_ret_t ILibDuktape_Pollyfills_Buffer_slice(duk_context *ctx)
{
	int nargs = duk_get_top(ctx);
	char *buffer;
	char *out;
	duk_size_t bufferLen;
	int offset = 0;
	duk_push_this(ctx);

	buffer = Duktape_GetBuffer(ctx, -1, &bufferLen);
	if (nargs >= 1)
	{
		offset = duk_require_int(ctx, 0);
		bufferLen -= offset;
	}
	if (nargs == 2)
	{
		bufferLen = (duk_size_t)duk_require_int(ctx, 1) - offset;
	}
	duk_push_fixed_buffer(ctx, bufferLen);
	out = Duktape_GetBuffer(ctx, -1, NULL);
	memcpy_s(out, bufferLen, buffer + offset, bufferLen);
	return 1;
}
duk_ret_t ILibDuktape_Polyfills_Buffer_randomFill(duk_context *ctx)
{
	int start, length;
	char *buffer;
	duk_size_t bufferLen;

	start = (int)(duk_get_top(ctx) == 0 ? 0 : duk_require_int(ctx, 0));
	length = (int)(duk_get_top(ctx) == 2 ? duk_require_int(ctx, 1) : -1);

	duk_push_this(ctx);
	buffer = (char*)Duktape_GetBuffer(ctx, -1, &bufferLen);
	if ((duk_size_t)length > bufferLen || length < 0)
	{
		length = (int)(bufferLen - start);
	}

	util_random(length, buffer + start);
	return(0);
}
duk_ret_t ILibDuktape_Polyfills_Buffer_toString(duk_context *ctx)
{
	int nargs = duk_get_top(ctx);
	char *buffer, *tmpBuffer;
	duk_size_t bufferLen = 0;
	char *cType;

	duk_push_this(ctx);									// [buffer]
	buffer = Duktape_GetBuffer(ctx, -1, &bufferLen);

	if (nargs == 0)
	{
		if (bufferLen == 0 || buffer == NULL)
		{
			duk_push_null(ctx);
		}
		else
		{
			// External stream buffers need not have a trailing NUL. The POSIX
			// strnlen_s compatibility macro calls strlen before applying its bound.
			char *terminator = (char*)memchr(buffer, 0, bufferLen);
			duk_push_lstring(ctx, buffer, terminator == NULL ? bufferLen : (duk_size_t)(terminator - buffer));
		}
	}
	else
	{
		cType = (char*)duk_require_string(ctx, 0);
		if (strcmp(cType, "base64") == 0)
		{
			duk_push_fixed_buffer(ctx, ILibBase64EncodeLength(bufferLen));
			tmpBuffer = Duktape_GetBuffer(ctx, -1, NULL);
			ILibBase64Encode((unsigned char*)buffer, (int)bufferLen, (unsigned char**)&tmpBuffer);
			duk_push_string(ctx, tmpBuffer);
		}
		else if (strcmp(cType, "hex") == 0)
		{
			duk_push_fixed_buffer(ctx, 1 + (bufferLen * 2));
			tmpBuffer = Duktape_GetBuffer(ctx, -1, NULL);
			util_tohex(buffer, (int)bufferLen, tmpBuffer);
			duk_push_string(ctx, tmpBuffer);
		}
		else if (strcmp(cType, "hex:") == 0)
		{
			duk_push_fixed_buffer(ctx, 1 + (bufferLen * 3));
			tmpBuffer = Duktape_GetBuffer(ctx, -1, NULL);
			util_tohex2(buffer, (int)bufferLen, tmpBuffer);
			duk_push_string(ctx, tmpBuffer);
		}
#ifdef WIN32
		else if (strcmp(cType, "utf16") == 0)
		{
			int sz = (MultiByteToWideChar(CP_UTF8, 0, buffer, (int)bufferLen, NULL, 0) * 2);
			WCHAR* b = duk_push_fixed_buffer(ctx, sz);
			duk_push_buffer_object(ctx, -1, 0, sz, DUK_BUFOBJ_NODEJS_BUFFER);
			MultiByteToWideChar(CP_UTF8, 0, buffer, (int)bufferLen, b, sz / 2);
		}
#endif
		else
		{
			return(ILibDuktape_Error(ctx, "Unrecognized parameter"));
		}
	}
	return 1;
}
duk_ret_t ILibDuktape_Polyfills_Buffer_from(duk_context *ctx)
{
	int nargs = duk_get_top(ctx);
	char *str;
	duk_size_t strlength;
	char *encoding;
	char *buffer;
	size_t bufferLen;

	if (nargs == 1)
	{
		str = (char*)duk_get_lstring(ctx, 0, &strlength);
		buffer = duk_push_fixed_buffer(ctx, strlength);
		memcpy_s(buffer, strlength, str, strlength);
		duk_push_buffer_object(ctx, -1, 0, strlength, DUK_BUFOBJ_NODEJS_BUFFER);
		return(1);
	}
	else if(!(nargs == 2 && duk_is_string(ctx, 0) && duk_is_string(ctx, 1)))
	{
		return(ILibDuktape_Error(ctx, "usage not supported yet"));
	}

	str = (char*)duk_get_lstring(ctx, 0, &strlength);
	encoding = (char*)duk_require_string(ctx, 1);

	if (strcmp(encoding, "base64") == 0)
	{
		// Base64		
		buffer = duk_push_fixed_buffer(ctx, ILibBase64DecodeLength(strlength));
		bufferLen = ILibBase64Decode((unsigned char*)str, (int)strlength, (unsigned char**)&buffer);
		duk_push_buffer_object(ctx, -1, 0, bufferLen, DUK_BUFOBJ_NODEJS_BUFFER);
	}
	else if (strcmp(encoding, "hex") == 0)
	{		
		if (ILibString_StartsWith(str, (int)strlength, "0x", 2) != 0)
		{
			str += 2;
			strlength -= 2;
		}
		buffer = duk_push_fixed_buffer(ctx, strlength / 2);
		bufferLen = util_hexToBuf(str, (int)strlength, buffer);
		duk_push_buffer_object(ctx, -1, 0, bufferLen, DUK_BUFOBJ_NODEJS_BUFFER);
	}
	else if (strcmp(encoding, "utf8") == 0)
	{
		str = (char*)duk_get_lstring(ctx, 0, &strlength);
		buffer = duk_push_fixed_buffer(ctx, strlength);
		memcpy_s(buffer, strlength, str, strlength);
		duk_push_buffer_object(ctx, -1, 0, strlength, DUK_BUFOBJ_NODEJS_BUFFER);
		return(1);
	}
	else if (strcmp(encoding, "binary") == 0)
	{
		str = (char*)duk_get_lstring(ctx, 0, &strlength);

#ifdef WIN32
		int r = MultiByteToWideChar(CP_UTF8, 0, (LPCCH)str, (int)strlength, NULL, 0);
		buffer = duk_push_fixed_buffer(ctx, 2 + (2 * r));
		strlength = (duk_size_t)MultiByteToWideChar(CP_UTF8, 0, (LPCCH)str, (int)strlength, (LPWSTR)buffer, r + 1);
		r = (int)WideCharToMultiByte(CP_ISO8859_1, 0, (LPCWCH)buffer, (int)strlength, NULL, 0, NULL, FALSE);
		duk_push_fixed_buffer(ctx, r);
		WideCharToMultiByte(CP_ISO8859_1, 0, (LPCWCH)buffer, (int)strlength, (LPSTR)Duktape_GetBuffer(ctx, -1, NULL), r, NULL, FALSE);
		duk_push_buffer_object(ctx, -1, 0, r, DUK_BUFOBJ_NODEJS_BUFFER);
#else
		duk_eval_string(ctx, "Buffer.fromBinary");	// [func]
		duk_dup(ctx, 0);
		duk_call(ctx, 1);
#endif
	}
	else
	{
		return(ILibDuktape_Error(ctx, "unsupported encoding"));
	}
	return 1;
}
duk_ret_t ILibDuktape_Polyfills_Buffer_readInt32BE(duk_context *ctx)
{
	int offset = duk_require_int(ctx, 0);
	char *buffer;
	duk_size_t bufferLen;

	duk_push_this(ctx);
	buffer = Duktape_GetBuffer(ctx, -1, &bufferLen);

	duk_push_int(ctx, ntohl(((int*)(buffer + offset))[0]));
	return(1);
}
duk_ret_t ILibDuktape_Polyfills_Buffer_alloc(duk_context *ctx)
{
	int sz = duk_require_int(ctx, 0);
	int fill = 0;

	if (duk_is_number(ctx, 1)) { fill = duk_require_int(ctx, 1); }

	duk_push_fixed_buffer(ctx, sz);
	char *buffer = Duktape_GetBuffer(ctx, -1, NULL);
	memset(buffer, fill, sz);
	duk_push_buffer_object(ctx, -1, 0, sz, DUK_BUFOBJ_NODEJS_BUFFER);
	return(1);
}

void ILibDuktape_Polyfills_Buffer(duk_context *ctx)
{
	char extras[] =
		"Object.defineProperty(Buffer.prototype, \"swap32\",\
	{\
		value: function swap32()\
		{\
			var a = this.readUInt16BE(0);\
			var b = this.readUInt16BE(2);\
			this.writeUInt16LE(a, 2);\
			this.writeUInt16LE(b, 0);\
			return(this);\
		}\
	});";
	duk_eval_string(ctx, extras); duk_pop(ctx);

#ifdef _POSIX
	char fromBinary[] =
		"Object.defineProperty(Buffer, \"fromBinary\",\
		{\
			get: function()\
			{\
				return((function fromBinary(str)\
						{\
							var child = require('child_process').execFile('/usr/bin/iconv', ['iconv', '-c','-f', 'UTF-8', '-t', 'CP819']);\
							child.stdout.buf = Buffer.alloc(0);\
							child.stdout.on('data', function(c) { this.buf = Buffer.concat([this.buf, c]); });\
							child.stdin.write(str);\
							child.stderr.on('data', function(c) { });\
							child.stdin.end();\
							child.waitExit();\
							return(child.stdout.buf);\
						}));\
			}\
		});";
	duk_eval_string_noresult(ctx, fromBinary);

#endif

	// Polyfill Buffer.from()
	duk_get_prop_string(ctx, -1, "Buffer");											// [g][Buffer]
	duk_push_c_function(ctx, ILibDuktape_Polyfills_Buffer_from, DUK_VARARGS);		// [g][Buffer][func]
	duk_put_prop_string(ctx, -2, "from");											// [g][Buffer]
	duk_pop(ctx);																	// [g]

	// Polyfill Buffer.alloc() for Node Buffers)
	duk_get_prop_string(ctx, -1, "Buffer");											// [g][Buffer]
	duk_push_c_function(ctx, ILibDuktape_Polyfills_Buffer_alloc, DUK_VARARGS);		// [g][Buffer][func]
	duk_put_prop_string(ctx, -2, "alloc");											// [g][Buffer]
	duk_pop(ctx);																	// [g]


	// Polyfill Buffer.toString() for Node Buffers
	duk_get_prop_string(ctx, -1, "Buffer");											// [g][Buffer]
	duk_get_prop_string(ctx, -1, "prototype");										// [g][Buffer][prototype]
	duk_push_c_function(ctx, ILibDuktape_Polyfills_Buffer_toString, DUK_VARARGS);	// [g][Buffer][prototype][func]
	duk_put_prop_string(ctx, -2, "toString");										// [g][Buffer][prototype]
	duk_push_c_function(ctx, ILibDuktape_Polyfills_Buffer_randomFill, DUK_VARARGS);	// [g][Buffer][prototype][func]
	duk_put_prop_string(ctx, -2, "randomFill");										// [g][Buffer][prototype]
	duk_pop_2(ctx);																	// [g]
}
duk_ret_t ILibDuktape_Polyfills_String_startsWith(duk_context *ctx)
{
	duk_size_t tokenLen;
	char *token = Duktape_GetBuffer(ctx, 0, &tokenLen);
	char *buffer;
	duk_size_t bufferLen;

	duk_push_this(ctx);
	buffer = Duktape_GetBuffer(ctx, -1, &bufferLen);

	if (ILibString_StartsWith(buffer, (int)bufferLen, token, (int)tokenLen) != 0)
	{
		duk_push_true(ctx);
	}
	else
	{
		duk_push_false(ctx);
	}

	return 1;
}
duk_ret_t ILibDuktape_Polyfills_String_endsWith(duk_context *ctx)
{
	duk_size_t tokenLen;
	char *token = Duktape_GetBuffer(ctx, 0, &tokenLen);
	char *buffer;
	duk_size_t bufferLen;

	duk_push_this(ctx);
	buffer = Duktape_GetBuffer(ctx, -1, &bufferLen);
	
	if (ILibString_EndsWith(buffer, (int)bufferLen, token, (int)tokenLen) != 0)
	{
		duk_push_true(ctx);
	}
	else
	{
		duk_push_false(ctx);
	}

	return 1;
}
duk_ret_t ILibDuktape_Polyfills_String_padStart(duk_context *ctx)
{
	int totalLen = (int)duk_require_int(ctx, 0);

	duk_size_t padcharLen;
	duk_size_t bufferLen;

	char *padchars;
	if (duk_get_top(ctx) > 1)
	{
		padchars = (char*)duk_get_lstring(ctx, 1, &padcharLen);
	}
	else
	{
		padchars = " ";
		padcharLen = 1;
	}

	duk_push_this(ctx);
	char *buffer = Duktape_GetBuffer(ctx, -1, &bufferLen);

	if ((int)bufferLen > totalLen)
	{
		duk_push_lstring(ctx, buffer, bufferLen);
		return(1);
	}
	else
	{
		duk_size_t needs = totalLen - bufferLen;

		duk_push_array(ctx);											// [array]
		while(needs > 0)
		{
			if (needs > padcharLen)
			{
				duk_push_string(ctx, padchars);							// [array][pad]
				duk_put_prop_index(ctx, -2, (duk_uarridx_t)duk_get_length(ctx, -2));	// [array]
				needs -= padcharLen;
			}
			else
			{
				duk_push_lstring(ctx, padchars, needs);					// [array][pad]
				duk_put_prop_index(ctx, -2, (duk_uarridx_t)duk_get_length(ctx, -2));	// [array]
				needs = 0;
			}
		}
		duk_push_lstring(ctx, buffer, bufferLen);						// [array][pad]
		duk_put_prop_index(ctx, -2, (duk_uarridx_t)duk_get_length(ctx, -2));			// [array]
		duk_get_prop_string(ctx, -1, "join");							// [array][join]
		duk_swap_top(ctx, -2);											// [join][this]
		duk_push_string(ctx, "");										// [join][this]['']
		duk_call_method(ctx, 1);										// [result]
		return(1);
	}
}
duk_ret_t ILibDuktape_Polyfills_Array_includes(duk_context *ctx)
{
	duk_push_this(ctx);										// [array]
	uint32_t count = (uint32_t)duk_get_length(ctx, -1);
	uint32_t i;
	for (i = 0; i < count; ++i)
	{
		duk_get_prop_index(ctx, -1, (duk_uarridx_t)i);		// [array][val1]
		duk_dup(ctx, 0);									// [array][val1][val2]
		if (duk_equals(ctx, -2, -1))
		{
			duk_push_true(ctx);
			return(1);
		}
		else
		{
			duk_pop_2(ctx);									// [array]
		}
	}
	duk_push_false(ctx);
	return(1);
}
duk_ret_t ILibDuktape_Polyfills_Array_partialIncludes(duk_context *ctx)
{
	duk_size_t inLen;
	char *inStr = (char*)duk_get_lstring(ctx, 0, &inLen);
	duk_push_this(ctx);										// [array]
	uint32_t count = (uint32_t)duk_get_length(ctx, -1);
	uint32_t i;
	duk_size_t tmpLen;
	char *tmp;
	for (i = 0; i < count; ++i)
	{
		tmp = Duktape_GetStringPropertyIndexValueEx(ctx, -1, i, "", &tmpLen);
		if (inLen > 0 && inLen <= tmpLen && strncmp(inStr, tmp, inLen) == 0)
		{
			duk_push_int(ctx, i);
			return(1);
		}
	}
	duk_push_int(ctx, -1);
	return(1);
}
duk_ret_t ILibDuktape_Polyfills_Array_find(duk_context *ctx)
{
	duk_push_this(ctx);								// [array]
	duk_prepare_method_call(ctx, -1, "findIndex");	// [array][findIndex][this]
	duk_dup(ctx, 0);								// [array][findIndex][this][func]
	duk_call_method(ctx, 1);						// [array][result]
	if (duk_get_int(ctx, -1) == -1) { duk_push_undefined(ctx); return(1); }
	duk_get_prop(ctx, -2);							// [element]
	return(1);
}
duk_ret_t ILibDuktape_Polyfills_Array_findIndex(duk_context *ctx)
{
	duk_idx_t nargs = duk_get_top(ctx);
	duk_push_this(ctx);								// [array]

	duk_size_t sz = duk_get_length(ctx, -1);
	duk_uarridx_t i;

	for (i = 0; i < sz; ++i)
	{
		duk_dup(ctx, 0);							// [array][func]
		if (nargs > 1 && duk_is_function(ctx, 1))
		{
			duk_dup(ctx, 1);						// [array][func][this]
		}
		else
		{
			duk_push_this(ctx);						// [array][func][this]
		}
		duk_get_prop_index(ctx, -3, i);				// [array][func][this][element]
		duk_push_uint(ctx, i);						// [array][func][this][element][index]
		duk_push_this(ctx);							// [array][func][this][element][index][array]
		duk_call_method(ctx, 3);					// [array][ret]
		if (!duk_is_undefined(ctx, -1) && duk_is_boolean(ctx, -1) && duk_to_boolean(ctx, -1) != 0)
		{
			duk_push_uint(ctx, i);
			return(1);
		}
		duk_pop(ctx);								// [array]
	}
	duk_push_int(ctx, -1);
	return(1);
}
void ILibDuktape_Polyfills_Array(duk_context *ctx)
{
	duk_get_prop_string(ctx, -1, "Array");											// [Array]
	duk_get_prop_string(ctx, -1, "prototype");										// [Array][proto]

	// Polyfill 'Array.includes'
	ILibDuktape_CreateProperty_InstanceMethod_SetEnumerable(ctx, "includes", ILibDuktape_Polyfills_Array_includes, 1, 0);

	// Polyfill 'Array.partialIncludes'
	ILibDuktape_CreateProperty_InstanceMethod_SetEnumerable(ctx, "partialIncludes", ILibDuktape_Polyfills_Array_partialIncludes, 1, 0);

	// Polyfill 'Array.find'
	ILibDuktape_CreateProperty_InstanceMethod_SetEnumerable(ctx, "find", ILibDuktape_Polyfills_Array_find, 1, 0);

	// Polyfill 'Array.findIndex'
	ILibDuktape_CreateProperty_InstanceMethod_SetEnumerable(ctx, "findIndex", ILibDuktape_Polyfills_Array_findIndex, DUK_VARARGS, 0);
	duk_pop_2(ctx);																	// ...
}
duk_ret_t ILibDuktape_Polyfills_String_splitEx(duk_context *ctx)
{
	duk_ret_t ret = 1;

	if (duk_is_null_or_undefined(ctx, 0))
	{
		duk_push_array(ctx);		// [array]
		duk_push_this(ctx);			// [array][string]
		duk_array_push(ctx, -2);	// [array]
	}
	else if (duk_is_string(ctx, 0))
	{
		const char *delim, *str;
		duk_size_t delimLen, strLen;

		duk_push_this(ctx);
		delim = duk_to_lstring(ctx, 0, &delimLen);
		str = duk_to_lstring(ctx, -1, &strLen);

		parser_result *pr = ILibParseStringAdv(str, 0, strLen, delim, delimLen);
		parser_result_field *f = pr->FirstResult;

		duk_push_array(ctx);
		while (f != NULL)
		{
			duk_push_lstring(ctx, f->data, f->datalength);
			duk_array_push(ctx, -2);
			f = f->NextResult;
		}

		ILibDestructParserResults(pr);
	}
	else
	{
		ret = ILibDuktape_Error(ctx, "Invalid Arguments");
	}
	return(ret);
}
void ILibDuktape_Polyfills_String(duk_context *ctx)
{
	// Polyfill 'String.startsWith'
	duk_get_prop_string(ctx, -1, "String");											// [string]
	duk_get_prop_string(ctx, -1, "prototype");										// [string][proto]
	duk_push_c_function(ctx, ILibDuktape_Polyfills_String_startsWith, DUK_VARARGS);	// [string][proto][func]
	duk_put_prop_string(ctx, -2, "startsWith");										// [string][proto]
	duk_push_c_function(ctx, ILibDuktape_Polyfills_String_endsWith, DUK_VARARGS);	// [string][proto][func]
	duk_put_prop_string(ctx, -2, "endsWith");										// [string][proto]
	duk_push_c_function(ctx, ILibDuktape_Polyfills_String_padStart, DUK_VARARGS);	// [string][proto][func]
	duk_put_prop_string(ctx, -2, "padStart");										// [string][proto]
	duk_push_c_function(ctx, ILibDuktape_Polyfills_String_splitEx, DUK_VARARGS);	// [string][proto][func]
	duk_put_prop_string(ctx, -2, "splitEx");										// [string][proto]
	duk_pop_2(ctx);
}
duk_ret_t ILibDuktape_Polyfills_Console_log(duk_context *ctx)
{
	int numargs = duk_get_top(ctx);
	int i, x;
	duk_size_t strLen;
	char *str;
	char *PREFIX = NULL;
	char *DESTINATION = NULL;
	duk_push_current_function(ctx);
	ILibDuktape_LogTypes logType = (ILibDuktape_LogTypes)Duktape_GetIntPropertyValue(ctx, -1, "logType", ILibDuktape_LogType_Normal);
	switch (logType)
	{
		case ILibDuktape_LogType_Warn:
			PREFIX = (char*)"WARNING: "; // LENGTH MUST BE <= 9
			DESTINATION = ILibDuktape_Console_WARN_Destination;
			break;
		case ILibDuktape_LogType_Error:
			PREFIX = (char*)"ERROR: "; // LENGTH MUST BE <= 9
			DESTINATION = ILibDuktape_Console_ERROR_Destination;
			break;
		case ILibDuktape_LogType_Info1:
		case ILibDuktape_LogType_Info2:
		case ILibDuktape_LogType_Info3:
			duk_push_this(ctx);
			i = Duktape_GetIntPropertyValue(ctx, -1, ILibDuktape_Console_INFO_Level, 0);
			duk_pop(ctx);
			PREFIX = NULL;
			if (i >= (((int)logType + 1) - (int)ILibDuktape_LogType_Info1))
			{
				DESTINATION = ILibDuktape_Console_LOG_Destination;
			}
			else
			{
				return(0);
			}
			break;
		default:
			PREFIX = NULL;
			DESTINATION = ILibDuktape_Console_LOG_Destination;
			break;
	}
	duk_pop(ctx);

	// Calculate total length of string
	strLen = 0;
	strLen += snprintf(NULL, 0, "%s", PREFIX != NULL ? PREFIX : "");
	for (i = 0; i < numargs; ++i)
	{
		if (duk_is_string(ctx, i))
		{
			strLen += snprintf(NULL, 0, "%s%s", (i == 0 ? "" : ", "), duk_require_string(ctx, i));
		}
		else
		{
			duk_dup(ctx, i);
			if (strcmp("[object Object]", duk_to_string(ctx, -1)) == 0)
			{
				duk_pop(ctx);
				duk_dup(ctx, i);
				strLen += snprintf(NULL, 0, "%s", (i == 0 ? "{" : ", {"));
				duk_enum(ctx, -1, DUK_ENUM_OWN_PROPERTIES_ONLY);
				int propNum = 0;
				while (duk_next(ctx, -1, 1))
				{
					strLen += snprintf(NULL, 0, "%s%s: %s", ((propNum++ == 0) ? " " : ", "), (char*)duk_to_string(ctx, -2), (char*)duk_to_string(ctx, -1));
					duk_pop_2(ctx);
				}
				duk_pop(ctx);
				strLen += snprintf(NULL, 0, " }");
			}
			else
			{
				strLen += snprintf(NULL, 0, "%s%s", (i == 0 ? "" : ", "), duk_to_string(ctx, -1));
			}
		}
	}
	strLen += snprintf(NULL, 0, "\n");
	strLen += 1;

	str = Duktape_PushBuffer(ctx, strLen);
	x = 0;
	for (i = 0; i < numargs; ++i)
	{
		if (duk_is_string(ctx, i))
		{
			x += sprintf_s(str + x, strLen - x, "%s%s", (i == 0 ? "" : ", "), duk_require_string(ctx, i));
		}
		else
		{
			duk_dup(ctx, i);
			if (strcmp("[object Object]", duk_to_string(ctx, -1)) == 0)
			{
				duk_pop(ctx);
				duk_dup(ctx, i);
				x += sprintf_s(str+x, strLen - x, "%s", (i == 0 ? "{" : ", {"));
				duk_enum(ctx, -1, DUK_ENUM_OWN_PROPERTIES_ONLY);
				int propNum = 0;
				while (duk_next(ctx, -1, 1))
				{
					x += sprintf_s(str + x, strLen - x, "%s%s: %s", ((propNum++ == 0) ? " " : ", "), (char*)duk_to_string(ctx, -2), (char*)duk_to_string(ctx, -1));
					duk_pop_2(ctx);
				}
				duk_pop(ctx);
				x += sprintf_s(str + x, strLen - x, " }");
			}
			else
			{
				x += sprintf_s(str + x, strLen - x, "%s%s", (i == 0 ? "" : ", "), duk_to_string(ctx, -1));
			}
		}
	}
	x += sprintf_s(str + x, strLen - x, "\n");

	duk_push_this(ctx);		// [console]
	int dest = Duktape_GetIntPropertyValue(ctx, -1, DESTINATION, ILibDuktape_Console_DestinationFlags_StdOut);

	if ((dest & ILibDuktape_Console_DestinationFlags_StdOut) == ILibDuktape_Console_DestinationFlags_StdOut)
	{
#ifdef WIN32
		DWORD writeLen;
		WriteFile(GetStdHandle(STD_OUTPUT_HANDLE), (void*)str, x, &writeLen, NULL);
#else
		ignore_result(write(STDOUT_FILENO, str, x));
#endif
	}
	if ((dest & ILibDuktape_Console_DestinationFlags_WebLog) == ILibDuktape_Console_DestinationFlags_WebLog)
	{
		ILibRemoteLogging_printf(ILibChainGetLogger(Duktape_GetChain(ctx)), ILibRemoteLogging_Modules_Microstack_Generic, ILibRemoteLogging_Flags_VerbosityLevel_1, "%s", str);
	}
	if ((dest & ILibDuktape_Console_DestinationFlags_ServerConsole) == ILibDuktape_Console_DestinationFlags_ServerConsole)
	{
		if (duk_peval_string(ctx, "require('MeshAgent');") == 0)
		{
			duk_get_prop_string(ctx, -1, "SendCommand");	// [console][agent][SendCommand]
			duk_swap_top(ctx, -2);							// [console][SendCommand][this]
			duk_push_object(ctx);							// [console][SendCommand][this][options]
			duk_push_string(ctx, "msg"); duk_put_prop_string(ctx, -2, "action");
			duk_push_string(ctx, "console"); duk_put_prop_string(ctx, -2, "type");
			duk_push_string(ctx, str); duk_put_prop_string(ctx, -2, "value");
			if (duk_has_prop_string(ctx, -4, ILibDuktape_Console_SessionID))
			{
				duk_get_prop_string(ctx, -4, ILibDuktape_Console_SessionID);
				duk_put_prop_string(ctx, -2, "sessionid");
			}
			duk_call_method(ctx, 1);
		}
	}
	if ((dest & ILibDuktape_Console_DestinationFlags_LogFile) == ILibDuktape_Console_DestinationFlags_LogFile)
	{
		duk_size_t pathLen;
		char *path;
		char *tmp = (char*)ILibMemory_SmartAllocate(x + 32);
		int tmpx = ILibGetLocalTime(tmp + 1, (int)ILibMemory_Size(tmp) - 1) + 1;
		tmp[0] = '[';
		tmp[tmpx] = ']';
		tmp[tmpx + 1] = ':';
		tmp[tmpx + 2] = ' ';
		memcpy_s(tmp + tmpx + 3, ILibMemory_Size(tmp) - tmpx - 3, str, x);
		duk_eval_string(ctx, "require('fs');");
		duk_get_prop_string(ctx, -1, "writeFileSync");						// [fs][writeFileSync]
		duk_swap_top(ctx, -2);												// [writeFileSync][this]
		duk_push_heapptr(ctx, ILibDuktape_GetProcessObject(ctx));			// [writeFileSync][this][process]
		duk_get_prop_string(ctx, -1, "execPath");							// [writeFileSync][this][process][execPath]
		path = (char*)duk_get_lstring(ctx, -1, &pathLen);
		if (path != NULL)
		{
			if (ILibString_EndsWithEx(path, (int)pathLen, ".exe", 4, 0))
			{
				duk_get_prop_string(ctx, -1, "substring");						// [writeFileSync][this][process][execPath][substring]
				duk_swap_top(ctx, -2);											// [writeFileSync][this][process][substring][this]
				duk_push_int(ctx, 0);											// [writeFileSync][this][process][substring][this][0]
				duk_push_int(ctx, (int)(pathLen - 4));							// [writeFileSync][this][process][substring][this][0][len]
				duk_call_method(ctx, 2);										// [writeFileSync][this][process][path]
			}
			duk_get_prop_string(ctx, -1, "concat");								// [writeFileSync][this][process][path][concat]
			duk_swap_top(ctx, -2);												// [writeFileSync][this][process][concat][this]
			duk_push_string(ctx, ".jlog");										// [writeFileSync][this][process][concat][this][.jlog]
			duk_call_method(ctx, 1);											// [writeFileSync][this][process][logPath]
			duk_remove(ctx, -2);												// [writeFileSync][this][logPath]
			duk_push_string(ctx, tmp);											// [writeFileSync][this][logPath][log]
			duk_push_object(ctx);												// [writeFileSync][this][logPath][log][options]
			duk_push_string(ctx, "a"); duk_put_prop_string(ctx, -2, "flags");
			duk_pcall_method(ctx, 3);
		}
		ILibMemory_Free(tmp);
	}
	return 0;
}
duk_ret_t ILibDuktape_Polyfills_Console_enableWebLog(duk_context *ctx)
{
#ifdef _REMOTELOGGING
	void *chain = Duktape_GetChain(ctx);
	int port = duk_require_int(ctx, 0);
	duk_size_t pLen;
	if (duk_peval_string(ctx, "process.argv0") != 0) { return(ILibDuktape_Error(ctx, "console.enableWebLog(): Couldn't fetch argv0")); }
	char *p = (char*)duk_get_lstring(ctx, -1, &pLen);
	if (ILibString_EndsWith(p, (int)pLen, ".js", 3) != 0)
	{
		memcpy_s(ILibScratchPad2, sizeof(ILibScratchPad2), p, pLen - 3);
		sprintf_s(ILibScratchPad2 + (pLen - 3), sizeof(ILibScratchPad2) - 3, ".wlg");
	}
	else if (ILibString_EndsWith(p, (int)pLen, ".exe", 3) != 0)
	{
		memcpy_s(ILibScratchPad2, sizeof(ILibScratchPad2), p, pLen - 4);
		sprintf_s(ILibScratchPad2 + (pLen - 3), sizeof(ILibScratchPad2) - 4, ".wlg");
	}
	else
	{
		sprintf_s(ILibScratchPad2, sizeof(ILibScratchPad2), "%s.wlg", p);
	}
	ILibStartDefaultLoggerEx(chain, (unsigned short)port, ILibScratchPad2);
#endif
	return (0);
}
duk_ret_t ILibDuktape_Polyfills_Console_displayStreamPipe_getter(duk_context *ctx)
{
	duk_push_int(ctx, g_displayStreamPipeMessages);
	return(1);
}
duk_ret_t ILibDuktape_Polyfills_Console_displayStreamPipe_setter(duk_context *ctx)
{
	g_displayStreamPipeMessages = duk_require_int(ctx, 0);
	return(0);
}
duk_ret_t ILibDuktape_Polyfills_Console_displayFinalizer_getter(duk_context *ctx)
{
	duk_push_int(ctx, g_displayFinalizerMessages);
	return(1);
}
duk_ret_t ILibDuktape_Polyfills_Console_displayFinalizer_setter(duk_context *ctx)
{
	g_displayFinalizerMessages = duk_require_int(ctx, 0);
	return(0);
}
duk_ret_t ILibDuktape_Polyfills_Console_logRefCount(duk_context *ctx)
{
	duk_push_global_object(ctx); duk_get_prop_string(ctx, -1, "console");	// [g][console]
	duk_get_prop_string(ctx, -1, "log");									// [g][console][log]
	duk_swap_top(ctx, -2);													// [g][log][this]
	duk_push_sprintf(ctx, "Reference Count => %s[%p]:%d\n", Duktape_GetStringPropertyValue(ctx, 0, ILibDuktape_OBJID, "UNKNOWN"), duk_require_heapptr(ctx, 0), ILibDuktape_GetReferenceCount(ctx, 0) - 1);
	duk_call_method(ctx, 1);
	return(0);
}
duk_ret_t ILibDuktape_Polyfills_Console_setDestination(duk_context *ctx)
{
	int nargs = duk_get_top(ctx);
	int dest = duk_require_int(ctx, 0);

	duk_push_this(ctx);						// console
	if ((dest & ILibDuktape_Console_DestinationFlags_ServerConsole) == ILibDuktape_Console_DestinationFlags_ServerConsole)
	{
		// Mesh Server Console
		if (duk_peval_string(ctx, "require('MeshAgent');") != 0) { return(ILibDuktape_Error(ctx, "Unable to set destination to Mesh Console ")); }
		duk_pop(ctx);
		if (nargs > 1)
		{
			duk_dup(ctx, 1);
			duk_put_prop_string(ctx, -2, ILibDuktape_Console_SessionID);
		}
		else
		{
			duk_del_prop_string(ctx, -1, ILibDuktape_Console_SessionID);
		}
	}
	duk_dup(ctx, 0);
	duk_put_prop_string(ctx, -2, ILibDuktape_Console_Destination);
	return(0);
}
duk_ret_t ILibDuktape_Polyfills_Console_setInfoLevel(duk_context *ctx)
{
	int val = duk_require_int(ctx, 0);
	if (val < 0) { return(ILibDuktape_Error(ctx, "Invalid Info Level: %d", val)); }

	duk_push_this(ctx);
	duk_push_int(ctx, val);
	duk_put_prop_string(ctx, -2, ILibDuktape_Console_INFO_Level);

	return(0);
}
duk_ret_t ILibDuktape_Polyfills_Console_getInfoLevel(duk_context *ctx)
{
	duk_push_this(ctx);
	duk_get_prop_string(ctx, -1, ILibDuktape_Console_INFO_Level);
	return(1);
}
duk_ret_t ILibDuktape_Polyfills_Console_setInfoMask(duk_context *ctx)
{
	ILIBLOGMESSAGEX2_SetMask(duk_require_uint(ctx, 0));
	return(0);
}
duk_ret_t ILibDuktape_Polyfills_Console_canonical_get(duk_context *ctx)
{
#if defined(WIN32)
	DWORD mode = 0;
	GetConsoleMode(GetStdHandle(STD_INPUT_HANDLE), &mode);
	duk_push_boolean(ctx, (mode & ENABLE_LINE_INPUT) == ENABLE_LINE_INPUT);
#elif defined(_POSIX)
	struct termios term;
	tcgetattr(fileno(stdin), &term);
	duk_push_boolean(ctx, (term.c_lflag & ICANON) == ICANON);
#else
	duk_push_boolean(ctx, 1);
#endif
	return(1);
}
duk_ret_t ILibDuktape_Polyfills_Console_canonical_set(duk_context *ctx)
{
	int val = duk_require_boolean(ctx, 0) ? 1 : 0;

#if defined(WIN32)
	DWORD mode = 0;
	GetConsoleMode(GetStdHandle(STD_INPUT_HANDLE), &mode);
	if (val == 0)
	{
		mode = mode & 0xFFFFFFFD;
	}
	else
	{
		mode |= ENABLE_LINE_INPUT;
	}
	SetConsoleMode(GetStdHandle(STD_INPUT_HANDLE), mode);
#elif defined(_POSIX)
	struct termios term;
	tcgetattr(fileno(stdin), &term);

	if (val == 0)
	{
		term.c_lflag &= ~ICANON;
	}
	else
	{
		term.c_lflag |= ICANON;
	}
	tcsetattr(fileno(stdin), 0, &term);
#else
	duk_push_boolean(ctx, 1);
#endif
	return(0);
}
duk_ret_t ILibDuktape_Polyfills_Console_echo_get(duk_context *ctx)
{
#if defined(WIN32)
	DWORD mode = 0;
	GetConsoleMode(GetStdHandle(STD_INPUT_HANDLE), &mode);
	duk_push_boolean(ctx, (mode & ENABLE_ECHO_INPUT) == ENABLE_ECHO_INPUT);
#elif defined(_POSIX)
	struct termios term;
	tcgetattr(fileno(stdin), &term);
	duk_push_boolean(ctx, (term.c_lflag & ECHO) == ECHO);
#else
	duk_push_boolean(ctx, 1);
#endif
	return(1);
}
duk_ret_t ILibDuktape_Polyfills_Console_echo_set(duk_context *ctx)
{
	int val = duk_require_boolean(ctx, 0) ? 1 : 0;

#if defined(WIN32)
	DWORD mode = 0;
	GetConsoleMode(GetStdHandle(STD_INPUT_HANDLE), &mode);
	if (val == 0)
	{
		mode = mode & 0xFFFFFFFB;
	}
	else
	{
		mode |= ENABLE_ECHO_INPUT;
	}
	SetConsoleMode(GetStdHandle(STD_INPUT_HANDLE), mode);
#elif defined(_POSIX)
	struct termios term;
	tcgetattr(fileno(stdin), &term);

	if (val == 0)
	{
		term.c_lflag &= ~ECHO;
	}
	else
	{
		term.c_lflag |= ECHO;
	}
	tcsetattr(fileno(stdin), 0, &term);
#endif
	return(0);
}
duk_ret_t ILibDuktape_Polyfills_Console_rawLog(duk_context *ctx)
{
	char *val = (char*)duk_require_string(ctx, 0);
	ILIBLOGMESSAGEX("%s", val);
	return(0);
}
void ILibDuktape_Polyfills_Console(duk_context *ctx)
{
	// Polyfill console.log()
#ifdef WIN32
	SetConsoleOutputCP(CP_UTF8);
#endif

	if (duk_has_prop_string(ctx, -1, "console"))
	{
		duk_get_prop_string(ctx, -1, "console");									// [g][console]
	}
	else
	{
		duk_push_object(ctx);														// [g][console]
		duk_dup(ctx, -1);															// [g][console][console]
		duk_put_prop_string(ctx, -3, "console");									// [g][console]
	}

	ILibDuktape_CreateInstanceMethodWithIntProperty(ctx, "logType", (int)ILibDuktape_LogType_Normal, "log", ILibDuktape_Polyfills_Console_log, DUK_VARARGS);
	ILibDuktape_CreateInstanceMethodWithIntProperty(ctx, "logType", (int)ILibDuktape_LogType_Warn, "warn", ILibDuktape_Polyfills_Console_log, DUK_VARARGS);
	ILibDuktape_CreateInstanceMethodWithIntProperty(ctx, "logType", (int)ILibDuktape_LogType_Error, "error", ILibDuktape_Polyfills_Console_log, DUK_VARARGS);
	ILibDuktape_CreateInstanceMethodWithIntProperty(ctx, "logType", (int)ILibDuktape_LogType_Info1, "info1", ILibDuktape_Polyfills_Console_log, DUK_VARARGS);
	ILibDuktape_CreateInstanceMethodWithIntProperty(ctx, "logType", (int)ILibDuktape_LogType_Info2, "info2", ILibDuktape_Polyfills_Console_log, DUK_VARARGS);
	ILibDuktape_CreateInstanceMethodWithIntProperty(ctx, "logType", (int)ILibDuktape_LogType_Info3, "info3", ILibDuktape_Polyfills_Console_log, DUK_VARARGS);
	ILibDuktape_CreateInstanceMethod(ctx, "rawLog", ILibDuktape_Polyfills_Console_rawLog, 1);

	ILibDuktape_CreateInstanceMethod(ctx, "enableWebLog", ILibDuktape_Polyfills_Console_enableWebLog, 1);
	ILibDuktape_CreateEventWithGetterAndSetterEx(ctx, "displayStreamPipeMessages", ILibDuktape_Polyfills_Console_displayStreamPipe_getter, ILibDuktape_Polyfills_Console_displayStreamPipe_setter);
	ILibDuktape_CreateEventWithGetterAndSetterEx(ctx, "displayFinalizerMessages", ILibDuktape_Polyfills_Console_displayFinalizer_getter, ILibDuktape_Polyfills_Console_displayFinalizer_setter);
	ILibDuktape_CreateInstanceMethod(ctx, "logReferenceCount", ILibDuktape_Polyfills_Console_logRefCount, 1);
	
	ILibDuktape_CreateInstanceMethod(ctx, "setDestination", ILibDuktape_Polyfills_Console_setDestination, DUK_VARARGS);
	ILibDuktape_CreateInstanceMethod(ctx, "setInfoLevel", ILibDuktape_Polyfills_Console_setInfoLevel, 1);
	ILibDuktape_CreateInstanceMethod(ctx, "getInfoLevel", ILibDuktape_Polyfills_Console_getInfoLevel, 0);
	ILibDuktape_CreateInstanceMethod(ctx, "setInfoMask", ILibDuktape_Polyfills_Console_setInfoMask, 1);
	ILibDuktape_CreateEventWithGetterAndSetterEx(ctx, "echo", ILibDuktape_Polyfills_Console_echo_get, ILibDuktape_Polyfills_Console_echo_set);
	ILibDuktape_CreateEventWithGetterAndSetterEx(ctx, "canonical", ILibDuktape_Polyfills_Console_canonical_get, ILibDuktape_Polyfills_Console_canonical_set);

	duk_push_object(ctx);
	duk_push_int(ctx, ILibDuktape_Console_DestinationFlags_DISABLED); duk_put_prop_string(ctx, -2, "DISABLED");
	duk_push_int(ctx, ILibDuktape_Console_DestinationFlags_StdOut); duk_put_prop_string(ctx, -2, "STDOUT");
	duk_push_int(ctx, ILibDuktape_Console_DestinationFlags_ServerConsole); duk_put_prop_string(ctx, -2, "SERVERCONSOLE");
	duk_push_int(ctx, ILibDuktape_Console_DestinationFlags_WebLog); duk_put_prop_string(ctx, -2, "WEBLOG");
	duk_push_int(ctx, ILibDuktape_Console_DestinationFlags_LogFile); duk_put_prop_string(ctx, -2, "LOGFILE");
	ILibDuktape_CreateReadonlyProperty(ctx, "Destinations");

	duk_push_int(ctx, ILibDuktape_Console_DestinationFlags_StdOut | ILibDuktape_Console_DestinationFlags_LogFile);
	duk_put_prop_string(ctx, -2, ILibDuktape_Console_ERROR_Destination);

	duk_push_int(ctx, ILibDuktape_Console_DestinationFlags_StdOut | ILibDuktape_Console_DestinationFlags_LogFile);
	duk_put_prop_string(ctx, -2, ILibDuktape_Console_WARN_Destination);

	duk_push_int(ctx, 0); duk_put_prop_string(ctx, -2, ILibDuktape_Console_INFO_Level);

	duk_pop(ctx);																	// [g]
}
duk_ret_t ILibDuktape_ntohl(duk_context *ctx)
{
	duk_size_t bufferLen;
	char *buffer = Duktape_GetBuffer(ctx, 0, &bufferLen);
	int offset = duk_require_int(ctx, 1);

	if ((int)bufferLen < (4 + offset)) { return(ILibDuktape_Error(ctx, "buffer too small")); }
	duk_push_int(ctx, ntohl(((unsigned int*)(buffer + offset))[0]));
	return 1;
}
duk_ret_t ILibDuktape_ntohs(duk_context *ctx)
{
	duk_size_t bufferLen;
	char *buffer = Duktape_GetBuffer(ctx, 0, &bufferLen);
	int offset = duk_require_int(ctx, 1);

	if ((int)bufferLen < 2 + offset) { return(ILibDuktape_Error(ctx, "buffer too small")); }
	duk_push_int(ctx, ntohs(((unsigned short*)(buffer + offset))[0]));
	return 1;
}
duk_ret_t ILibDuktape_htonl(duk_context *ctx)
{
	duk_size_t bufferLen;
	char *buffer = Duktape_GetBuffer(ctx, 0, &bufferLen);
	int offset = duk_require_int(ctx, 1);
	unsigned int val = (unsigned int)duk_require_int(ctx, 2);

	if ((int)bufferLen < (4 + offset)) { return(ILibDuktape_Error(ctx, "buffer too small")); }
	((unsigned int*)(buffer + offset))[0] = htonl(val);
	return 0;
}
duk_ret_t ILibDuktape_htons(duk_context *ctx)
{
	duk_size_t bufferLen;
	char *buffer = Duktape_GetBuffer(ctx, 0, &bufferLen);
	int offset = duk_require_int(ctx, 1);
	unsigned int val = (unsigned int)duk_require_int(ctx, 2);

	if ((int)bufferLen < (2 + offset)) { return(ILibDuktape_Error(ctx, "buffer too small")); }
	((unsigned short*)(buffer + offset))[0] = htons(val);
	return 0;
}
void ILibDuktape_Polyfills_byte_ordering(duk_context *ctx)
{
	ILibDuktape_CreateInstanceMethod(ctx, "ntohl", ILibDuktape_ntohl, 2);
	ILibDuktape_CreateInstanceMethod(ctx, "ntohs", ILibDuktape_ntohs, 2);
	ILibDuktape_CreateInstanceMethod(ctx, "htonl", ILibDuktape_htonl, 3);
	ILibDuktape_CreateInstanceMethod(ctx, "htons", ILibDuktape_htons, 3);
}

typedef enum ILibDuktape_Timer_Type
{
	ILibDuktape_Timer_Type_TIMEOUT = 0,
	ILibDuktape_Timer_Type_INTERVAL = 1,
	ILibDuktape_Timer_Type_IMMEDIATE = 2
}ILibDuktape_Timer_Type;
typedef struct ILibDuktape_Timer
{
	duk_context *ctx;
	void *object;
	void *callback;
	void *args;
	int timeout;
	ILibDuktape_Timer_Type timerType;
}ILibDuktape_Timer;

duk_ret_t ILibDuktape_Polyfills_timer_finalizer(duk_context *ctx)
{
	// Make sure we remove any timers just in case, so we don't leak resources
	ILibDuktape_Timer *ptrs;
	if (duk_has_prop_string(ctx, 0, ILibDuktape_Timer_Ptrs))
	{
		duk_get_prop_string(ctx, 0, ILibDuktape_Timer_Ptrs);
		if (duk_has_prop_string(ctx, 0, "\xFF_callback"))
		{
			duk_del_prop_string(ctx, 0, "\xFF_callback");
		}
		if (duk_has_prop_string(ctx, 0, "\xFF_argArray"))
		{
			duk_del_prop_string(ctx, 0, "\xFF_argArray");
		}
		ptrs = (ILibDuktape_Timer*)Duktape_GetBuffer(ctx, -1, NULL);

		ILibLifeTime_Remove(ILibGetBaseTimer(Duktape_GetChain(ctx)), ptrs);
	}

	duk_eval_string(ctx, "require('events')");			// [events]
	duk_prepare_method_call(ctx, -1, "deleteProperty");	// [events][deleteProperty][this]
	duk_push_this(ctx);									// [events][deleteProperty][this][timer]
	duk_prepare_method_call(ctx, -4, "hiddenProperties");//[events][deleteProperty][this][timer][hidden][this]
	duk_push_this(ctx);									// [events][deleteProperty][this][timer][hidden][this][timer]
	duk_call_method(ctx, 1);							// [events][deleteProperty][this][timer][array]
	duk_call_method(ctx, 2);							// [events][ret]
	return 0;
}
void ILibDuktape_Polyfills_timer_elapsed(void *obj)
{
	ILibDuktape_Timer *ptrs = (ILibDuktape_Timer*)obj;
	int argCount, i;
	char *funcName;

	if (!ILibMemory_CanaryOK(ptrs)) { return; }
	
	duk_context *ctx = ptrs->ctx;
	if (duk_check_stack(ctx, 3) == 0) { return; }

	duk_push_heapptr(ctx, ptrs->callback);				// [func]
	funcName = Duktape_GetStringPropertyValue(ctx, -1, "name", "unknown_method");
	duk_push_heapptr(ctx, ptrs->object);				// [func][this]
	duk_push_heapptr(ctx, ptrs->args);					// [func][this][argArray]

	if (ptrs->timerType == ILibDuktape_Timer_Type_INTERVAL)
	{
		char *metadata = ILibLifeTime_GetCurrentTriggeredMetadata(ILibGetBaseTimer(duk_ctx_chain(ctx)));
		ILibLifeTime_AddEx3(ILibGetBaseTimer(Duktape_GetChain(ctx)), ptrs, ptrs->timeout, ILibDuktape_Polyfills_timer_elapsed, NULL, metadata);
	}
	else
	{
		if (ptrs->timerType == ILibDuktape_Timer_Type_IMMEDIATE)
		{
			duk_push_heap_stash(ctx);
			duk_del_prop_string(ctx, -1, Duktape_GetStashKey(ptrs->object));
			duk_pop(ctx);
		}

		duk_del_prop_string(ctx, -2, "\xFF_callback");
		duk_del_prop_string(ctx, -2, "\xFF_argArray");
		duk_del_prop_string(ctx, -2, ILibDuktape_Timer_Ptrs);
	}

	argCount = (int)duk_get_length(ctx, -1);
	for (i = 0; i < argCount; ++i)
	{
		duk_get_prop_index(ctx, -1, i);					// [func][this][argArray][arg]
		duk_swap_top(ctx, -2);							// [func][this][arg][argArray]
	}
	duk_pop(ctx);										// [func][this][...arg...]
	if (duk_pcall_method(ctx, argCount) != 0) { ILibDuktape_Process_UncaughtExceptionEx(ctx, "timers.onElapsed() callback handler on '%s()' ", funcName); }
	duk_pop(ctx);										// ...
}
duk_ret_t ILibDuktape_Polyfills_Timer_Metadata(duk_context *ctx)
{
	duk_push_this(ctx);
	ILibLifeTime_Token token = (ILibLifeTime_Token)Duktape_GetPointerProperty(ctx, -1, "\xFF_token");
	if (token != NULL)
	{
		duk_size_t metadataLen;
		char *metadata = (char*)duk_require_lstring(ctx, 0, &metadataLen);
		ILibLifeTime_SetMetadata(token, metadata, metadataLen);
	}
	return(0);
}
duk_ret_t ILibDuktape_Polyfills_timer_set(duk_context *ctx)
{
	char *metadata = NULL;
	int nargs = duk_get_top(ctx);
	ILibDuktape_Timer *ptrs;
	ILibDuktape_Timer_Type timerType;
	void *chain = Duktape_GetChain(ctx);
	int argx;

	duk_push_current_function(ctx);
	duk_get_prop_string(ctx, -1, "type");
	timerType = (ILibDuktape_Timer_Type)duk_get_int(ctx, -1);

	duk_push_object(ctx);																	//[retVal]
	switch (timerType)
	{
	case ILibDuktape_Timer_Type_IMMEDIATE:
		ILibDuktape_WriteID(ctx, "Timers.immediate");	
		metadata = "setImmediate()";
		// We're only saving a reference for immediates
		duk_push_heap_stash(ctx);															//[retVal][stash]
		duk_dup(ctx, -2);																	//[retVal][stash][immediate]
		duk_put_prop_string(ctx, -2, Duktape_GetStashKey(duk_get_heapptr(ctx, -1)));		//[retVal][stash]
		duk_pop(ctx);																		//[retVal]
		break;
	case ILibDuktape_Timer_Type_INTERVAL:
		ILibDuktape_WriteID(ctx, "Timers.interval");
		metadata = "setInterval()";
		break;
	case ILibDuktape_Timer_Type_TIMEOUT:
		ILibDuktape_WriteID(ctx, "Timers.timeout");
		metadata = "setTimeout()";
		break;
	}
	ILibDuktape_CreateFinalizer(ctx, ILibDuktape_Polyfills_timer_finalizer);
	
	ptrs = (ILibDuktape_Timer*)Duktape_PushBuffer(ctx, sizeof(ILibDuktape_Timer));	//[retVal][ptrs]
	duk_put_prop_string(ctx, -2, ILibDuktape_Timer_Ptrs);							//[retVal]

	ptrs->ctx = ctx;
	ptrs->object = duk_get_heapptr(ctx, -1);
	ptrs->timerType = timerType;
	ptrs->timeout = timerType == ILibDuktape_Timer_Type_IMMEDIATE ? 0 : (int)duk_require_int(ctx, 1);
	ptrs->callback = duk_require_heapptr(ctx, 0);

	duk_push_array(ctx);																			//[retVal][argArray]
	for (argx = ILibDuktape_Timer_Type_IMMEDIATE == timerType ? 1 : 2; argx < nargs; ++argx)
	{
		duk_dup(ctx, argx);																			//[retVal][argArray][arg]
		duk_put_prop_index(ctx, -2, argx - (ILibDuktape_Timer_Type_IMMEDIATE == timerType ? 1 : 2));//[retVal][argArray]
	}
	ptrs->args = duk_get_heapptr(ctx, -1);															//[retVal]
	duk_put_prop_string(ctx, -2, "\xFF_argArray");

	duk_dup(ctx, 0);																				//[retVal][callback]
	duk_put_prop_string(ctx, -2, "\xFF_callback");													//[retVal]

	duk_push_pointer(
		ctx,
		ILibLifeTime_AddEx3(ILibGetBaseTimer(chain), ptrs, ptrs->timeout, ILibDuktape_Polyfills_timer_elapsed, NULL, metadata));
	duk_put_prop_string(ctx, -2, "\xFF_token");
	ILibDuktape_CreateEventWithSetterEx(ctx, "metadata", ILibDuktape_Polyfills_Timer_Metadata);
	return 1;
}
duk_ret_t ILibDuktape_Polyfills_timer_clear(duk_context *ctx)
{
	ILibDuktape_Timer *ptrs;
	ILibDuktape_Timer_Type timerType;
	
	duk_push_current_function(ctx);
	duk_get_prop_string(ctx, -1, "type");
	timerType = (ILibDuktape_Timer_Type)duk_get_int(ctx, -1);

	if(!duk_has_prop_string(ctx, 0, ILibDuktape_Timer_Ptrs)) 
	{
		switch (timerType)
		{
			case ILibDuktape_Timer_Type_TIMEOUT:
				return(ILibDuktape_Error(ctx, "timers.clearTimeout(): Invalid Parameter"));
			case ILibDuktape_Timer_Type_INTERVAL:
				return(ILibDuktape_Error(ctx, "timers.clearInterval(): Invalid Parameter"));
			case ILibDuktape_Timer_Type_IMMEDIATE:
				return(ILibDuktape_Error(ctx, "timers.clearImmediate(): Invalid Parameter"));
		}
	}

	duk_dup(ctx, 0);
	duk_del_prop_string(ctx, -1, "\xFF_argArray");

	duk_get_prop_string(ctx, 0, ILibDuktape_Timer_Ptrs);
	ptrs = (ILibDuktape_Timer*)Duktape_GetBuffer(ctx, -1, NULL);

	if (ptrs->timerType == ILibDuktape_Timer_Type_IMMEDIATE)
	{
		duk_push_heap_stash(ctx);
		duk_del_prop_string(ctx, -1, Duktape_GetStashKey(ptrs->object));
		duk_pop(ctx);
	}

	ILibLifeTime_Remove(ILibGetBaseTimer(Duktape_GetChain(ctx)), ptrs);
	return 0;
}
void ILibDuktape_Polyfills_timer(duk_context *ctx)
{
	ILibDuktape_CreateInstanceMethodWithIntProperty(ctx, "type", ILibDuktape_Timer_Type_TIMEOUT, "setTimeout", ILibDuktape_Polyfills_timer_set, DUK_VARARGS);
	ILibDuktape_CreateInstanceMethodWithIntProperty(ctx, "type", ILibDuktape_Timer_Type_INTERVAL, "setInterval", ILibDuktape_Polyfills_timer_set, DUK_VARARGS);
	ILibDuktape_CreateInstanceMethodWithIntProperty(ctx, "type", ILibDuktape_Timer_Type_IMMEDIATE, "setImmediate", ILibDuktape_Polyfills_timer_set, DUK_VARARGS);

	ILibDuktape_CreateInstanceMethodWithIntProperty(ctx, "type", ILibDuktape_Timer_Type_TIMEOUT, "clearTimeout", ILibDuktape_Polyfills_timer_clear, 1);
	ILibDuktape_CreateInstanceMethodWithIntProperty(ctx, "type", ILibDuktape_Timer_Type_INTERVAL, "clearInterval", ILibDuktape_Polyfills_timer_clear, 1);
	ILibDuktape_CreateInstanceMethodWithIntProperty(ctx, "type", ILibDuktape_Timer_Type_IMMEDIATE, "clearImmediate", ILibDuktape_Polyfills_timer_clear, 1);
}
duk_ret_t ILibDuktape_Polyfills_getJSModule(duk_context *ctx)
{
	if (ILibDuktape_ModSearch_GetJSModule(ctx, (char*)duk_require_string(ctx, 0)) == 0)
	{
		return(ILibDuktape_Error(ctx, "getJSModule(): (%s) not found", (char*)duk_require_string(ctx, 0)));
	}
	return(1);
}
duk_ret_t ILibDuktape_Polyfills_getJSModuleDate(duk_context *ctx)
{
	duk_push_uint(ctx, ILibDuktape_ModSearch_GetJSModuleDate(ctx, (char*)duk_require_string(ctx, 0)));
	return(1);
}
duk_ret_t ILibDuktape_Polyfills_addModule(duk_context *ctx)
{
	int narg = duk_get_top(ctx);
	duk_size_t moduleLen;
	duk_size_t moduleNameLen;
	char *module = (char*)Duktape_GetBuffer(ctx, 1, &moduleLen);
	char *moduleName = (char*)Duktape_GetBuffer(ctx, 0, &moduleNameLen);
	char *mtime = narg > 2 ? (char*)duk_require_string(ctx, 2) : NULL;
	int add = 0;

	ILibDuktape_Polyfills_getJSModuleDate(ctx);								// [existing]
	uint32_t update = 0;
	uint32_t existing = duk_get_uint(ctx, -1);
	duk_pop(ctx);															// ...

	if (mtime != NULL)
	{
		// Check the timestamps
		duk_push_sprintf(ctx, "(new Date('%s')).getTime()/1000", mtime);	// [str]
		duk_eval(ctx);														// [new]
		update = duk_get_uint(ctx, -1);
		duk_pop(ctx);														// ...
	}
	if ((update > existing) || (update == existing && update == 0)) { add = 1; }

	if (add != 0)
	{
		if (ILibDuktape_ModSearch_IsRequired(ctx, moduleName, (int)moduleNameLen) != 0)
		{
			// Module is already cached, so we need to do some magic
			duk_push_sprintf(ctx, "if(global._legacyrequire==null) {global._legacyrequire = global.require; global.require = global._altrequire;}");
			duk_eval_noresult(ctx);
		}
		if (ILibDuktape_ModSearch_AddModuleEx(ctx, moduleName, module, (int)moduleLen, mtime) != 0)
		{
			return(ILibDuktape_Error(ctx, "Cannot add module: %s", moduleName));
		}
	}
	return(0);
}
duk_ret_t ILibDuktape_Polyfills_addCompressedModule_dataSink(duk_context *ctx)
{
	duk_push_this(ctx);								// [stream]
	if (!duk_has_prop_string(ctx, -1, "_buffer"))
	{
		duk_push_array(ctx);						// [stream][array]
		duk_dup(ctx, 0);							// [stream][array][buffer]
		duk_array_push(ctx, -2);					// [stream][array]
		duk_buffer_concat(ctx);						// [stream][buffer]
		duk_put_prop_string(ctx, -2, "_buffer");	// [stream]
	}
	else
	{
		duk_push_array(ctx);						// [stream][array]
		duk_get_prop_string(ctx, -2, "_buffer");	// [stream][array][buffer]
		duk_array_push(ctx, -2);					// [stream][array]
		duk_dup(ctx, 0);							// [stream][array][buffer]
		duk_array_push(ctx, -2);					// [stream][array]
		duk_buffer_concat(ctx);						// [stream][buffer]
		duk_put_prop_string(ctx, -2, "_buffer");	// [stream]
	}
	return(0);
}
duk_ret_t ILibDuktape_Polyfills_addCompressedModule(duk_context *ctx)
{
	int narg = duk_get_top(ctx);
	duk_eval_string(ctx, "require('compressed-stream').createDecompressor();");
	duk_dup(ctx, 0); duk_put_prop_string(ctx, -2, ILibDuktape_EventEmitter_FinalizerDebugMessage);
	void *decoder = duk_get_heapptr(ctx, -1);
	ILibDuktape_EventEmitter_AddOnEx(ctx, -1, "data", ILibDuktape_Polyfills_addCompressedModule_dataSink);

	duk_dup(ctx, -1);						// [stream]
	duk_get_prop_string(ctx, -1, "end");	// [stream][end]
	duk_swap_top(ctx, -2);					// [end][this]
	duk_dup(ctx, 1);						// [end][this][buffer]
	if (duk_pcall_method(ctx, 1) == 0)
	{
		duk_push_heapptr(ctx, decoder);				// [stream]
		duk_get_prop_string(ctx, -1, "_buffer");	// [stream][buffer]
		duk_get_prop_string(ctx, -1, "toString");	// [stream][buffer][toString]
		duk_swap_top(ctx, -2);						// [stream][toString][this]
		duk_call_method(ctx, 0);					// [stream][decodedString]
		duk_push_global_object(ctx);				// [stream][decodedString][global]
		duk_get_prop_string(ctx, -1, "addModule");	// [stream][decodedString][global][addModule]
		duk_swap_top(ctx, -2);						// [stream][decodedString][addModule][this]
		duk_dup(ctx, 0);							// [stream][decodedString][addModule][this][name]
		duk_dup(ctx, -4);							// [stream][decodedString][addModule][this][name][string]
		if (narg > 2) { duk_dup(ctx, 2); }
		duk_pcall_method(ctx, narg);
	}

	duk_push_heapptr(ctx, decoder);							// [stream]
	duk_prepare_method_call(ctx, -1, "removeAllListeners");	// [stream][remove][this]
	duk_pcall_method(ctx, 0);

	return(0);
}
duk_ret_t ILibDuktape_Polyfills_addModuleObject(duk_context *ctx)
{
	void *module = duk_require_heapptr(ctx, 1);
	char *moduleName = (char*)duk_require_string(ctx, 0);

	ILibDuktape_ModSearch_AddModuleObject(ctx, moduleName, module);
	return(0);
}
duk_ret_t ILibDuktape_Queue_Finalizer(duk_context *ctx)
{
	duk_get_prop_string(ctx, 0, ILibDuktape_Queue_Ptr);
	ILibQueue_Destroy((ILibQueue)duk_get_pointer(ctx, -1));
	return(0);
}
duk_ret_t ILibDuktape_Queue_EnQueue(duk_context *ctx)
{
	ILibQueue Q;
	int i;
	int nargs = duk_get_top(ctx);
	duk_push_this(ctx);																// [queue]
	duk_get_prop_string(ctx, -1, ILibDuktape_Queue_Ptr);							// [queue][ptr]
	Q = (ILibQueue)duk_get_pointer(ctx, -1);
	duk_pop(ctx);																	// [queue]

	ILibDuktape_Push_ObjectStash(ctx);												// [queue][stash]
	duk_push_array(ctx);															// [queue][stash][array]
	for (i = 0; i < nargs; ++i)
	{
		duk_dup(ctx, i);															// [queue][stash][array][arg]
		duk_put_prop_index(ctx, -2, i);												// [queue][stash][array]
	}
	ILibQueue_EnQueue(Q, duk_get_heapptr(ctx, -1));
	duk_put_prop_string(ctx, -2, Duktape_GetStashKey(duk_get_heapptr(ctx, -1)));	// [queue][stash]
	return(0);
}
duk_ret_t ILibDuktape_Queue_DeQueue(duk_context *ctx)
{
	duk_push_current_function(ctx);
	duk_get_prop_string(ctx, -1, "peek");
	int peek = duk_get_int(ctx, -1);

	duk_push_this(ctx);										// [Q]
	duk_get_prop_string(ctx, -1, ILibDuktape_Queue_Ptr);	// [Q][ptr]
	ILibQueue Q = (ILibQueue)duk_get_pointer(ctx, -1);
	void *h = peek == 0 ? ILibQueue_DeQueue(Q) : ILibQueue_PeekQueue(Q);
	if (h == NULL) { return(ILibDuktape_Error(ctx, "Queue is empty")); }
	duk_pop(ctx);											// [Q]
	ILibDuktape_Push_ObjectStash(ctx);						// [Q][stash]
	duk_push_heapptr(ctx, h);								// [Q][stash][array]
	int length = (int)duk_get_length(ctx, -1);
	int i;
	for (i = 0; i < length; ++i)
	{
		duk_get_prop_index(ctx, -i - 1, i);				   // [Q][stash][array][args]
	}
	if (peek == 0) { duk_del_prop_string(ctx, -length - 2, Duktape_GetStashKey(h)); }
	return(length);
}
duk_ret_t ILibDuktape_Queue_isEmpty(duk_context *ctx)
{
	duk_push_this(ctx);
	duk_push_boolean(ctx, ILibQueue_IsEmpty((ILibQueue)Duktape_GetPointerProperty(ctx, -1, ILibDuktape_Queue_Ptr)));
	return(1);
}
duk_ret_t ILibDuktape_Queue_new(duk_context *ctx)
{
	duk_push_object(ctx);									// [queue]
	duk_push_pointer(ctx, ILibQueue_Create());				// [queue][ptr]
	duk_put_prop_string(ctx, -2, ILibDuktape_Queue_Ptr);	// [queue]

	ILibDuktape_CreateFinalizer(ctx, ILibDuktape_Queue_Finalizer);
	ILibDuktape_CreateInstanceMethod(ctx, "enQueue", ILibDuktape_Queue_EnQueue, DUK_VARARGS);
	ILibDuktape_CreateInstanceMethodWithIntProperty(ctx, "peek", 0, "deQueue", ILibDuktape_Queue_DeQueue, DUK_VARARGS);
	ILibDuktape_CreateInstanceMethodWithIntProperty(ctx, "peek", 1, "peekQueue", ILibDuktape_Queue_DeQueue, DUK_VARARGS);
	ILibDuktape_CreateInstanceMethod(ctx, "isEmpty", ILibDuktape_Queue_isEmpty, 0);

	return(1);
}
void ILibDuktape_Queue_Push(duk_context *ctx, void* chain)
{
	duk_push_c_function(ctx, ILibDuktape_Queue_new, 0);
}

typedef struct ILibDuktape_DynamicBuffer_data
{
	int start;
	int end;
	int unshiftBytes;
	char *buffer;
	int bufferLen;
}ILibDuktape_DynamicBuffer_data;

typedef struct ILibDuktape_DynamicBuffer_ContextSwitchData
{
	void *chain;
	void *heapptr;
	ILibDuktape_DuplexStream *stream;
	ILibDuktape_DynamicBuffer_data *data;
	int bufferLen;
	char buffer[];
}ILibDuktape_DynamicBuffer_ContextSwitchData;

ILibTransport_DoneState ILibDuktape_DynamicBuffer_WriteSink(ILibDuktape_DuplexStream *stream, char *buffer, int bufferLen, void *user);
void ILibDuktape_DynamicBuffer_WriteSink_ChainThread(void *chain, void *user)
{
	ILibDuktape_DynamicBuffer_ContextSwitchData *data = (ILibDuktape_DynamicBuffer_ContextSwitchData*)user;
	if(ILibMemory_CanaryOK(data->stream))
	{
		ILibDuktape_DynamicBuffer_WriteSink(data->stream, data->buffer, data->bufferLen, data->data);
		ILibDuktape_DuplexStream_Ready(data->stream);
	}
	free(user);
}
ILibTransport_DoneState ILibDuktape_DynamicBuffer_WriteSink(ILibDuktape_DuplexStream *stream, char *buffer, int bufferLen, void *user)
{
	ILibDuktape_DynamicBuffer_data *data = (ILibDuktape_DynamicBuffer_data*)user;
	if (ILibIsRunningOnChainThread(stream->readableStream->chain) == 0)
	{
		ILibDuktape_DynamicBuffer_ContextSwitchData *tmp = (ILibDuktape_DynamicBuffer_ContextSwitchData*)ILibMemory_Allocate(sizeof(ILibDuktape_DynamicBuffer_ContextSwitchData) + bufferLen, 0, NULL, NULL);
		tmp->chain = stream->readableStream->chain;
		tmp->heapptr = stream->ParentObject;
		tmp->stream = stream;
		tmp->data = data;
		tmp->bufferLen = bufferLen;
		memcpy_s(tmp->buffer, bufferLen, buffer, bufferLen);
		Duktape_RunOnEventLoop(tmp->chain, duk_ctx_nonce(stream->readableStream->ctx), stream->readableStream->ctx, ILibDuktape_DynamicBuffer_WriteSink_ChainThread, NULL, tmp);
		return(ILibTransport_DoneState_INCOMPLETE);
	}


	if ((data->bufferLen - data->start - data->end) < bufferLen)
	{
		if (data->end > 0)
		{
			// Move the buffer first
			memmove_s(data->buffer, data->bufferLen, data->buffer + data->start, data->end);
			data->start = 0;
		}
		if ((data->bufferLen - data->end) < bufferLen)
		{
			// Need to resize buffer first
			int tmpSize = data->bufferLen;
			while ((tmpSize - data->end) < bufferLen)
			{
				tmpSize += 4096;
			}
			if ((data->buffer = (char*)realloc(data->buffer, tmpSize)) == NULL) { ILIBCRITICALEXIT(254); }
			data->bufferLen = tmpSize;
		}
	}


	memcpy_s(data->buffer + data->start + data->end, data->bufferLen - data->start - data->end, buffer, bufferLen);
	data->end += bufferLen;

	int unshifted = 0;
	do
	{
		duk_push_heapptr(stream->readableStream->ctx, stream->ParentObject);		// [ds]
		duk_get_prop_string(stream->readableStream->ctx, -1, "emit");				// [ds][emit]
		duk_swap_top(stream->readableStream->ctx, -2);								// [emit][this]
		duk_push_string(stream->readableStream->ctx, "readable");					// [emit][this][readable]
		if (duk_pcall_method(stream->readableStream->ctx, 1) != 0) { ILibDuktape_Process_UncaughtExceptionEx(stream->readableStream->ctx, "DynamicBuffer.WriteSink => readable(): "); }
		duk_pop(stream->readableStream->ctx);										// ...

		ILibDuktape_DuplexStream_WriteData(stream, data->buffer + data->start, data->end);
		if (data->unshiftBytes == 0)
		{
			// All the data was consumed
			data->start = data->end = 0;
		}
		else
		{
			unshifted = (data->end - data->unshiftBytes);
			if (unshifted > 0)
			{
				data->start += unshifted;
				data->end = data->unshiftBytes;
				data->unshiftBytes = 0;
			}
		}
	} while (unshifted != 0);

	return(ILibTransport_DoneState_COMPLETE);
}
void ILibDuktape_DynamicBuffer_EndSink(ILibDuktape_DuplexStream *stream, void *user)
{
	ILibDuktape_DuplexStream_WriteEnd(stream);
}
duk_ret_t ILibDuktape_DynamicBuffer_Finalizer(duk_context *ctx)
{
	duk_get_prop_string(ctx, 0, "\xFF_buffer");
	ILibDuktape_DynamicBuffer_data *data = (ILibDuktape_DynamicBuffer_data*)Duktape_GetBuffer(ctx, -1, NULL);
	free(data->buffer);
	return(0);
}

int ILibDuktape_DynamicBuffer_unshift(ILibDuktape_DuplexStream *sender, int unshiftBytes, void *user)
{
	ILibDuktape_DynamicBuffer_data *data = (ILibDuktape_DynamicBuffer_data*)user;
	data->unshiftBytes = unshiftBytes;
	return(unshiftBytes);
}
duk_ret_t ILibDuktape_DynamicBuffer_read(duk_context *ctx)
{
	ILibDuktape_DynamicBuffer_data *data;
	duk_push_this(ctx);															// [DynamicBuffer]
	duk_get_prop_string(ctx, -1, "\xFF_buffer");								// [DynamicBuffer][buffer]
	data = (ILibDuktape_DynamicBuffer_data*)Duktape_GetBuffer(ctx, -1, NULL);
	duk_push_external_buffer(ctx);												// [DynamicBuffer][buffer][extBuffer]
	duk_config_buffer(ctx, -1, data->buffer + data->start, data->bufferLen - (data->start + data->end));
	duk_push_buffer_object(ctx, -1, 0, data->bufferLen - (data->start + data->end), DUK_BUFOBJ_NODEJS_BUFFER);
	return(1);
}
duk_ret_t ILibDuktape_DynamicBuffer_new(duk_context *ctx)
{
	ILibDuktape_DynamicBuffer_data *data;
	int initSize = 4096;
	if (duk_get_top(ctx) != 0)
	{
		initSize = duk_require_int(ctx, 0);
	}

	duk_push_object(ctx);					// [stream]
	duk_push_fixed_buffer(ctx, sizeof(ILibDuktape_DynamicBuffer_data));
	data = (ILibDuktape_DynamicBuffer_data*)Duktape_GetBuffer(ctx, -1, NULL);
	memset(data, 0, sizeof(ILibDuktape_DynamicBuffer_data));
	duk_put_prop_string(ctx, -2, "\xFF_buffer");

	data->bufferLen = initSize;
	data->buffer = (char*)malloc(initSize);

	ILibDuktape_DuplexStream_InitEx(ctx, ILibDuktape_DynamicBuffer_WriteSink, ILibDuktape_DynamicBuffer_EndSink, NULL, NULL, ILibDuktape_DynamicBuffer_unshift, data);
	ILibDuktape_EventEmitter_CreateEventEx(ILibDuktape_EventEmitter_GetEmitter(ctx, -1), "readable");
	ILibDuktape_CreateInstanceMethod(ctx, "read", ILibDuktape_DynamicBuffer_read, DUK_VARARGS);
	ILibDuktape_CreateFinalizer(ctx, ILibDuktape_DynamicBuffer_Finalizer);

	return(1);
}

void ILibDuktape_DynamicBuffer_Push(duk_context *ctx, void *chain)
{
	duk_push_c_function(ctx, ILibDuktape_DynamicBuffer_new, DUK_VARARGS);
}

duk_ret_t ILibDuktape_Polyfills_debugCrash(duk_context *ctx)
{
	void *p = NULL;
	((int*)p)[0] = 55;
	return(0);
}


void ILibDuktape_Stream_PauseSink(struct ILibDuktape_readableStream *sender, void *user)
{
}
void ILibDuktape_Stream_ResumeSink(struct ILibDuktape_readableStream *sender, void *user)
{
	int skip = 0;
	duk_size_t bufferLen;

	duk_push_heapptr(sender->ctx, sender->object);			// [stream]
	void *func = Duktape_GetHeapptrProperty(sender->ctx, -1, "_read");
	duk_pop(sender->ctx);									// ...

	while (func != NULL && sender->paused == 0)
	{
		duk_push_heapptr(sender->ctx, sender->object);									// [this]
		if (!skip && duk_has_prop_string(sender->ctx, -1, ILibDuktape_Stream_Buffer))
		{
			duk_get_prop_string(sender->ctx, -1, ILibDuktape_Stream_Buffer);			// [this][buffer]
			if ((bufferLen = duk_get_length(sender->ctx, -1)) > 0)
			{
				// Buffer is not empty, so we need to 'PUSH' it
				duk_get_prop_string(sender->ctx, -2, "push");							// [this][buffer][push]
				duk_dup(sender->ctx, -3);												// [this][buffer][push][this]
				duk_dup(sender->ctx, -3);												// [this][buffer][push][this][buffer]
				duk_remove(sender->ctx, -4);											// [this][push][this][buffer]
				duk_call_method(sender->ctx, 1);										// [this][boolean]
				sender->paused = !duk_get_boolean(sender->ctx, -1);
				duk_pop(sender->ctx);													// [this]

				if (duk_has_prop_string(sender->ctx, -1, ILibDuktape_Stream_Buffer))
				{
					duk_get_prop_string(sender->ctx, -1, ILibDuktape_Stream_Buffer);	// [this][buffer]
					if (duk_get_length(sender->ctx, -1) == bufferLen)
					{
						// All the data was unshifted
						skip = !sender->paused;					
					}
					duk_pop(sender->ctx);												// [this]
				}
				duk_pop(sender->ctx);													// ...
			}
			else
			{
				// Buffer is empty
				duk_pop(sender->ctx);													// [this]
				duk_del_prop_string(sender->ctx, -1, ILibDuktape_Stream_Buffer);
				duk_pop(sender->ctx);													// ...
			}
		}
		else
		{
			// We need to 'read' more data
			duk_push_heapptr(sender->ctx, func);										// [this][read]
			duk_swap_top(sender->ctx, -2);												// [read][this]
			if (duk_pcall_method(sender->ctx, 0) != 0) { ILibDuktape_Process_UncaughtException(sender->ctx); duk_pop(sender->ctx); break; }
			//																			// [buffer]
			if (duk_is_null_or_undefined(sender->ctx, -1))
			{
				duk_pop(sender->ctx);
				break;
			}
			duk_push_heapptr(sender->ctx, sender->object);								// [buffer][this]
			duk_swap_top(sender->ctx, -2);												// [this][buffer]
			if (duk_has_prop_string(sender->ctx, -2, ILibDuktape_Stream_Buffer))
			{
				duk_push_global_object(sender->ctx);									// [this][buffer][g]
				duk_get_prop_string(sender->ctx, -1, "Buffer");							// [this][buffer][g][Buffer]
				duk_remove(sender->ctx, -2);											// [this][buffer][Buffer]
				duk_get_prop_string(sender->ctx, -1, "concat");							// [this][buffer][Buffer][concat]
				duk_swap_top(sender->ctx, -2);											// [this][buffer][concat][this]
				duk_push_array(sender->ctx);											// [this][buffer][concat][this][Array]
				duk_get_prop_string(sender->ctx, -1, "push");							// [this][buffer][concat][this][Array][push]
				duk_dup(sender->ctx, -2);												// [this][buffer][concat][this][Array][push][this]
				duk_get_prop_string(sender->ctx, -7, ILibDuktape_Stream_Buffer);		// [this][buffer][concat][this][Array][push][this][buffer]
				duk_call_method(sender->ctx, 1); duk_pop(sender->ctx);					// [this][buffer][concat][this][Array]
				duk_get_prop_string(sender->ctx, -1, "push");							// [this][buffer][concat][this][Array][push]
				duk_dup(sender->ctx, -2);												// [this][buffer][concat][this][Array][push][this]
				duk_dup(sender->ctx, -6);												// [this][buffer][concat][this][Array][push][this][buffer]
				duk_remove(sender->ctx, -7);											// [this][concat][this][Array][push][this][buffer]
				duk_call_method(sender->ctx, 1); duk_pop(sender->ctx);					// [this][concat][this][Array]
				duk_call_method(sender->ctx, 1);										// [this][buffer]
			}
			duk_put_prop_string(sender->ctx, -2, ILibDuktape_Stream_Buffer);			// [this]
			duk_pop(sender->ctx);														// ...
			skip = 0;
		}
	}
}
int ILibDuktape_Stream_UnshiftSink(struct ILibDuktape_readableStream *sender, int unshiftBytes, void *user)
{
	duk_push_fixed_buffer(sender->ctx, unshiftBytes);									// [buffer]
	memcpy_s(Duktape_GetBuffer(sender->ctx, -1, NULL), unshiftBytes, sender->unshiftReserved, unshiftBytes);
	duk_push_heapptr(sender->ctx, sender->object);										// [buffer][stream]
	duk_push_buffer_object(sender->ctx, -2, 0, unshiftBytes, DUK_BUFOBJ_NODEJS_BUFFER);	// [buffer][stream][buffer]
	duk_put_prop_string(sender->ctx, -2, ILibDuktape_Stream_Buffer);					// [buffer][stream]
	duk_pop_2(sender->ctx);																// ...

	return(unshiftBytes);
}
duk_ret_t ILibDuktape_Stream_Push(duk_context *ctx)
{
	duk_push_this(ctx);																					// [stream]

	ILibDuktape_readableStream *RS = (ILibDuktape_readableStream*)Duktape_GetPointerProperty(ctx, -1, ILibDuktape_Stream_ReadablePtr);

	duk_size_t bufferLen;
	char *buffer = (char*)Duktape_GetBuffer(ctx, 0, &bufferLen);
	if (buffer != NULL)
	{
		duk_push_boolean(ctx, !ILibDuktape_readableStream_WriteDataEx(RS, 0, buffer, (int)bufferLen));		// [stream][buffer][retVal]
	}
	else
	{
		ILibDuktape_readableStream_WriteEnd(RS);
		duk_push_false(ctx);
	}
	return(1);
}
duk_ret_t ILibDuktape_Stream_EndSink(duk_context *ctx)
{
	duk_push_this(ctx);												// [stream]
	ILibDuktape_readableStream *RS = (ILibDuktape_readableStream*)Duktape_GetPointerProperty(ctx, -1, ILibDuktape_Stream_ReadablePtr);
	ILibDuktape_readableStream_WriteEnd(RS);
	return(0);
}
duk_ret_t ILibDuktape_Stream_readonlyError(duk_context *ctx)
{
	duk_push_current_function(ctx);
	duk_size_t len;
	char *propName = Duktape_GetStringPropertyValueEx(ctx, -1, "propName", "<unknown>", &len);
	duk_push_lstring(ctx, propName, len);
	duk_get_prop_string(ctx, -1, "concat");					// [string][concat]
	duk_swap_top(ctx, -2);									// [concat][this]
	duk_push_string(ctx, " is readonly");					// [concat][this][str]
	duk_call_method(ctx, 1);								// [str]
	duk_throw(ctx);
	return(0);
}
duk_idx_t ILibDuktape_Stream_newReadable(duk_context *ctx)
{
	ILibDuktape_readableStream *RS;
	duk_push_object(ctx);							// [Readable]
	ILibDuktape_WriteID(ctx, "stream.readable");
	RS = ILibDuktape_ReadableStream_InitEx(ctx, ILibDuktape_Stream_PauseSink, ILibDuktape_Stream_ResumeSink, ILibDuktape_Stream_UnshiftSink, NULL);
	RS->paused = 1;

	duk_push_pointer(ctx, RS);
	duk_put_prop_string(ctx, -2, ILibDuktape_Stream_ReadablePtr);
	ILibDuktape_CreateInstanceMethod(ctx, "push", ILibDuktape_Stream_Push, DUK_VARARGS);
	ILibDuktape_EventEmitter_AddOnceEx3(ctx, -1, "end", ILibDuktape_Stream_EndSink);

	if (duk_is_object(ctx, 0))
	{
		void *h = Duktape_GetHeapptrProperty(ctx, 0, "read");
		if (h != NULL) { duk_push_heapptr(ctx, h); duk_put_prop_string(ctx, -2, "_read"); }
		else
		{
			ILibDuktape_CreateEventWithSetterEx(ctx, "_read", ILibDuktape_Stream_readonlyError);
		}
	}
	return(1);
}
duk_ret_t ILibDuktape_Stream_Writable_WriteSink_Flush(duk_context *ctx)
{
	duk_push_current_function(ctx);
	ILibTransport_DoneState *retVal = (ILibTransport_DoneState*)Duktape_GetPointerProperty(ctx, -1, "retval");
	if (retVal != NULL)
	{
		*retVal = ILibTransport_DoneState_COMPLETE;
	}
	else
	{
		ILibDuktape_WritableStream *WS = (ILibDuktape_WritableStream*)Duktape_GetPointerProperty(ctx, -1, ILibDuktape_Stream_WritablePtr);
		ILibDuktape_WritableStream_Ready(WS);
	}
	return(0);
}
ILibTransport_DoneState ILibDuktape_Stream_Writable_WriteSink(struct ILibDuktape_WritableStream *stream, char *buffer, int bufferLen, void *user)
{
	void *h;
	ILibTransport_DoneState retVal = ILibTransport_DoneState_INCOMPLETE;
	duk_push_this(stream->ctx);																		// [writable]
	int bufmode = Duktape_GetIntPropertyValue(stream->ctx, -1, "bufferMode", 0);
	duk_get_prop_string(stream->ctx, -1, "_write");													// [writable][_write]
	duk_swap_top(stream->ctx, -2);																	// [_write][this]
	if(duk_stream_flags_isBuffer(stream->Reserved))
	{
		if (bufmode == 0)
		{
			// Legacy Mode. We use an external buffer, so a memcpy does not occur. JS must copy memory if it needs to save it
			duk_push_external_buffer(stream->ctx);													// [_write][this][extBuffer]
			duk_config_buffer(stream->ctx, -1, buffer, (duk_size_t)bufferLen);
		}
		else
		{
			// Compliant Mode. We copy the buffer into a buffer that will be wholly owned by the recipient
			char *cb = (char*)duk_push_fixed_buffer(stream->ctx, (duk_size_t)bufferLen);			// [_write][this][extBuffer]
			memcpy_s(cb, (size_t)bufferLen, buffer, (size_t)bufferLen);
		}
		duk_push_buffer_object(stream->ctx, -1, 0, (duk_size_t)bufferLen, DUK_BUFOBJ_NODEJS_BUFFER);// [_write][this][extBuffer][buffer]
		duk_remove(stream->ctx, -2);																// [_write][this][buffer]	
	}
	else
	{
		duk_push_lstring(stream->ctx, buffer, (duk_size_t)bufferLen);								// [_write][this][string]
	}
	duk_push_c_function(stream->ctx, ILibDuktape_Stream_Writable_WriteSink_Flush, DUK_VARARGS);		// [_write][this][string/buffer][callback]
	h = duk_get_heapptr(stream->ctx, -1);
	duk_push_heap_stash(stream->ctx);																// [_write][this][string/buffer][callback][stash]
	duk_dup(stream->ctx, -2);																		// [_write][this][string/buffer][callback][stash][callback]
	duk_put_prop_string(stream->ctx, -2, Duktape_GetStashKey(h));									// [_write][this][string/buffer][callback][stash]
	duk_pop(stream->ctx);																			// [_write][this][string/buffer][callback]
	duk_push_pointer(stream->ctx, stream); duk_put_prop_string(stream->ctx, -2, ILibDuktape_Stream_WritablePtr);

	duk_push_pointer(stream->ctx, &retVal);															// [_write][this][string/buffer][callback][retval]
	duk_put_prop_string(stream->ctx, -2, "retval");													// [_write][this][string/buffer][callback]
	if (duk_pcall_method(stream->ctx, 2) != 0)
	{
		ILibDuktape_Process_UncaughtExceptionEx(stream->ctx, "stream.writable.write(): "); retVal = ILibTransport_DoneState_ERROR;
	}
	else
	{
		if (retVal != ILibTransport_DoneState_COMPLETE)
		{
			retVal = duk_to_boolean(stream->ctx, -1) ? ILibTransport_DoneState_COMPLETE : ILibTransport_DoneState_INCOMPLETE;
		}
	}
	duk_pop(stream->ctx);																			// ...

	duk_push_heapptr(stream->ctx, h);																// [callback]
	duk_del_prop_string(stream->ctx, -1, "retval");
	duk_pop(stream->ctx);																			// ...
	
	duk_push_heap_stash(stream->ctx);
	duk_del_prop_string(stream->ctx, -1, Duktape_GetStashKey(h));
	duk_pop(stream->ctx);
	return(retVal);
}
duk_ret_t ILibDuktape_Stream_Writable_EndSink_finish(duk_context *ctx)
{
	duk_push_current_function(ctx);
	ILibDuktape_WritableStream *ws = (ILibDuktape_WritableStream*)Duktape_GetPointerProperty(ctx, -1, "ptr");
	if (ILibMemory_CanaryOK(ws))
	{
		ILibDuktape_WritableStream_Finish(ws);
	}
	return(0);
}
void ILibDuktape_Stream_Writable_EndSink(struct ILibDuktape_WritableStream *stream, void *user)
{
	duk_push_this(stream->ctx);															// [writable]
	duk_get_prop_string(stream->ctx, -1, "_final");										// [writable][_final]
	duk_swap_top(stream->ctx, -2);														// [_final][this]
	duk_push_c_function(stream->ctx, ILibDuktape_Stream_Writable_EndSink_finish, 0);	// [_final][this][callback]
	duk_push_pointer(stream->ctx, stream); duk_put_prop_string(stream->ctx, -2, "ptr");
	if (duk_pcall_method(stream->ctx, 1) != 0) { ILibDuktape_Process_UncaughtExceptionEx(stream->ctx, "stream.writable._final(): "); }
	duk_pop(stream->ctx);								// ...
}
duk_ret_t ILibDuktape_Stream_newWritable(duk_context *ctx)
{
	ILibDuktape_WritableStream *WS;
	duk_push_object(ctx);						// [Writable]
	ILibDuktape_WriteID(ctx, "stream.writable");
	WS = ILibDuktape_WritableStream_Init(ctx, ILibDuktape_Stream_Writable_WriteSink, ILibDuktape_Stream_Writable_EndSink, NULL);
	WS->JSCreated = 1;

	duk_push_pointer(ctx, WS);
	duk_put_prop_string(ctx, -2, ILibDuktape_Stream_WritablePtr);

	if (duk_is_object(ctx, 0))
	{
		void *h = Duktape_GetHeapptrProperty(ctx, 0, "write");
		if (h != NULL) { duk_push_heapptr(ctx, h); duk_put_prop_string(ctx, -2, "_write"); }
		h = Duktape_GetHeapptrProperty(ctx, 0, "final");
		if (h != NULL) { duk_push_heapptr(ctx, h); duk_put_prop_string(ctx, -2, "_final"); }
	}
	return(1);
}
void ILibDuktape_Stream_Duplex_PauseSink(ILibDuktape_DuplexStream *stream, void *user)
{
	ILibDuktape_Stream_PauseSink(stream->readableStream, user);
}
void ILibDuktape_Stream_Duplex_ResumeSink(ILibDuktape_DuplexStream *stream, void *user)
{
	ILibDuktape_Stream_ResumeSink(stream->readableStream, user);
}
int ILibDuktape_Stream_Duplex_UnshiftSink(ILibDuktape_DuplexStream *stream, int unshiftBytes, void *user)
{
	return(ILibDuktape_Stream_UnshiftSink(stream->readableStream, unshiftBytes, user));
}
ILibTransport_DoneState ILibDuktape_Stream_Duplex_WriteSink(ILibDuktape_DuplexStream *stream, char *buffer, int bufferLen, void *user)
{
	return(ILibDuktape_Stream_Writable_WriteSink(stream->writableStream, buffer, bufferLen, user));
}
void ILibDuktape_Stream_Duplex_EndSink(ILibDuktape_DuplexStream *stream, void *user)
{
	ILibDuktape_Stream_Writable_EndSink(stream->writableStream, user);
}

duk_ret_t ILibDuktape_Stream_newDuplex(duk_context *ctx)
{
	ILibDuktape_DuplexStream *DS;
	duk_push_object(ctx);						// [Duplex]
	ILibDuktape_WriteID(ctx, "stream.Duplex");
	DS = ILibDuktape_DuplexStream_InitEx(ctx, ILibDuktape_Stream_Duplex_WriteSink, ILibDuktape_Stream_Duplex_EndSink, ILibDuktape_Stream_Duplex_PauseSink, ILibDuktape_Stream_Duplex_ResumeSink, ILibDuktape_Stream_Duplex_UnshiftSink, NULL);
	DS->writableStream->JSCreated = 1;

	duk_push_pointer(ctx, DS->writableStream);
	duk_put_prop_string(ctx, -2, ILibDuktape_Stream_WritablePtr);

	duk_push_pointer(ctx, DS->readableStream);
	duk_put_prop_string(ctx, -2, ILibDuktape_Stream_ReadablePtr);
	ILibDuktape_CreateInstanceMethod(ctx, "push", ILibDuktape_Stream_Push, DUK_VARARGS);
	ILibDuktape_EventEmitter_AddOnceEx3(ctx, -1, "end", ILibDuktape_Stream_EndSink);

	if (duk_is_object(ctx, 0))
	{
		void *h = Duktape_GetHeapptrProperty(ctx, 0, "write");
		if (h != NULL) { duk_push_heapptr(ctx, h); duk_put_prop_string(ctx, -2, "_write"); }
		else
		{
			ILibDuktape_CreateEventWithSetterEx(ctx, "_write", ILibDuktape_Stream_readonlyError);
		}
		h = Duktape_GetHeapptrProperty(ctx, 0, "final");
		if (h != NULL) { duk_push_heapptr(ctx, h); duk_put_prop_string(ctx, -2, "_final"); }
		else
		{
			ILibDuktape_CreateEventWithSetterEx(ctx, "_final", ILibDuktape_Stream_readonlyError);
		}
		h = Duktape_GetHeapptrProperty(ctx, 0, "read");
		if (h != NULL) { duk_push_heapptr(ctx, h); duk_put_prop_string(ctx, -2, "_read"); }
		else
		{
			ILibDuktape_CreateEventWithSetterEx(ctx, "_read", ILibDuktape_Stream_readonlyError);
		}
	}
	return(1);
}
void ILibDuktape_Stream_Init(duk_context *ctx, void *chain)
{
	duk_push_object(ctx);					// [stream
	ILibDuktape_WriteID(ctx, "stream");
	ILibDuktape_CreateInstanceMethod(ctx, "Readable", ILibDuktape_Stream_newReadable, DUK_VARARGS);
	ILibDuktape_CreateInstanceMethod(ctx, "Writable", ILibDuktape_Stream_newWritable, DUK_VARARGS);
	ILibDuktape_CreateInstanceMethod(ctx, "Duplex", ILibDuktape_Stream_newDuplex, DUK_VARARGS);
}
void ILibDuktape_Polyfills_debugGC2(duk_context *ctx, void ** args, int argsLen)
{
	if (duk_ctx_is_alive((duk_context*)args[1]) && duk_ctx_is_valid((uintptr_t)args[2], ctx) && duk_ctx_shutting_down(ctx)==0)
	{
		if (g_displayFinalizerMessages) { printf("=> GC();\n"); }
		duk_gc(ctx, 0);
	}
}
duk_ret_t ILibDuktape_Polyfills_debugGC(duk_context *ctx)
{
	ILibDuktape_Immediate(ctx, (void*[]) { Duktape_GetChain(ctx), ctx, (void*)duk_ctx_nonce(ctx), NULL }, 3, ILibDuktape_Polyfills_debugGC2);
	return(0);
}
duk_ret_t ILibDuktape_Polyfills_debug(duk_context *ctx)
{
#ifdef WIN32
	if (IsDebuggerPresent()) { __debugbreak(); }
#elif defined(_POSIX)
	raise(SIGTRAP);
#endif
	return(0);
}
#ifndef MICROSTACK_NOTLS
duk_ret_t ILibDuktape_PKCS7_getSignedDataBlock(duk_context *ctx)
{
	char *hash = ILibMemory_AllocateA(UTIL_SHA256_HASHSIZE);
	char *pkeyHash = ILibMemory_AllocateA(UTIL_SHA256_HASHSIZE);
	unsigned int size, r;
	BIO *out = NULL;
	PKCS7 *message = NULL;
	char* data2 = NULL;
	STACK_OF(X509) *st = NULL;

	duk_size_t bufferLen;
	char *buffer = Duktape_GetBuffer(ctx, 0, &bufferLen);

	message = d2i_PKCS7(NULL, (const unsigned char**)&buffer, (long)bufferLen);
	if (message == NULL) { return(ILibDuktape_Error(ctx, "PKCS7 Error")); }

	// Lets rebuild the original message and check the size
	size = i2d_PKCS7(message, NULL);
	if (size < (unsigned int)bufferLen) { PKCS7_free(message); return(ILibDuktape_Error(ctx, "PKCS7 Error")); }

	out = BIO_new(BIO_s_mem());

	// Check the PKCS7 signature, but not the certificate chain.
	r = PKCS7_verify(message, NULL, NULL, NULL, out, PKCS7_NOVERIFY);
	if (r == 0) { PKCS7_free(message); BIO_free(out); return(ILibDuktape_Error(ctx, "PKCS7 Verify Error")); }

	// If data block contains less than 32 bytes, fail.
	size = (unsigned int)BIO_get_mem_data(out, &data2);
	if (size <= ILibMemory_AllocateA_Size(hash)) { PKCS7_free(message); BIO_free(out); return(ILibDuktape_Error(ctx, "PKCS7 Size Mismatch Error")); }


	duk_push_object(ctx);												// [val]
	duk_push_fixed_buffer(ctx, size);									// [val][fbuffer]
	duk_dup(ctx, -1);													// [val][fbuffer][dup]
	duk_put_prop_string(ctx, -3, "\xFF_fixedbuffer");					// [val][fbuffer]
	duk_swap_top(ctx, -2);												// [fbuffer][val]
	duk_push_buffer_object(ctx, -2, 0, size, DUK_BUFOBJ_NODEJS_BUFFER); // [fbuffer][val][buffer]
	ILibDuktape_CreateReadonlyProperty(ctx, "data");					// [fbuffer][val]
	memcpy_s(Duktape_GetBuffer(ctx, -2, NULL), size, data2, size);


	// Get the certificate signer
	st = PKCS7_get0_signers(message, NULL, PKCS7_NOVERIFY);
	
	// Get a full certificate hash of the signer
	X509_digest(sk_X509_value(st, 0), EVP_sha256(), (unsigned char*)hash, NULL);
	X509_pubkey_digest(sk_X509_value(st, 0), EVP_sha256(), (unsigned char*)pkeyHash, NULL); 

	sk_X509_free(st);
	
	// Check certificate hash with first 32 bytes of data.
	if (memcmp(hash, Duktape_GetBuffer(ctx, -2, NULL), ILibMemory_AllocateA_Size(hash)) != 0) { PKCS7_free(message); BIO_free(out); return(ILibDuktape_Error(ctx, "PKCS7 Certificate Hash Mismatch Error")); }
	char *tmp = ILibMemory_AllocateA(1 + (ILibMemory_AllocateA_Size(hash) * 2));
	util_tohex(hash, (int)ILibMemory_AllocateA_Size(hash), tmp);
	duk_push_object(ctx);												// [fbuffer][val][cert]
	ILibDuktape_WriteID(ctx, "certificate");
	duk_push_string(ctx, tmp);											// [fbuffer][val][cert][fingerprint]
	ILibDuktape_CreateReadonlyProperty(ctx, "fingerprint");				// [fbuffer][val][cert]
	util_tohex(pkeyHash, (int)ILibMemory_AllocateA_Size(pkeyHash), tmp);
	duk_push_string(ctx, tmp);											// [fbuffer][val][cert][publickeyhash]
	ILibDuktape_CreateReadonlyProperty(ctx, "publicKeyHash");			// [fbuffer][val][cert]

	ILibDuktape_CreateReadonlyProperty(ctx, "signingCertificate");		// [fbuffer][val]

	// Approved, cleanup and return.
	BIO_free(out);
	PKCS7_free(message);

	return(1);
}
duk_ret_t ILibDuktape_PKCS7_signDataBlockFinalizer(duk_context *ctx)
{
	char *buffer = Duktape_GetPointerProperty(ctx, 0, "\xFF_signature");
	if (buffer != NULL) { free(buffer); }
	return(0);
}
duk_ret_t ILibDuktape_PKCS7_signDataBlock(duk_context *ctx)
{
	duk_get_prop_string(ctx, 1, "secureContext");
	duk_get_prop_string(ctx, -1, "\xFF_SecureContext2CertBuffer");
	struct util_cert *cert = (struct util_cert*)Duktape_GetBuffer(ctx, -1, NULL);
	duk_size_t bufferLen;
	char *buffer = (char*)Duktape_GetBuffer(ctx, 0, &bufferLen);

	BIO *in = NULL;
	PKCS7 *message = NULL;
	char *signature = NULL;
	int signatureLength = 0;

	// Sign the block
	in = BIO_new_mem_buf(buffer, (int)bufferLen);
	message = PKCS7_sign(cert->x509, cert->pkey, NULL, in, PKCS7_BINARY);
	if (message != NULL)
	{
		signatureLength = i2d_PKCS7(message, (unsigned char**)&signature);
		PKCS7_free(message);
	}
	if (in != NULL) BIO_free(in);
	if (signatureLength <= 0) { return(ILibDuktape_Error(ctx, "PKCS7_signDataBlockError: ")); }

	duk_push_external_buffer(ctx);
	duk_config_buffer(ctx, -1, signature, signatureLength);
	duk_push_buffer_object(ctx, -1, 0, signatureLength, DUK_BUFOBJ_NODEJS_BUFFER);
	duk_push_pointer(ctx, signature);
	duk_put_prop_string(ctx, -2, "\xFF_signature");
	ILibDuktape_CreateFinalizer(ctx, ILibDuktape_PKCS7_signDataBlockFinalizer);

	return(1);
}
void ILibDuktape_PKCS7_Push(duk_context *ctx, void *chain)
{
	duk_push_object(ctx);
	ILibDuktape_CreateInstanceMethod(ctx, "getSignedDataBlock", ILibDuktape_PKCS7_getSignedDataBlock, 1);
	ILibDuktape_CreateInstanceMethod(ctx, "signDataBlock", ILibDuktape_PKCS7_signDataBlock, DUK_VARARGS);
}

extern uint32_t crc32c(uint32_t crc, const unsigned char* buf, uint32_t len);
extern uint32_t crc32(uint32_t crc, const unsigned char* buf, uint32_t len);
duk_ret_t ILibDuktape_Polyfills_crc32c(duk_context *ctx)
{
	duk_size_t len;
	char *buffer = Duktape_GetBuffer(ctx, 0, &len);
	uint32_t pre = duk_is_number(ctx, 1) ? duk_require_uint(ctx, 1) : 0;
	duk_push_uint(ctx, crc32c(pre, (unsigned char*)buffer, (uint32_t)len));
	return(1);
}
duk_ret_t ILibDuktape_Polyfills_crc32(duk_context *ctx)
{
	duk_size_t len;
	char *buffer = Duktape_GetBuffer(ctx, 0, &len);
	uint32_t pre = duk_is_number(ctx, 1) ? duk_require_uint(ctx, 1) : 0;
	duk_push_uint(ctx, crc32(pre, (unsigned char*)buffer, (uint32_t)len));
	return(1);
}
#endif
duk_ret_t ILibDuktape_Polyfills_Object_hashCode(duk_context *ctx)
{
	duk_push_this(ctx);
	duk_push_string(ctx, Duktape_GetStashKey(duk_get_heapptr(ctx, -1)));
	return(1);
}
duk_ret_t ILibDuktape_Polyfills_Array_peek(duk_context *ctx)
{
	duk_push_this(ctx);				// [Array]
	duk_get_prop_index(ctx, -1, (duk_uarridx_t)duk_get_length(ctx, -1) - 1);
	return(1);
}
duk_ret_t ILibDuktape_Polyfills_Object_keys(duk_context *ctx)
{
	duk_push_this(ctx);														// [obj]
	duk_push_array(ctx);													// [obj][keys]
	duk_enum(ctx, -2, DUK_ENUM_OWN_PROPERTIES_ONLY);						// [obj][keys][enum]
	while (duk_next(ctx, -1, 0))											// [obj][keys][enum][key]
	{
		duk_array_push(ctx, -3);											// [obj][keys][enum]
	}
	duk_pop(ctx);															// [obj][keys]
	return(1);
}
duk_ret_t ILibDuktape_Polyfills_function_getter(duk_context *ctx)
{
	duk_push_this(ctx);			// [Function]
	duk_push_true(ctx);
	duk_put_prop_string(ctx, -2, ILibDuktape_EventEmitter_InfrastructureEvent);
	return(1);
}
void ILibDuktape_Polyfills_function(duk_context *ctx)
{
	duk_get_prop_string(ctx, -1, "Function");										// [g][Function]
	duk_get_prop_string(ctx, -1, "prototype");										// [g][Function][prototype]
	ILibDuktape_CreateEventWithGetter(ctx, "internal", ILibDuktape_Polyfills_function_getter);
	duk_pop_2(ctx);																	// [g]
}
void ILibDuktape_Polyfills_object(duk_context *ctx)
{
	// Polyfill Object._hashCode() 
	duk_get_prop_string(ctx, -1, "Object");											// [g][Object]
	duk_get_prop_string(ctx, -1, "prototype");										// [g][Object][prototype]
	duk_push_c_function(ctx, ILibDuktape_Polyfills_Object_hashCode, 0);				// [g][Object][prototype][func]
	ILibDuktape_CreateReadonlyProperty(ctx, "_hashCode");							// [g][Object][prototype]
	duk_push_c_function(ctx, ILibDuktape_Polyfills_Object_keys, 0);					// [g][Object][prototype][func]
	ILibDuktape_CreateReadonlyProperty(ctx, "keys");								// [g][Object][prototype]
	duk_pop_2(ctx);																	// [g]

	duk_get_prop_string(ctx, -1, "Array");											// [g][Array]
	duk_get_prop_string(ctx, -1, "prototype");										// [g][Array][prototype]
	duk_push_c_function(ctx, ILibDuktape_Polyfills_Array_peek, 0);					// [g][Array][prototype][peek]
	ILibDuktape_CreateReadonlyProperty(ctx, "peek");								// [g][Array][prototype]
	duk_pop_2(ctx);																	// [g]
}


#ifndef MICROSTACK_NOTLS
void ILibDuktape_bignum_addBigNumMethods(duk_context *ctx, BIGNUM *b);
duk_ret_t ILibDuktape_bignum_toString(duk_context *ctx)
{
	duk_push_this(ctx);
	BIGNUM *b = (BIGNUM*)Duktape_GetPointerProperty(ctx, -1, "\xFF_BIGNUM");
	if (b != NULL)
	{
		char *numstr = BN_bn2dec(b);
		duk_push_string(ctx, numstr);
		OPENSSL_free(numstr);
		return(1);
	}
	else
	{
		return(ILibDuktape_Error(ctx, "Invalid BIGNUM"));
	}
}
duk_ret_t ILibDuktape_bignum_add(duk_context* ctx)
{
	BIGNUM *ret = BN_new();
	BIGNUM *r1, *r2;

	duk_push_this(ctx);
	r1 = (BIGNUM*)Duktape_GetPointerProperty(ctx, -1, "\xFF_BIGNUM");
	r2 = (BIGNUM*)Duktape_GetPointerProperty(ctx, 0, "\xFF_BIGNUM");

	BN_add(ret, r1, r2);
	ILibDuktape_bignum_addBigNumMethods(ctx, ret);
	return(1);
}
duk_ret_t ILibDuktape_bignum_sub(duk_context* ctx)
{
	BIGNUM *ret = BN_new();
	BIGNUM *r1, *r2;

	duk_push_this(ctx);
	r1 = (BIGNUM*)Duktape_GetPointerProperty(ctx, -1, "\xFF_BIGNUM");
	r2 = (BIGNUM*)Duktape_GetPointerProperty(ctx, 0, "\xFF_BIGNUM");

	BN_sub(ret, r1, r2);
	ILibDuktape_bignum_addBigNumMethods(ctx, ret);
	return(1);
}
duk_ret_t ILibDuktape_bignum_mul(duk_context* ctx)
{
	BN_CTX *bx = BN_CTX_new();
	BIGNUM *ret = BN_new();
	BIGNUM *r1, *r2;

	duk_push_this(ctx);
	r1 = (BIGNUM*)Duktape_GetPointerProperty(ctx, -1, "\xFF_BIGNUM");
	r2 = (BIGNUM*)Duktape_GetPointerProperty(ctx, 0, "\xFF_BIGNUM");
	BN_mul(ret, r1, r2, bx);
	BN_CTX_free(bx);
	ILibDuktape_bignum_addBigNumMethods(ctx, ret);
	return(1);
}
duk_ret_t ILibDuktape_bignum_div(duk_context* ctx)
{
	BN_CTX *bx = BN_CTX_new();
	BIGNUM *ret = BN_new();
	BIGNUM *r1, *r2;

	duk_push_this(ctx);
	r1 = (BIGNUM*)Duktape_GetPointerProperty(ctx, -1, "\xFF_BIGNUM");
	r2 = (BIGNUM*)Duktape_GetPointerProperty(ctx, 0, "\xFF_BIGNUM");
	BN_div(ret, NULL, r1, r2, bx);

	BN_CTX_free(bx);
	ILibDuktape_bignum_addBigNumMethods(ctx, ret);
	return(1);
}
duk_ret_t ILibDuktape_bignum_mod(duk_context* ctx)
{
	BN_CTX *bx = BN_CTX_new();
	BIGNUM *ret = BN_new();
	BIGNUM *r1, *r2;

	duk_push_this(ctx);
	r1 = (BIGNUM*)Duktape_GetPointerProperty(ctx, -1, "\xFF_BIGNUM");
	r2 = (BIGNUM*)Duktape_GetPointerProperty(ctx, 0, "\xFF_BIGNUM");
	BN_div(NULL, ret, r1, r2, bx);

	BN_CTX_free(bx);
	ILibDuktape_bignum_addBigNumMethods(ctx, ret);
	return(1);
}
duk_ret_t ILibDuktape_bignum_cmp(duk_context *ctx)
{
	BIGNUM *r1, *r2;
	duk_push_this(ctx);
	r1 = (BIGNUM*)Duktape_GetPointerProperty(ctx, -1, "\xFF_BIGNUM");
	r2 = (BIGNUM*)Duktape_GetPointerProperty(ctx, 0, "\xFF_BIGNUM");
	duk_push_int(ctx, BN_cmp(r2, r1));
	return(1);
}

duk_ret_t ILibDuktape_bignum_finalizer(duk_context *ctx)
{
	BIGNUM *b = (BIGNUM*)Duktape_GetPointerProperty(ctx, 0, "\xFF_BIGNUM");
	if (b != NULL)
	{
		BN_free(b);
	}
	return(0);
}
void ILibDuktape_bignum_addBigNumMethods(duk_context *ctx, BIGNUM *b)
{
	duk_push_object(ctx);
	duk_push_pointer(ctx, b); duk_put_prop_string(ctx, -2, "\xFF_BIGNUM");
	ILibDuktape_CreateProperty_InstanceMethod(ctx, "toString", ILibDuktape_bignum_toString, DUK_VARARGS);
	ILibDuktape_CreateInstanceMethod(ctx, "add", ILibDuktape_bignum_add, 1);
	ILibDuktape_CreateInstanceMethod(ctx, "sub", ILibDuktape_bignum_sub, 1);
	ILibDuktape_CreateInstanceMethod(ctx, "mul", ILibDuktape_bignum_mul, 1);
	ILibDuktape_CreateInstanceMethod(ctx, "div", ILibDuktape_bignum_div, 1);
	ILibDuktape_CreateInstanceMethod(ctx, "mod", ILibDuktape_bignum_mod, 1);
	ILibDuktape_CreateInstanceMethod(ctx, "cmp", ILibDuktape_bignum_cmp, 1);

	duk_push_c_function(ctx, ILibDuktape_bignum_finalizer, 1); duk_set_finalizer(ctx, -2);
	duk_eval_string(ctx, "(function toNumber(){return(parseInt(this.toString()));})"); duk_put_prop_string(ctx, -2, "toNumber");
}
duk_ret_t ILibDuktape_bignum_random(duk_context *ctx)
{
	BIGNUM *r = (BIGNUM*)Duktape_GetPointerProperty(ctx, 0, "\xFF_BIGNUM");
	BIGNUM *rnd = BN_new();

	if (BN_rand_range(rnd, r) == 0) { return(ILibDuktape_Error(ctx, "Error Generating Random Number")); }
	ILibDuktape_bignum_addBigNumMethods(ctx, rnd);
	return(1);
}
duk_ret_t ILibDuktape_bignum_fromBuffer(duk_context *ctx)
{
	char *endian = duk_get_top(ctx) > 1 ? Duktape_GetStringPropertyValue(ctx, 1, "endian", "big") : "big";
	duk_size_t len;
	char *buffer = Duktape_GetBuffer(ctx, 0, &len);
	BIGNUM *b;

	if (strcmp(endian, "big") == 0)
	{
		b = BN_bin2bn((unsigned char*)buffer, (int)len, NULL);
	}
	else if (strcmp(endian, "little") == 0)
	{
#ifdef OLDSSL
		return(ILibDuktape_Error(ctx, "Invalid endian specified"));
#endif
		b = BN_lebin2bn((unsigned char*)buffer, (int)len, NULL);
	}
	else
	{
		return(ILibDuktape_Error(ctx, "Invalid endian specified"));
	}

	ILibDuktape_bignum_addBigNumMethods(ctx, b);
	return(1);
}

duk_ret_t ILibDuktape_bignum_func(duk_context *ctx)
{	
	BIGNUM *b = NULL;
	BN_dec2bn(&b, duk_require_string(ctx, 0));
	ILibDuktape_bignum_addBigNumMethods(ctx, b);
	return(1);
}
void ILibDuktape_bignum_Push(duk_context *ctx, void *chain)
{
	duk_push_c_function(ctx, ILibDuktape_bignum_func, DUK_VARARGS);
	duk_push_c_function(ctx, ILibDuktape_bignum_fromBuffer, DUK_VARARGS); duk_put_prop_string(ctx, -2, "fromBuffer");
	duk_push_c_function(ctx, ILibDuktape_bignum_random, DUK_VARARGS); duk_put_prop_string(ctx, -2, "random");
	
	char randRange[] = "exports.randomRange = function randomRange(low, high)\
						{\
							var result = exports.random(high.sub(low)).add(low);\
							return(result);\
						};";
	ILibDuktape_ModSearch_AddHandler_AlsoIncludeJS(ctx, randRange, sizeof(randRange) - 1);
}
void ILibDuktape_dataGenerator_onPause(struct ILibDuktape_readableStream *sender, void *user)
{

}
void ILibDuktape_dataGenerator_onResume(struct ILibDuktape_readableStream *sender, void *user)
{
	SHA256_CTX shctx;

	char *buffer = (char*)user;
	size_t bufferLen = ILibMemory_Size(buffer);
	int val;

	while (sender->paused == 0)
	{
		duk_push_heapptr(sender->ctx, sender->object);
		val = Duktape_GetIntPropertyValue(sender->ctx, -1, "\xFF_counter", 0);
		duk_push_int(sender->ctx, (val + 1) < 255 ? (val+1) : 0); duk_put_prop_string(sender->ctx, -2, "\xFF_counter");
		duk_pop(sender->ctx);

		//util_random((int)(bufferLen - UTIL_SHA256_HASHSIZE), buffer + UTIL_SHA256_HASHSIZE);
		memset(buffer + UTIL_SHA256_HASHSIZE, val, bufferLen - UTIL_SHA256_HASHSIZE);


		SHA256_Init(&shctx);
		SHA256_Update(&shctx, buffer + UTIL_SHA256_HASHSIZE, bufferLen - UTIL_SHA256_HASHSIZE);
		SHA256_Final((unsigned char*)buffer, &shctx);
		ILibDuktape_readableStream_WriteData(sender, buffer, (int)bufferLen);
	}
}
duk_ret_t ILibDuktape_dataGenerator_const(duk_context *ctx)
{
	int bufSize = (int)duk_require_int(ctx, 0);
	void *buffer;

	if (bufSize <= UTIL_SHA256_HASHSIZE)
	{
		return(ILibDuktape_Error(ctx, "Value too small. Must be > %d", UTIL_SHA256_HASHSIZE));
	}

	duk_push_object(ctx);
	duk_push_int(ctx, 0); duk_put_prop_string(ctx, -2, "\xFF_counter");
	buffer = Duktape_PushBuffer(ctx, bufSize);
	duk_put_prop_string(ctx, -2, "\xFF_buffer");
	ILibDuktape_ReadableStream_Init(ctx, ILibDuktape_dataGenerator_onPause, ILibDuktape_dataGenerator_onResume, buffer)->paused = 1;
	return(1);
}
void ILibDuktape_dataGenerator_Push(duk_context *ctx, void *chain)
{
	duk_push_c_function(ctx, ILibDuktape_dataGenerator_const, DUK_VARARGS);
}
#endif

void ILibDuktape_Polyfills_JS_Init(duk_context *ctx)
{
	// {{ BEGIN AUTO-GENERATED BODY

	// The following can be overriden by calling addModule() or by having a .js file in the module path

	// CRC32-STREAM, refer to /modules/crc32-stream.js for details
	duk_peval_string_noresult(ctx, "addCompressedModule('crc32-stream', Buffer.from('eJyNVNFu2jAUfY+Uf7jiBaiygNgbVTWxtNOiVVARuqpPk3FugrdgZ7bTFCH+fdchtKTdpPnF2Pfk3HOOrxhd+F6kyp0W+cbCZDwZQywtFhApXSrNrFDS93zvVnCUBlOoZIoa7AZhVjJOW1sJ4DtqQ2iYhGMYOECvLfWGl763UxVs2Q6kslAZJAZhIBMFAj5zLC0ICVxty0IwyRFqYTdNl5Yj9L3HlkGtLSMwI3hJp+wcBsw6tUBrY205HY3qug5ZozRUOh8VR5wZ3cbRzTy5+UBq3Rf3skBjQOPvSmiyud4BK0kMZ2uSWLAalAaWa6SaVU5srYUVMg/AqMzWTKPvpcJYLdaV7eR0kkZ+zwGUFJPQmyUQJz34PEviJPC9h3j1dXG/gofZcjmbr+KbBBZLiBbz63gVL+Z0+gKz+SN8i+fXASClRF3wudROPUkULkFMKa4EsdM+U0c5pkQuMsHJlMwrliPk6gm1JC9Qot4K417RkLjU9wqxFbYZAvPeETW5GLnwnpiGB4qjyerqFOKgT2aRbfvD8FS8dGjfyyrJHSdwqlsc0DxEy+jjhA99b398PUep0RKbxPqFfHAsurV//emWew2cwgvzgG8q+SuArKjMZtjFvvnULTeN4Q9eaY3SNT2eG1ERfCKdnNSdODvgIUyP5b9XL9/3aiQN3lYOQfecCcmKc0P/6eQf7K/Hw6lG8Z5bHp9ft86v4OVpKAWrKyS3GSsMtuDF+idyG6ZIcvFOKxoguxsQRQD9J1ZU2A9gDznacydDuiJIpaX7n+ikBYeOvgZCu7s6uMnZqrQqMKSBV9oa0rdvZ2ja7nAg6B/4IHJ3', 'base64'));");

	// http-digest. Refer to /modules/http-digest.js for a human readable version
	duk_peval_string_noresult(ctx, "addCompressedModule('http-digest', Buffer.from('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', 'base64'), '2022-07-01T10:24:45.000-07:00');");

	// Clipboard. Refer to /modules/clipboard.js for a human readable version
	duk_peval_string_noresult(ctx, "addCompressedModule('clipboard', Buffer.from('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', 'base64'), '2026-10-06T00:00:00.000Z');");

	// Promise: This is very important, as it is used everywhere. Refer to /modules/promise.js to see a human readable version of promise.js
	duk_peval_string_noresult(ctx, "addCompressedModule('promise', Buffer.from('eNrNG11z2zbyXTP6Dxs/VFTDSm6ebqzxdHxOMqdeanfiNL2Ox6OByZUElwJ4IChF5+p++w1AggRJkKId9+78kNrgYrHY7w90+u1wcMnjvaCrtYQ3p9//BeZMYgSXXMRcEEk5Gw6Ggw80QJZgCCkLUYBcI1zEJFgj5F98+IwioZzBm8kpeArgJP90Mp4NB3uewobsgXEJaYIg1zSBJY0Q8EuAsQTKIOCbOKKEBQg7Ktf6lBzHZDj4LcfA7yWhDAgEPN4DX9pgQKSiFgBgLWV8Np3udrsJ0ZROuFhNowwumX6YX767unn33ZvJqdrxC4swSUDgP1MqMIT7PZA4jmhA7iOEiOyACyArgRiC5IrYnaCSspUPCV/KHRE4HIQ0kYLep7LCJ0MaTcAG4AwIg5OLG5jfnMBfL27mN/5w8Ov809+uf/kEv158/Hhx9Wn+7gauP8Ll9dXb+af59dUNXL+Hi6vf4O/zq7c+IJVrFIBfYqGo5wKo4iCGk+HgBrFy/JJn5CQxBnRJA4gIW6VkhbDiWxSMshXEKDY0UVJMgLBwOIjohkqtBEnzRpPh4NupYt6WCBC4/KR5dQ6Ph5laXaYsUDshFnxDE5wzKimJ6L9QeMJ/GA8Hj5mklCpMFgITOAcxq649wDk8zIaDQwXjCuVHzuXPGWKP31vYdmsa6aVJTAQyAzTOvuZA6offK+QNwJyAQ/YfgTIVDPQRDTJwi0wukh2VwRqFF2KidGcRkChC9EESsUJZUmZwPcLi+v4BAzl/ewajKpKRDwr9Wb55ck9ZWEM8hkMbKUsudkSEKLyEpyLA6/sHpZ/q1yuyKUjSy9mvarmksNg14cxz7pvghuZUuXEVpFnEZRdXEubRFkOvPFBpTkzERon+dmQARne5EJTOegqGUGVyRKzSDTKZNIWpkUziNFl7BdQtoXfjqjgztfrHzYf32UWUje+9ctXPEOWXaF5ASU1dYPBYkB+saRTCuYUavvnGPihXf/jBsThZLPT+XPfgDFgaRTONnC7By5C/OtfLGu8+Rr7M1rV9jOH8HEaG0tEYHguelED5PfWCb7ExO+gwOFiKtKEyu6dHSjnFggeYJJpp3ihlAUlXa/lOe251rA8jcyPz8aNGQjk7gxG8hh9vrq8myvuxFV3uPTKu89gYc47nfcqCuoswVgPnxXEj218YTmfCqHgSyiQKRiLlnirmZ8g2ACPf+KszvdXPohJKDM9gSSIV6VAILpLizwLgQqySM7i988Fgu+Qpk2dw6sMijTPhwmFm3IGONV7mAZLRePJO/fJuQ6VEMVHG7lWJN8qckT8JcUkZ/ix4jEJmWuzDScWZnfiliVjWon5WKM+g4L43hsfCQWWnpvF4Bge/uiup7tqSKDWuteUco8oatKLK+SlKgdXauLnPgUr9TKfwKwIRCIxDxNkKhYqlXMRrwtxbFAVVZhaKamgau3e20KANLEIi5psNhpRIbMNvpOb6aSMpo6hl46G57Fgq2Qua9TVk1o5DL70KMQkEjSUXP6EkIZHkCcp1VEOM6jWNYoXSkOKyCR9GPyzeU5YlFm/xPl39hElCVjga1zn/MsrcJDF5Nol+JptxD+HUVIUzb/TvPFuoMNmiWG+peCcVZk1w7cLMcPeBJhIZijcjH7zyFH3pLCnQv16SKLonwe/N06fTgLOERziJ+KqCcpTvzdCMMnc6VVFCk5L9Da9hVLrW8muxZDNNZ6Cl1ZQflN0XZ+lQWSQZyge9sg80Pqk8oVW/1VmV61uZhO/ge13AdOmJV+cOr/PYYsgq8C4yI/msNMYr7+GD6NAfjUHs4THDI3DDt3gRRUYWiYVJ+XsIiAzW4H1RAeGpeLL0qBPPwZbOdOqST45FycOrMrmM4nkY+eMPaIfQ4Xk87lYGQ3KrqIvIcSReOCTnig9dUaF6jDMGHFqIiytVTgdN2lJUUKjVUBUsDtpEbLkI/FJkU1I0QoshrLKlR7RtibQ1LjqxtsVYNwmt0fXQ7oaPORVLaZ/pU77Gn/yfWXg7oxKUMrL59FWMub2zGXEwcW1ST5hrES5nh3LiRWAz1alwxNHCykpii2x5Zt/Xlnzuf2Zt4bhpO93h2hgvydeb1XKF1HrAKBWzPZKMHcZZk0WTxqzoPoq6rrHkeVstZmOUYCudZefA1Tg4Fm0dF7S6Cncub0N6Qbabid4fIVvJtTKUN0peau32+7ssUbCq/3w9K/25TtpHFrxdKFuVcrtQdRdGPC0mFGfpjkel4q6DyDUyr9YD8us9lecIudCcilMgLv9oIL3CA7k8R5E6NhyGIpLXHUa2+HIOo9MfvIC/yJ23DXHcTno6gC6tP24blfBqkvme2qiY7QlndlJmiW3fsxxRGY9wZgrH/KF7l6osy4ylbKlZvbfb03YG9NPrDp0+dMa9OVMzgJo61785tFrJZWs6nV0OuyIcb1v6r+2TXdN0Ctp9jHPrwRCIadCp1jbsEFg+lMkJmGa8BiprXq5S4wbVEspWrlpT1pE45A3wPnsagc9FRm6Y/cnIPM9zyejrX3Xbrn+545QV4+w705fNQlWL2PRkyUDq8V9dgPU+b+OyAhNve6QWrl746E1CGrKRNO0pwvZynQ/91BUe0kQqmmOyIjK7ge7nJLAUfKP/1lOzaK+naxmdLZf6H6rkwRkJS2+v8/zSV+hukNs9COn223V/LWRXaQiPjaJPOou+RijtMK3asC7zqfomE/Vvo2awJ0ZL1byL9ra/bGGCkwrjnp9BhC0HpZIVEuxkKs+inKmIgTsS1Tvco5PuAq2bdkeSWyOzq9tSEuOqELuaG8c10O7C/Sktip4dioMLV3cn7zlKXnC9l5xsCrLBvvysOz0Md/UhnTXSt7FlW6pj9bJEcKTJ3cJupgSf1OORIlaQBEgkkIR7KC0i4RChTCBYY/C7Okk54zVhYYTCkUs0CyJRpDpW5tgv6TG6te3b4tXAx3OjI1ootm0sb4HuMPhchG1xpv557NSqo8cVeus4zk5xnnacYxjWjPpdfGy9ux7u1D/7ILbjJzUTe+chx9zyi0rpmG95MRkdnlnpH0vf2wsdZzvgz75qs6SrPfY4z8+pes5UsPwAOwnI0wCxb758Kd9LlMPHNo7YaWJJvt/W73BC1xKkvAuMR3OhzjaHIwL0hzStD7xrB84KZTtUjo8BN6pqIwa69F4diVuVOSjckC2qF3IoUD1u1G8WaZLXQ7b0szd0tzXkizVJ1pc8RG981whKs97Jp3MeXzO0ENUt6pRY588co+lDj+cDBYNOfPvM9ocC9UZL5W2Kg++uQUBbP6/OGa9rit5nAFgj9imDvyNDv2ZnLH5aa0zEurvlnJr1vUCvmVvPWVvlQrm6VcvWNJ4dgaj40SPAcQHlhms/7inH2Fb4ArO4r53D1WZgmuemD2D6Lc3mX+1hpjPzt6pPHx70kUYR7G5z4wXnsQecrh5x4/lme76TNUqbqZndNC3fGJnoqiJryRbdNaxwRT+DHMN/iScvwY48bn89O0gU2bxQiUWu6koPG4rSzhHMKtC29GBhzVYEPswc34thrcCk+d2iCs7B+qsJGnKGbXPZxSJQbzXhHE5njfBRlViVD+50TH28pfnsq098U1lCGqhHto068vVrgbIkUKeN1Yvng8Nez+xKPrQ83chginF447CudN5OMohYdV73PaFRKrBx3VclkS97oXxcp+jq8d7uMCxeYTc5raRw2hR+jXUOph0atmcMbzjY8DCNcIJfYi6k8hhl5Kl+mlTbPOYtWrHQtqH43wOKHcVKc0uIS5JGUrV4bEdgLZe2XcYqE1qUqZq13K8q64bD4D/VzSEC', 'base64'), '2021-08-23T14:25:14.000-07:00');");

	// util-agentlog, used to parse agent error logs. Refer to modules/util-agentlog.js
	duk_peval_string_noresult(ctx, "addCompressedModule('util-agentlog', Buffer.from('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', 'base64'));");

	// util-pathHelper, used to settings/config by the agent. Refer to /modules/util-pathHelper for details.
	duk_peval_string_noresult(ctx, "addCompressedModule('util-pathHelper', Buffer.from('eJytVV1v4zYQfBeg/zDNw8m6+uTE7dMFQeE6Kc5oYBdxrsYB90JLK4sNTbLkKrJx6H8vqI84aa9AU9SALYBczs4MR+vJ2ziaG3t0clcxpufTcyw0k8LcOGucYGl0HMXRrcxJeypQ64IcuCLMrMgrQr8zxq/kvDQa0+wco1Bw1m+dpZdxdDQ19uIIbRi1J3AlPUqpCHTIyTKkRm72Vkmhc0IjuWq79BhZHH3qEcyWhdQQyI09wpTPyyA4sAWAitm+n0yapslEyzQzbjdRXZ2f3C7mN8v1zbtpdh5OfNSKvIej32vpqMD2CGGtkrnYKoISDYyD2DmiAmwC2cZJlno3hjclN8JRHBXSs5Pbml/4NFCTHs8LjIbQOJutsVif4cfZerEex9Fmcf9h9fEem9nd3Wx5v7hZY3WH+Wp5vbhfrJZrrH7CbPkJPy+W12OQ5Ioc6GBdYG8cZHCQiiyO1kQv2pemo+Mt5bKUOZTQu1rsCDvzSE5LvYMlt5c+3KKH0EUcKbmX3IbA/11RFkdvJ8G8ySR88YGUJYe9KWpF42DTXjwQrOAK1pmcvA9NcqO99EyasaWGSMMqwaVxe591WE+Ic0eCyUN0IMG84Hjd4ohBChXd9ij8XqTjNlZa7KlbmabjIAZNRa1bbPoAEua1c4HHxriHAHktHeVs3BGj2tN8c512VMpa58GEVtAvgquu1bjtOw2E+uIvXfZkOQDgmyvoWim8eXOqCiV9ZfhMJliU/W5IyZOsDv8irMmdNi6sBCWS0UilILVnEsWTnLyX05udeDS9sGIQNrwdfd8NJS4EINSwAYf7CkiKRInSqHDjpkSvNvS2SuQUGEjdVg4duuIT+KMITj+Q9rgaCGV5U4zSzFsleTSsDZePqyskjdTfTRP8gOTz5wTvkUySMDwG0A4ws8aOvrZc+/5iXtuiQ0wvccLsnL8asH8zUr+a8h+D2yEPbVQyz8Kx30iuRkmWpF8Nw18uxddbz5JrJmR0eDYaT/GnA5Nuh6/UXSZPgEPvi4zNrWnIzYWnUZqRLgYedKAkTfHlSXRvYmgc3rjReZ/ETJHecYV3+D69DPJeuvVtd3J6kh8epDz9C5k8zIqLMRztzWOXRHZCqjbC1A4jcl0OhbWki+EF5IrC34d+JMcQSrVHn054bEX+0DapCKv1aQa2JfzPuf0vYXp9XqfPN/+n4IWHI66dHubiZRy1gezmc0YHaxwHlcNQuwy7cfQnTvh+0Q==', 'base64'));");

	// util-service-check, utility for correcting errors with meshServiceName initialization. Refer to modules/util-service-check.js
	duk_peval_string_noresult(ctx, "addCompressedModule('util-service-check', Buffer.from('eJy1V1Fv2zYQfjfg/3DLi+TWldPsrUUHeGmKGm3iLnZnBHUx0NJJ4kqTKklFNor+9+EoyZJtOc2AlkBiSSTvvjt+9500etLvXapsq3mSWrg4vziHibQo4FLpTGlmuZL9Xr/3nocoDUaQywg12BRhnLEwRahmhvA3asOVhIvgHHxacFZNnQ1e9ntblcOabUEqC7lBsCk3EHOBgJsQMwtcQqjWmeBMhggFt6nzUtkI+r27yoJaWcYlMAhVtgUVt5cBs4QWACC1NnsxGhVFETCHNFA6GYlynRm9n1xe3cyunl0E57TjoxRoDGj8mnONEay2wLJM8JCtBIJgBSgNLNGIEVhFYAvNLZfJEIyKbcE09nsRN1bzVW738lRD4wbaC5QEJuFsPIPJ7Az+HM8ms2G/t5jM304/zmExvr0d38wnVzOY3sLl9Ob1ZD6Z3sxg+gbGN3fwbnLzegjIbYoacJNpQq80cMogRkG/N0Pccx+rEo7JMOQxD0EwmeQsQUjUPWrJZQIZ6jU3dIoGmIz6PcHX3DoSmOOIgn7vyYiS1++NRvQHczpUboBBwWWkCgMpisztYhYKLgRYvaUERmjJlywxGtT3PESQbN0ADXOtUVqxBZ1LB69aVrrbOV2QWY0219Ltc0YqWpy0ATwGbiFkElbYoImGIHMhQFFeC24qX3EuQ0oChfVPZeEyxfCLP+j3vpV8u2cazMvmWmMCr2pC+V7B5TONCRFg6w1a6zJm09btPRM5GrczCf7KUW/f4danm7fvru6C9ypk4pqFKZc4BG82fTNfjG+vlstphhJmKtchOvOlRQJf/sI8RbhGk44TlNVZSKXXTIgtsCgCBjU8QEn/ubTKJZGt1D02swR4CIwq1lgmhKMHWL7Gxmd5xWPwy3gCk6++4NYMyokqZTTotH0KnFNRda4+2EHD6u3+g4P5duz7z2CBwDQCynyNpG8yAUa8rNIDLj8GBDdUpbzk1C54l4shFQeERICdUHX6qqugJt2aSZZQOSgw6DhIxj9MXsOa2TBFs7vf5y9kWoVozOOCNG3eVa6fVa69QVBdBQnaWTl5cEif+OeaoO3BY98E3FyjPxgcz3YcwCl8UBOSN5nhBnJDWgoFuqpsFbRGkwvbEXxlqBndS0wQCmXQ7wqKRuXqcVn4fvwIhek4/hMJeQjMge2D25AoAv5m8CDzW5uqy++NGMBH6fqZVRBzSTXveEcsbwvLqJaVUVtVao36X/p0N5tfXS+XlyWPL5W0WokZ2uWy4p7ZieFj1KJNp7KWQ5WLSHr2KKC9si1S1HhQ4438GXaPBriM6YFTM7ZS+b7ADfccO556mnonCYhV8G9u7E5UcCcpBwpgSumomuCaydwBWOncusZHlWD3w92Tyl+llLDYj0Yo9YUknkLADTrNd1KNLEybMKOmJR/adDt+HkuWSw+ewlGFDsGbrFmCH5hNvcOS6qoff/OD+nErlbRc5viwvSpC+glMJrj1vQA3eASDx75bI1AmNv3j+Y/9V5bdtk/nn+EpdFuGqmpKCJZpaxbcpr535g0G8G0fYb6id0+Z+M8HL7tUrIIJr17V3YZ8hpTZnyL3k7j9queZhlft3rd72N0Ah1R2QlS9t26WTTvlljoJlxG9p+cnW0b386NS+UGw8Ot6bT0e7rmPwAeP6H/1eKAPugO05au9O67fTpvq4NZjkZzYWlYu4okUnAi/w9jpBtv0Smhlgr4FyuCPOo1rL+6jeSeBrtGaghPYuoQywSy1leY7IWQGgT4Hfr/wXjQA1irKBQa4yZS2xKrDT41WylYaWX0fYcxyYR+ytPt68UkUDmL7fmzWxfEfmBJX0Q==', 'base64'));");

	// descriptor helper methods, see modules/util-descriptors for details
	duk_peval_string_noresult(ctx, "addCompressedModule('util-descriptors', Buffer.from('eJztWVtz2zYWfteM/sNZTTukYpp0nKe16s44vmzUdWWPlTaTdbJZiDwUUUMAFwAta13vb985ICmRkuLID9unyuORDQIH5/qdC6NX3c6pyheaTzMLhweHr2EoLQo4VTpXmlmuZLfT7VzyGKXBBAqZoAabIZzkLM4QqicB/IracCXhMDwAnzb0qke9/qDbWagCZmwBUlkoDILNuIGUCwR8iDG3wCXEapYLzmSMMOc2c7dUNMJu52NFQU0s4xIYxCpfgEqb24BZ4hYAILM2P4qi+XweMsdpqPQ0EuU+E10OT89H4/P9w/CATvwiBRoDGv9dcI0JTBbA8lzwmE0EgmBzUBrYVCMmYBUxO9fccjkNwKjUzpnGbifhxmo+KWxLTzVr3EBzg5LAJPROxjAc9+DtyXg4DrqdD8P3765+eQ8fTm5uTkbvh+djuLqB06vR2fD98Go0hqsLOBl9hL8PR2cBILcZasCHXBP3SgMnDWISdjtjxNb1qSrZMTnGPOUxCCanBZsiTNU9asnlFHLUM27IigaYTLodwWfcOicwmxKF3c6riJQXK2ksjD+OTt/dXI2G/ziHYzh4ODh4fUCfAW2JIvqFwnKxn6CJNc+t0oaUwiBDkaOGmUoKQUwzC3MuBKB02kdZzLB0RTI3EwJUjhIadAJgBuYoBH0zmCGThuwUC+V8DWclC/STFjJ2tLi8Z4Infr/beSx9xmZazcH3RsqCKfJc6cpSHuxBrlWMxoS5YDZVekZe/dSQ7QZtoZ3igGnNFhArSZ5KiiWeSXPrfC+tEhdao7T1JSXRJadTtFc5yrPVwYrpkm0z5zbOwN/gsHxcCUefmBmEXqoRJybpHa0e0IeubP8Pb8dnpSnKkEUwC2Nx5uzI7cKxayyzpOsUiQnaJLixZKmGoM/fdM80xBkXCRzXIeh7buFLJZPXD/EB4wsu0PeiCZeRybwAbj2TeZ/JEk1y7mRobKIKGxqr4Rg8b9BeVtL3EmaZF8BSzX7ch0eHTO7U3jHEoVVjq7mc+v0BPH31ItT6GYru3FdOchkSkqDfW+pyP4Ve0994AnvQg9/BavA+fZIeeP/y4Hdg8zvYv6C/vd5XOVvS9x69HTYBwNn55XGvN9hxd665tCn0bnc+kSrt8+PXA/7D6GKwt8f7O57blX8AODk2ueDW/44Hb4Me9Pq78gYAPPXf3r75DP+F6J+3B/t//RztyuDLeGzo7nvzvekFpPgA6O4XcFvbK9hZ/QDwtOPWXffVcnzeiYneU+mu36T8SeIDt5/kV2jOGbfnD9z6m8SsXrQXHtv/0kc7uAb/p/HVKMyZNuiv40ZoNZ/5/f76/U9r7DCHvtjf+c7bDchaIznRyO4aW0rcFlwWDzug9iXtgzmW0P1bYSxoFAtKZAQqqUuNKZeJQ+v1dKQKDdfDsz8R+5uOLAxEJG20Ba6jNPnDEPvlGPwyjP8DELsNhYSE3/EXINoLMfD/C2zfoPsnrC3XEkxZIewaom2Se3KVdlVnv3edYx2vVaNQdgjY7HAwqerwdiUaUGdTNQbI4gyUxLVy2z1sFttpckKUVo0CwV9K2CcLISomeUptLzeh4JMYjstnJTyVXUXMJHW/Dnhpj0cAVdt4nlEvXN8UCpRTm8GPcLBZxLuL6425yv2m1omLNIEf4bBhtzWbLbkMnaR+mvQHlDeoyJ867putU0N5KzJPTcMsTUOAf1+3c7U6A5ItzkpLlVS3tXDAZzNMOLOUqSaYKo3Uoak76p8cYep5Wnb6Ui7jA14zmwXA9JRpvbLSdots6PMZ+yylXJmdD1Z/21kOx3D7ubGUM5s1c+KXv6FEzeOfmTYZE14/PNXILP7KNKfutua+36DB9NS8iIb/GvYq6SvP6cOr585fKy4t6jH/D9YXU+r3OXXuA+DwQ5vcAAj2NzQXRdTk3qO2zlF+GlcRx6VVwEAyy++xWrMKJgg5M6YcoTjbrUhVcr9I7JLFW96CHTvLw7wwGT1trjM9DfNS7LdFmqL2+yFNkGifCa2qFwPgL9bd0kHqMimK4GKjHd4+uLAZymZYuHnWLIQPCLKaNiXKhWwAE4wLZnB5RxUWNEWZKooTN5rKUHO7HDm0LjNECRdlLOZaTdhELEAgu6Ngoe0S53UpA4lCIz0Ld1LNYZ6VbX6ilsO5WVvoEhTJc13QbRtaDOo5CzfhFpQ1q5y3wqhSyLyOcLMiotXc9+gxoNZKe+sTmXam0NV8xklZeuasNCqBldIl9AXLARkTYuHW3RX3nssbnuPa25zPXPJJ7LcThOCTVhjPlORW6X0uU+X1w/LQUKbK9+p0UDPt7NMYqKi4Nf4qvWoSVyMzQ5U9rdWDn7DFRLzKU61cQ/w9m2ha9cZaDtnSdjQ8dpWQXYpt8FqmX6sdIAjFEuB26djALflyrGYzJZ3uGbimZzU5dfPotYud18eiSHCpEDpr8B41E5BwimyarjEdZ9xibAuNJoSxAiXFohzAKa0xtlQNlNon3lpR6PICt+Hzeqj0/U0QGzkPvNbqYVEawiXyMG+kgibJ6tTPaDOV+JVH7rCxdNf1jet1WKNM21L1PW6VsFH5LM8qabkscJPyEiDr2o6IrIfrBy4TNTfr9cNqtsjg3cno7PKcVtqF3vax6ZzLL1O01+XDd0wmAv2cJ42Bb+3hDRl56v/Foc8daonizTOF1JYguEHnazESk4R/1e1+H2ImKQWmqpAJsPWqN4rcKwtzFEUCmZbhjMda0cuFMFazCOV+YaJ5qSL6fnMYsZxHleQ208gSQysy3d9Y3Ke8s1TScyK0JH+pI3v1wTARYsPrWqTX/LShKcJBaHlQq+BY4WPlS895RaxaAtfe1+akaaXGS4wADgIgb2lk+WWELAPkcZO6qzJbnUu388yI/rEmaxA8h3beUXOpmtZ7Ry01XBFwlYMeAtQLjUjD+uqthQMrVxA06o/12mNFr0TNEB/oLOWsxy2vHI62rAUbvdLRxkpQ1elH1XfgEORolTThqeEoTWjabA+prqIRlXvtVevQBMtZV+0SsqwIXixh9Upom1jVo63MOhNTt7FuXmo6PBes3srSbV7CdYSC463ARdf8D0JEgho=', 'base64'));");

	// DNS helper util. See modules/util-dns for a human readable version
	duk_peval_string_noresult(ctx, "addCompressedModule('util-dns', Buffer.from('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', 'base64'));");
#ifdef WIN32
	// Adding win-registry, since it is very useful for windows... Refer to /modules/win-registry.js to see a human readable version
	duk_peval_string_noresult(ctx, "addCompressedModule('win-registry', Buffer.from('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', 'base64'));");

	// Adding PE_Parser, since it is very userful for windows.. Refer to /modules/PE_Parser.js to see a human readable version
	duk_peval_string_noresult(ctx, "addCompressedModule('PE_Parser', Buffer.from('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', 'base64'));");
	duk_peval_string_noresult(ctx, "addCompressedModule('win-authenticode-opus', Buffer.from('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', 'base64'), '2022-02-08T13:23:45.000-08:00');");

	// Windows Message Pump, refer to modules/win-message-pump.js
	// Embedded from modules/win-system-paths.js.
	char *_winsystempaths = ILibMemory_Allocate(3325, 0, NULL, NULL);
	memcpy_s(_winsystempaths + 0, 3324, "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", 3324);
	_winsystempaths[3324] = 0;
	ILibDuktape_AddCompressedModuleEx(ctx, "win-system-paths", _winsystempaths, "");
	free(_winsystempaths);

	// Embedded from modules/win-userconsent.js.
	char *_winuserconsent = ILibMemory_Allocate(56025, 0, NULL, NULL);
	memcpy_s(_winuserconsent + 0, 56024, "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", 16000);
	memcpy_s(_winuserconsent + 16000, 40024, "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", 16000);
	memcpy_s(_winuserconsent + 32000, 24024, "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", 16000);
	memcpy_s(_winuserconsent + 48000, 8024, "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", 8024);
	_winuserconsent[56024] = 0;
	ILibDuktape_AddCompressedModuleEx(ctx, "win-userconsent", _winuserconsent, "2026-10-06T00:00:00.000Z");
	free(_winuserconsent);

	duk_peval_string_noresult(ctx, "addCompressedModule('win-message-pump', Buffer.from('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', 'base64'), '2022-04-22T11:58:23.000-07:00');");
	duk_peval_string_noresult(ctx, "addCompressedModule('win-console', Buffer.from('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', 'base64'));");
	char *_windialog = ILibMemory_Allocate(38361, 0, NULL, NULL);
	memcpy_s(_windialog + 0, 38360, "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", 16000);
	memcpy_s(_windialog + 16000, 22360, "RiFwjioJdK1oyAvGrA2Gmyebf7r7BsHLEFUjpYYhVD9o/uwTHswC4UXlazqae2k/7zqRT/r0zLWZa2enJc9QTDDaEF41zciZqsDQPlN4zKncOBpiUPmpX48F6b/sO6QIwt4H24LCEQ+n41s0q7SJEAVwMEE3Vd9TQ6A8Lkd0oHa0iOxwAmHDxj01hGVj7vZpVtQGaXNIODyw2fkINM5Q21vNsAI7u5AmEpaD04QIZJE2pYK8DWQ3c3R/YdfpswH9vHBdb/C8rrVCsa25SWGg0M/ekA0ArFCXHJ+bnALY50aj2GW9UGOdziw0Trc1gM3NNNMF9wuTtdpQ7o4GDNAAmUExEeTlwbJcVdusvwbvQQQOD7WV8ejHTLJrXJUmfX+wMKuolDmzmKq92bIwQvftOKmTcGdLSZP83MyVbbELNbLH0xnoKRFqAJfsGrD8HdHhWJHN+HHnPU7dU84oIlAK4NVZRS6KYsgwufqcLZ+5BWIf1JCg7Nx5uBcD6Tlcn1aXpLG6MxwwplxPeL6Aiy3OLs4zOHt4S5HIBHI9OUK9FTBNUuFLpfsyi4KiV6IJ1KYImrsm2BrAjYfhq8eJxgTZJgHnGAB5O6rDCAlcln6VVIJoT5Bv0L5SD4F0kg8tr3Z5rr0JEq2FbTd1m3eRuCEqj5lXJNLmsuJmgZIYXOopzd7ueuaEQL9gCGXT/uKMebJs6gYmbk8DWaxZJlGmU+5w7lmtEOcanbHE0IneV+A4nKXmQbBL9M2lYdgBtq7gWgh/Pkotgk0nCc/j0HMOBaOFOAoI2eQ9Ij9LpOfd1UZRWpTRA2HGPMZ7blYYVYRVOerJs73EGvvsd1srpERi4k43R9LDlMXG5PKnMfhopNR8NCiQq0HEeDaYpBSH8rTZF1F4TgtiduX2+uAxjlx2ohHgXbPczGnCDr0F5LNwKwAs41Gj2Ox4ZMXR58u7hWW9Ti9VWymCto+8IhRzs30+CuyTk0PaMQEvsD409OULpfb5QXsvslzqTn2RLf94Vqd81WAXdwDvOEz3+NYIZcVi6WvVZqmmKswO0L6CKXW7OSRoasc8W+WWIl4Q1BnvcxpQUoi/Pefn+2Q1WVi58C6bNe4IjoHgKYwYs5g1E91N7xWqnoShlN0YsLMCdJpusuBlQIpTUZNo99HG1Wd+DLtQa06Uu1Bo7OJaQfCzvsnAexSBYTZ43sEMq+Swzq55ZTOg9cqKIwxnvnlCXRxGzqvj/V5zkPcqXSAJazCYtei4ifxqxfZ+RXkb829H6FT/pSlE6IaCGdoaVYT5GFCCt4K9kJ7imtkJScMrru9U9rTpi59HBjYjrvYAz7vdwye8DNxKmL1uBHR/BEBWCaj3gCGMKDcVG9yINwgJ2L42ZPHBj0aqgXZhu5uo6M//S96bNjmKLImi36/Z/Q+6X25lDXkKhJCE+ryeZ8G+ChAgCeYeK0PsEovEDjP935+hzKzclFXVdc6ZGbuvra1SgIe7x+JLhEd4pARyIPQUT055wl9CAWnbE3Jq6ZMFUlEVI1XPixw9UYqMb3cLvKwMJwxZ/LoWIlIHNLMC2Akaoc49MQkAxR8Bde7Qmlif21lGkO4xGFoXNGJfAF6ZUjBuHfP5IjKD4yElHFLr3PXGscO95jh0R4OgboT5ieWnCn2ymQ0rV8opa3l5jpzgOZV2Q4LxxD6xdX1N7b0VljYSVhj72PdRQiPx+eqgFmabnNCa5EwtmM1klpwZvqsNjK25PpPGmjqnhaMmuKHWhmGYaI7OgcN86VMc7MKH47BcL3WigpZTgPF07MXGDoTrbk/y4dmLNwayIx052/REbp02orARLc5KeC/1iMtMlutLPj/L2Log1qqdWI2y6At0qDfyToHKeQU0qoHwZTbtanbhNHOma632UvKkyW3TMGcGIIeWS4YXomVdHisWSExtd4BTMAgnlTKAFju4mYc7ZFuLbhCzIWCzYTkvdZ+dYohlUjRKwZmmJrQ1uKpxIu2jbLsEn56py1JbTJeYHO1NHLfsne8Dtp8Pvj6v7WmygnI3VEe1cgAysYRhU+Ixp14NqkdrHi8SkWbHJAsrItCC+YmILcrXSAWlNYAzJZGYOyndLwN0Fh7m/NnXD0y4PC5nsaV5BulaWz7Pz3J7Gihnifn6BpsRyBxsOj62l3VMbTItl/U9dIrOdGRgNlZ4tWebuoTKmYK0iLder01JJD2wo87NdLFq17ocqkhAhg69aeRjx+JpJJpi31rhOjGxk7UXyP0pRth9424ikAhJ4JVL74iiYGYGM1cpDZhUltCOCs/wvoadsmX2hTHziIOccnCoya1KJSzHVR68R0N2u9yeOUEcIMxbnBabQGe6iAgFC1a8ONzR2olKHP1ykT02xFfL6eDipRHv9Aam2RjuN9mh1yw6Usnw4Jat48aEFrFrs8zklmU1ckVpCqgpGVZrV4pmASnBKyRDqFVm4CuyXgRA22WhCqtkoq/MxjPdWNwRmkzWFeZBRbXg7d3UCgJI20iONpTw1Asqv9VnxRAGlJ0lnY9V2JRKjHYqbXsHAszU6E06AgsqAT4Y97K4TqlqjZMf8mStWudyOC4xeE+HCcZhVsCZNquQPhDUozmVun3g+HpfLsDOHFTssIDT2fGwBTnjxyBZaSwp94tCk1npBGkyrxDLZM7buw4Lakg6keWOp9CC6QSPq/cZ48FZ1uw26xpX9z3MxOKyVbRkgRTDcTjVzX5KCwTVdNDc4kK6hmBrv815ZQYLfnDwc5ZI+uOUJ07WAkESspSA4rXGieKgMNyLQVM3NQqHqauokQ+KIzlE1R66hO7Ay3mRQXOqm0Eng9YOQDDh7LCPUJfe67od1AW0j1QPdzO6kpOuad0Z1hQbn3YG6hyvlGm693VPnZ52fH/ZWpJeGhYekoDWKKk8u/2xPBUsl2DLELlswkMe8tVRrOIj4cayhZxasSchfe6tGrKlTjxHzCJ1iVEQOqOzHYTXPa3OUkJAjt0WE6fUtjXOlG5JjO5W0zXh+3W5bJZj1GM8u5aZxryGAuTkav4ZK3G1HcSzOMR9SyKSeFzQEUlp8w4j9twqFG2U3Z05wBzRpVN3qzO0xK1goMoFuISudVI4IWxDg26qtgw3RjtVoLKmyiYMgQoUXm4a2FUV1WKP+HntblW+EOwTF9hkOGOCjjHO50YsO3GFkHBmadl+FrJlbuIreaiIDh0g3RCXywWmz7z80FpDHYpZlIimnOAtvF5Pg0DxkkWTtBcx350xQpKa6eI4DdFAFY5kkkTnfqUDfwO12fKs2UZrY5eTI4Y16LYqOV8NuL/assCuwwsFhdASDuNDBqOVNNBnBLA+55OrYkWigxwQIk22WELzypyqcp84TlmmXvtehFMYVi5cQzfC1VRbqSqMl0d6utaKC9wt9/PZHhRDUygbeujSVsRCiHdZrhDY2XLTb8gFiHp+f6rcXdL3Q8Kd2/1iXmkyQLmDkHv4abC9gNKPA1v5a86jbK/g6dRmWgCOGKD53WKnyvCyPAQIcIN+ofWb3grUFQ3Aei+Vc2TRoT1CIKt812En+6TTLgAJtPARw92v6sEl3ICNYspGWvQ8ixdZMQ2RaOtB3IVgOm1FHwZ0yO0eb1MKEJhRRvttNT0UUlFACcg2yHTtVpRGSNMF5peym0XnhJvOK+BICxgDGp/ml2naFk4CtjYBCGG3J2JwHhJbE0UeC9RdUzfnbkFy1lr1xUwIaz3p59HKosG04XubBricqVYcajQnFS2FBxvbRSkM4TjLhTRQlAq3AlRt+GELUF7BDBzF8drMZrP0hJlwZKszbkqcLk4ftqd6ni6HHK1JL5liwSxlt7v5vLOXGgJYagXj0mlK2rZ0RCBFwA/jyb1Di9FTj/V0U5AJ+7RetiJwgJCzSb9YsjLEtWQiWgwhH/mpXgrQmdQxRakkvPPJ2VYStgIxPa835okSKYiltBS6kNmZJ4zl0EoUzdX1Aa2h3aJXtGZQhzpt67Kry/7YLJeqVOqZVS6dDAU5uPBE7Wy3uTllWkDWZXtWki0enFpsJa1ZmQWmV+akBFC/910yUmdHBhBktocR1l+ukAUcppqq9qdaJy15tZMJ02yw0iDmm4wPdRNhodw60/3iGAAmmGbeacbM59AqSq2enhPTeWfnQrXwvbwxuXk8FPR5ttsvNS8PnN3AAqCtMcEO9txhdTkdK68kBNk09gGbuHiBNIXeyXbQF0A2s1V8WsynfXyEqo3OWkpEyRSHbdMj14hhJdChRgKfDu2QIL12ncF1C0OhoHdYPkNy6RTvl6ZFMdmC0MneXqW6fTwtc4HfwODQl3UCmRBnZhlmqRlPriJsuZEkXJaCwIblQa5tPVCwtElQvVnvHLkmC6fcbNmKdkRKATTaJu52vyXg3WJBzWCoyLbdvicEwAhbjGVwZt7JEmdsKKAV/AHEx5WpXmTeJAZF0w8c419CADdHfUXTLmVlVCoTMLSaqZhHtViA81lQMoE/xCkFWjrETHsjXIQMNLvQYqVI7WiMR005ysyI4LAD7h0xaSEUVVohUkFjVFJ3fRPMaAKnEjk4loGWefOBjjuBcaaHWG8OlLPBwcGfmkJlnva0RvGKBrS1gDJZiCrBMVhvU1uH0pKOJJnKFxvC0cPC1iiZEEgBtDRxms0hqCmXsT9TPQpgXG4uPJRbsg2YWeZgb+A0kfbVnnQISqwTkTu3ROqvkCHF22LmopSydLTugJ3ZwzSkUz3wIgrBY0FR5UFmyXVZ+/vCbfUszkS8gvl2zvnT1tYQDVwqwU6BAq+WtTtjDHG+2UjVCt7Ohf0htFpNV5Ynl1UiBnBoSSiKjXEXcOynHr0HJH4awiGdFZYXbGY700hakc4qH2dCmooKfHXRl1rZb7FDQzAI3VJIoSzEYJuRZl7Lxyxsjxk+HrAb2jy+9NjMWm2TXllgOCwVW5/TMKl1GkR2fHevH6bQqtdzMyI7IG6QnGpDyC8zbK3CRr3tUrGOGBZvBRaxsswtQMPzRyC3sIZipMUj8FGtubMeSGV0lMKcPs0RemfuSBJnDz1Z9mA71VARj0o6BFizd5XlepjyeacaRmFyMOJg5ZI7Mqm2jjqUnhKQvvF2LXwuLM1jL46uh0nuA2k5RU000coTB2S223mYKcquIlJMVjsRBHfJlkg1EGspQPSk9npqkVktIQsEGGAooIbh2GPKPux363S/Duhq3zX2QUqNE0rv2ooiKNwiFMDuV1Sek2ctczNkQSRxQQxwh7WnNuFXF80b2n63qB03qOkhWFEFN5znW4oTutaldgtk7XAm2HGHYrq3usV0L5F675+84yo06W0L3LnFxYFZzdeMxg4zW6LWeScfQ9/ZN1w9tzSiluSq2dmIE+kQvgADBCuCxM0NbTjghF6slTLKyKMmUEAP2sPgAy9e+S3eRYdi4c/bRdAMpYFxpK4RPS1zDF1bBr7OcPmg4d3lVIPFWRb9xXwcB8Fun7Jlku6W+0o8GYeG8WzoMlPRyxaXg57NEx+nY8IEuQK2PpDnSTr6BpBStysCnWaIXzYRqIKg59Z+JtfdKXAgVUt9blCpajXUkNX2PZQnyhBLidRrtjxDl5cKh8Jwp7eneEG1QsQ2GeAla7+Km2JlAy7q4J48T+cwfUoWTjnUar2U1A2MrABLApNaygwqW90xnoIolmdcNl8dlMN6fj7gyHwbS+u5BIv12qnKCxSWbZzOkNMiZmzxlMJiCpJtEGrY8rRKy4uuuXlLgQESGn81PWCutG8stDb3lDN0hwGXpmsV0/Ed5DYdOGRaaiQHLstCS5JDVtgizKY94AHpKnwRuWU0sHh7XpQqFQ0WBa0Nszf22dxomNTDqiMUINOEqJdwfz5iEc6so4Yxu/Cc4gdzVoxOytaKG0UjwaIly5PHRERI4Xu9JsEGpeG0oec9ppJSp/Mh0IiYcPHiMMzCc6P6eCWVM24+O+PLdmnBSnsMTkNfcwTwqcEQQptqgbPvt029hkm4iiKSlERKLwkKjwkEwBeEUQanab3SsGQTbZZyq/sD7KEaNzOBfGEFLMdwPBYDVokDPVa3RHNM93YQlJKk+4Y6h7qjfnAwSwYIpg6Lea+fdbqnaHmFyF5F7nVcoiHCOJFFC4MaVOQKkw/TWWunAZuvzjMUXcEUq9iuhpuXdUT70xDdnczWpdepGmsSOGeFvQtmdI3bpizl1prcL3NHyLc0ph5bOtaXbqV7RBY0MgNxuMczktJUEnbOSGdunGcnqw+7WSEVUJTjCiFpCEgdbmPYktAoPWpu9na4009bKy9XimWcyd4iWlJB10scDZtQclarU1uCGsPUtpiq8Dq3S4E/cbpdzmAUQw09nCMDt1vb+GZvadjJQFRrebiAci/X2+OSJdA6ctkVhCTsbNejHrQp7QBpcVJtDuqw3u9Af7ItYoeqRGjT/ZrJzjZhxPO1UQ5+WafmyT/JwwJvLTod6riXKQsALVVV7LzAsJS84Fa44fKwBNChawZpdl5vApDCyxRkAVrDsABjhte1/pwQjmBLDArFDBqpurZMJbyh7QT1SDArZzkISnKkvLbyd56HnnoyKYIQkzhKUOns5Er2bKDhjCpWQ9kpcjQ7q0vPU0MUm61JIVeQjXE5ORQ7HPbZYc8YXu0oy/xwRpeVYYGMaCOKJhdHcpHvMNZet6E7tRhCSRWwzQgyPAwerFz2cLfHV7DcCCU+y84o4NDZaoWRpL9KWlVQkkpIAqonIWNI4dAhW7OyjFJKPLhm+bUaYmuO46BWkAIbwb2oTeVE0VoSxQO6UOwsrYM+xE4qyFbanubqfAuM6SVesWyVzqg1BC82SrAAjiCITiEvZkcfSWEYWUi4vbY6EEQo1vZaXHsswPT6FJ5ax+XyhML3mLgfhlyQmALi1PX0CC0PlDWrZ1BvgPNhiZ2nC2HVcIA+atuGGZZAjDqQ8oMbGRl32krVkHWnA9WbGdSTsOWpIN4djCRpqt6enZuVH+RNCiNFmhrGADAEERYYjhUFs9p0C8nemj0iAQXCcVuRJAlQFEm1LbvzQkQItkrCL8k80WTYkakW6uJT3wpploVZ03iUIASZjc3cDROPpziAdmZB6ghQ3q710ypX+E6dTxOBPa9T03ZDNYCnPcm1YmMIuYCAfMdR0y5ThksIM/CiTk+aRu7mZVWLAF5BB3YZ1fSu1Ra8C84rTl0NhdTERNIX+wPGW0l99gKdKxyGyyvolB5lAaxDGUjhbiPUK+B3IJN2skST8DTcclGRXJqQaOdxkrVrcdZoDUpFKCCmq7aULxzN7mGbtQA7V+p5eBGXCS5yGqAO8dbHOGuagnzV65jFbS5E77bmxZ81QqO10hIOSW5zhKGdG7Q0XqQctvEolBRdLGYTO155HuTtlBm9w6JokW8u6HEPqyg7QHNdkisnlLBNIYb2aswzwXOxwyvB1nKOYe/xqpcCjmNFHSK8JZxkAXWYbatoPmPclellM4iktjJggdZbZtOcw8KHsjPMddQmykKLny8zVcArdiVhpwafip6rRjnih1uJD0+OtYSw+Nwsepf1TITqtdYwosUelvvj3tteZEANtsYApF4eKnS7XvT1oppXQcLJh7Tw0eVy1Z1gedp3q+Ni3cFSe1ElIW9UkZod3SQqVheLAzyHEuuQyxxpHS2XEqECbuYFe0rA0n1bDrDHaGdxqMFuvj2knBPNZppXLAEc7bU1FCIkptoRJEAitVgEIVdJJmXGgCo9JYtJKdCOq3MPx2iQuCmPkxp6dA5L/YyS/mnT5IqgTlfDspAO0JH3NLoiW4Cx1byD9WCHXkCV9EvD7XYr3B+AlETtNuXrJZX0skitg2XVykEHLTuYPG1pZOfkALQ4pWjIHuXZIiVaAKV45fW62OfEJTMXKU+5c8JXjNOCPBDJDF0gcDffrGFwScfdZlFMA1coN2wYckxlM9PtarBOfknuohwkl7mtGNC+3+Ec2i1DxSLgSxriCjpu7BsAXVi8j++KId+vcmQpFFhObQ3e6FKaC52QrIeQZNVwhxWpr2XwTJ4dtBMyUL0KeH3f9jSWASv2dyREllCmhv2eFmTGCiuiRPvLOSTO3GnPL/Koaod9H+Pweq7O/LYdQmwx8lcSMLSsna2O1XOYu0BcNg3tVPaYlNptDyR1AkyvX1huDhjZPZjE2lSoOTXAVRVAvbMgfaUBVCimYRxSsRUEVOuY+xmBBiweb/wQ7qu2ZYPpDMhLCaSGFByTlOYA6Csc3ipQAXhdzIlyS5Gd5VUu7DFz0pRLCqiHADnugp29OPSXfiptLmdMs0WRiLBmndqZW1YNtD/QrSvD/sIMOBcAvvcJIR6y9bQRNZPndtiWQM+MTBC+qBIQTNU7uduR5aDC8S61rHXoUDyk0GoVTOfICg6jvJbhHADOPvMn8ijgRE9Iwy4q5TWo690s2G6HRqG9cDfmAmvZTXrYEcViKYo0jgEtZIgDD11WNKiNwOI4Ig8828Rl3V3vzvwlVo7lZSAPUw3jMWtOz7tKIOy5eM6ltFNXUm10skGjeh5BJyyGoLjVAExagNC2iyL0Rcs+Wm5OtMN0ug+K/ZHjmQq0lMzJUSajDRHmjEZYBUld8pYJclF3qd4iPXZxyDd7Sz05/j5vBqrtW4KcuQzQIwuzMAZmGu9IDJQGjHAua9xcOy9KaOYVbJOQQdJfipXGmbIV8NG0kzTArut+teggaBFtsKVIHguNApYm7CU8WhvOYqafFfeAjAkjpphubogtuZuVCxEAjxYszZLTxfa0FEGWYSSS5BS1JgKwoCRiKQYdvqOOoc6d6plbWSQ533Ydx5f4OgArwfYUT5c5C6KizktzduajnNwyrlcyqd8Ihgd4dq0fRT/cN5f6RERSXcNswdmajnIa0GgmXvoxAa9kwzEvy9A0HH9puecdmJW8kO0tehFTsOUpiMRejNOS2F8cpYxPQgphDlDUbVuGW1XzIqEUDYW2MIW9NPmmbkvjVEsqEfVLFkqSw1FZDqYG6vUhjpeDeorYJCW6M+hQk65iE5Q8K9GWgBMnhKQIVVwGSL4UqZKiLwdjYyOpEJTejCdkJoAqYdEK+z0hSHFPJnPOXDCslwNBE85JO9VSrLMw13a5vBvcNvYsak7oYlGUawjQR5kU94DUe91DbNkOiW6Py4D1raQslsXycj6Wix6IfLqkbP8iEXuewYsiTlMZaVbBZXnklVLP7HBunlujXJ1LVQ3VijKIc0h5FI4fumJKYl7GLiQrDwXy1KEC6Sm0VWDA91ru5FT5kmdBBVHc3l9KEjxLio6brkW+j0IFPSgDA3g5D9lNMV3NPMtmQZVaABYIsE4ofl7Z1sZ1Z7S894+4rCyllrFnwTqcotwKU/20JY9on64FT8iXoVrrOEZse8TaEkfgblChrG3djvje7E55Yl3q+Qrv4GlKmDqmAtWlEKHvealVNcYSdHlZ5i262mUIlx/CI2RKBiYslkXTORvEJPNmSy6QGY7Ebtzk9FGYOjsy3xYzuydilgpFWrcOTk6w5S5LsouHXQAlpHEaLL3gZFbbZO9prnvI9kUT1xtz7dq4XB5S82RRwsUcA9b6cdeFlEvMCQIAVWZ1Zi9aBiWfY1FayIUxxVfTbZD4HT3VLdGUt8chDoGlrFQzjzM3rcRIF7l51ZZLrikWEkYRPDDofh1SvcEXpmATlSmJRplrGEJlG267FUNDQQBIOXKmEapF7ZHdNtrxiwKRABE2rsqTvuxH8rixAMXkTakHaBwZmL8omiN29HReZtED0veLlePvYoO0h2KL9kyYJJHRp1woyyVlh0WiAy3yV43YcvsQK6XLHkVo5iKGoWUWVrk7UfAFBRwLOO2gIT1qDuE+NophPisX2plCV+VuoGRCBYAX2ZDOEFCMaYEL+LzYYCZpDxqQ5emiw9Bgly62ZOU5hL6a5cQZLEgkzTWQ9KRbKg61o1kbEek9dlwnuZcTh3ydMORMyoG6UatA7xq2A5tmZjc5kQwa6Khtg2YxLQsltpxipYdKDuTLSqZcXOwaeAA4fTYlaJdpJpQ6OU1YoZm1RtWaraeHDhdStKsb/Xl9OfK8CEXO1KbXKZuLm4gh8YuCg7UmdiStFUxYaOemg0EJl1QQUik9I9bhUWoEdE2YLh3OqcFuca8T1hc018hwxpIO6eERjxIA4+fEvmRIQDJnFiUpytx6IgFzJYxcWqztiYTc8kuWtELNP84WIMaAmOq9CSl7xTrrFFzPFsA91q04r7C1Ja9MkddyU+/3G+NikWd+HoSRNY2JrrAu0BKay+hs4DcdV5uekudEDMQNsOhhVhtoPUURYE+9Ks7qglC9kx4qC4WyqPRUsOwhJME+w4hNIF/4I63RYYan5EbnwSlXChzH96A9FRQvzry9zLR1qiwRi5BFysKO+BlER7MFWMnCy0YNVhgy27onD9h7vUfGPAKU0ybTab/QKWXq4GwPejZ0WX+3n+l+Fp7iw2aNntZg3bO7PlJYejgUpYtA88wOBqAJhpqxUqmQ5tL07XAdnzyS5Q1umxJzuwqg2g+Ww1yGN6yhZkw2pdPp0sI2LQ2myKxp2CzJq8GCaJewuMyyY2MLgfmJRgl8htC2JabdNKQhbmER9sLtZxeFVXRdaKvMF2JaBkRnYhJF6d087rFkftSPUkBqQ7CaypFWlNpaDSuohL1A1qmQIjWWYGUgM4AQ3e7YkxePPRvYupKWbtX3CSecq3Mnr1xnL5qqrAc0SyEIFC41iiArxKo7dAqJ5ZEJjA7nYJGz2RUgQxtPC/LYL/iG59tVaddsOJ8dsipqrDFCobvekpfcg9tASwMpGpgLBNICVKv1m4rchdfU3t2mxQey92bLJLmEe6ckBjVAdv0C9VKTE+R5g26pEOjAPFGDuIRIUNIs37dxfin4bWQL9l5zSrxqWAJs7BWiIYxhHIJMWp2XUGcCEuhxCxrIJXJ2BjTAgA1drmFNR7fBBbPrMKDyIdHrNozAjrdc+2JYZqj5tEctxDMX9ApgAiE6SQTZcgtumtYh26erTmQuRAYEbbkZtB5faZskE6QNIOmUlWNwblvLAii9siH8YrsXj8qYY8uLvurviHDsB5oIhRnaXerd4KPeelcnhygOCBo5zk+MbTv0vgq1JcmxCHZYR9SJPG9V8dTqiUBLkJUXStzKA7pa8MfgqIBVG7TVImxhsGEKP5xdeLXR1t50p0LnFM4xrh1TTney1MoAMVstNTkZ8Q4Y0plgS66OGMQ3AdQet2W2SMVDcYC2K0IwgRUUQFsDDbpQmMo5ESGaMdWSOL7p0nKmTEE1tWfozMThWXc+ia1AsR5EynJ3iAENBKyJMXXGOJQ/taF8ipNA2FuAWaOrSBm67XmxCqGhv5z3sbZY4SnUBA1etHTbTAdjlc8vdWPrWXneg1bkGrk8+5s6wZRA2W/rhO/Ueo+H+yAL3e1pTvFBQJdsxIZeHu8FeVykoX2UMu2a31KWKadruiClNKRZglxXPru/rA6hELNbRsA6sDjkECFvKnFKRhETVogyrctiH9R1NmsCdsvCsw0OWoRxtZgc17eNswV8jBZjbbDl3lKWUdvrwsxFILdxRUxAKS5s2kt43CRxYuAczzUyVBChLKrHuZvIQznf2dBgWjnf8hbsb7NpMe7mpGh0g27HPQQU2DhBae1tpwU5fWaOM8neeB4eiMlOTOYnB74s97sDoDzbshTq6MDbhGhbAPPdtjsVuSEvcC43HLM/hDmcuUsF70G/MPuGZxROBesFs3cJY5dtZlq6wYPKIO3az/Z7eOlP+62iCYNnelzHzc6S72wbBd/O4q1uhs6gXLYIGREnecXNNKnK9451QNkUSlcbYw3rUxpsCoYqKI8/8iALKQxxTw0QM7v1LAZf64HRLvsk0oeppSjwUUFbgVbdbX4BbdS1LsExdSidOhwNGfOi7gt4voRWR2YNnRsDo+fyyZeKoDoVjYVcphQ622pJKzTcbIo3GRMWmLmWQi3u+j2hyUKzN6FTRfRIBDiRZUSJ6cVFV4u1Je6JulOojju4DUJoSd5a7b7kgngB6s5eGKeeFwC+yfUFSWx5yS3W2y1SBn6f+wOz91Vqvodn0GlZwStc07b7jQnFXTZd+ozZw/WO0VKN6YW1T+ADRYNhn8/QdR4DriLK1YmgQnFHMJttXAjcfhvrvIyYtiRDzXRr49QaNVqcjuSBMFkrHlYUEtKyNat6d+kdl0Pjz3s3aVTpuKguq43fLYfcPg3HWXBZO1R2Xq4EQqOMWetDwjRG/CYFpqHtHPu8yp3DOUYHyQ1BtCaxYCmL2DnkF+26LTUyXTGYdsJxwmBqMiWlemjObtHKcK/GbuhgeEdIC56UTwilQKe4WFC07KaLbDwtFKJVE+QqDEPQzGvOZt74jXA4cIYJz2gTrDfBOdtWtKdszi3m7lIjicMS0Za4dqAJDScOPs75BZL5oNujkr/HvHDdEjuB9ly15JR8RTaWUVMIZGeBSWQMBKyOq/e5YRoKCVvnlJFjmiOOyjZaNiStQ30fQMGULtAKWsLYBYHzwIL8RsgiGgk8GJwBHxblxsLgbraHcYU0LyxGssOy2hwsEh0kuWtwO1vRXgoiwBHnlmBwYsGEobIndxu6m7YBzzCrmK4IZmNgQQg0mRVaTIVOglRGWOaK5t5ymCpE4Gk4tfwVvK3QeR3u5mVsehpYA322pQ5aT0hjrtIyJMAe1fdk6h3WcQeQBa2zVFjutfWJEU3SyKUSB7hkzFMa2wip1JBi75kMr6DYTgFEZDbdzpoDXu74qQfvi7LtaQFWuZBt15i8XvWG0WvIYVtNSW/mVIaHDYtdzgBKOa+x7cwPajhg+Q1KUUF5GfZoChqE6EKS1DJZAzy1SOZtb/QgtiMvc8wZIoPpcjNjYUNdXOYHDbQGHq93OF/l9dEic2WmrdVphKj79Wo6XcXz4ixiXUNoYGABcSowu7R20j7UtqyZrEJmgRLWhW6NIUAavMvIKeoUBWzKqjakIl0yCEJ7JaHkOhX6Tcqw9jADQVQQ4ehK43EOmHDBkvtCnjptFBOnZkdbfr48ivrcwpXLrrWWBVUVQYIwgNpJLm2hJ26Qtj4UZMNiumwHnkmZ0hG7bFr0xBoFDsVih31cnGjUWqz0Q7+eu/CBOLIh0bAVi2SVFyVQOdd4pOZMh5maJ8Rc8bowK9zNZUq5WoChgDOMTpXZYt91EgaU2FnSFsnsWXqYrUqR3Rp+sTugioZghEagzMU+63QazsZ7VhzJ9U0cKgSG4Mbniyi32+1aBDWSjvlIlp59XGTpllDyfHz2NnrqnM5CvkbG61jC2f4sqw6kawRyvdvlWAqmoZ+ESijH3BvIDoPO86mpX0SZZgBlmnZ8EfUd4Z0VAHICXQzctKFz8pobMAcLMpGnZ93QDpGggTVRq47jb5E0PI7PDMFZziVNgOEYGi+C9aXqVsYghplpjs9KnhvrnXk6kUvdp2CABy5jNH2/OELXu3johDFOeq2lJPnp2xVA3dfYzbPv3u3Djpf7EKfHu31a7Lw1b93tQ4jJt7t9ZuZURxGgET6wU4dv52AJ1uegE9Nex3rzYPt7qZT3EVVYZ2KhmwQhoifKWCz2y+FCbQ7GeqgNdJWuBctcQj13CRX/EuVFF5141GRCHtjkNGR7N24j4iTtwEHoJZJmtcoiyowvee1PfK8lF0fFTo+xummaYtHBENwswVRQ8cUqGOYDpKrwzMC8wO5Rdl2EqH/i+m6nbO2kyHF1Fkhzrwhm1aLLCc2SWugwpeBqiy/n2nzhzhxmk5MgY9e7aIMJ/VHhhkZs61V7cgntoMcnlkRye5NYNhtapOki1tTgzHV/ZnWzxOwUdxF0t9pvDdERdGEzpWnWMjdiHwHZYwRTM+0oZLhFdElrmlT0PDzoCurT07MktivXpJiNvqWJ1NLD7Owa1oER4dksUFiHO24M+YzFgNmc7eSiw4oMHSCS9Bhwkpeiw4cnyJFpIdf6cyiojK4LeW7pfNadLnuF1PUjarO2KOJWOui2bPaRkOXdSVrt9yvhVMOzdOZXdtEc1Q1hjLcGDHKPNkEcLJf2jLY7i/KDWXhcZI3iss4+IPiESouLy06Pl/a8UiAxtDdLFdHyrGOPC5HOe6oRG3abLMhQXG6EYxSnXrY7d6d1JFy2nlFDU/FgLJZ7cbk6uss9EeejmzN3nMBO5QMG26lhWojoxESeKNLqEkP7OrOrEFlHC7ATe4sEmQjyYon18+msM2zciRricikrf61zU1afhqvtzoWdaMUSJNvHlwLHBnShVpfKkbHx4kjIQDTQ5uRuNl07+2I/a6n0qNiHy2KHS312ufS4wHCgt4T1Yofi4bw9DyYpRC3vl1g3J6okTXPaoGNwJhXHo7s8VPB8ETeqOxXIE80SWigg2WbGHs5azxE5oOeKs+byjohMnqE1naNyIM+zRNFnO2xqK3EAE2eSYhZahAV9mBvCsFn2UWvpy7PEno3LaolceFDhC3K3ODvs0qiWyJzVcoZUdJJgGjTK/dyPBLjGkHJRWLi+FWMh3izkc8FRgBHXBMUTWkZpWbG4lGFumlR4WaSdTDAbjCQRFMJObeeaEbtUSNLMtEQIeWkzENFJJIC+OUo9JuVNuc1jzfOaZmrSoYvbfe0ucG+m1mzbotSwwS+WAKTUxuqpnjnk8QDrCTEXrP2FZ8CpYrHD5QwZONLUtm7koUimlLJYRixxZvjNZtOehJM1BSdKv1haTJYicK1LHFA7CeS5RSoabqEaxbKlaASbmF/rs82uapaD6jOX2QLjKalf7uDaznCRptZTO0BcBKbpRKDxrYzvTutW1/t1vpe2sRsboXghvFp36c0lELZewEbhhVf2+zISVIKQ2BPTrZwdm4dbLV/561DDvBqHA9Hrl2vdytMoPvOq48uBKWrmUXTmzU73JTeAeUActG56WtO5PPUMC5Mx+1wyoUYT7GFYgHh3lPQ08rv5hqVIDRNandyp/CxyddAWerzh7RyFp5HrgHDWAd5lch0/w7hBQYtcPQTTYNMErTYzcrvGL910Bpchz2rcZvSWiROng6LrhJhnNY8nG45O+dAmkFDEXf0XvmfclGiXDq2p6/P5lp16slTGBqx1FWzotfH6AlMVaCb9+l7N8S7fr2NCQnajmNcbgx/uSx3vtDsXeRqXr64yf3z1abw9cwRh5e9edP4IJftl6YS+Wqfnl+BtnP0lffj0l3Odnj99/ka6iN1o8vuElb+Qhe9U/tqp4sZXi7zr7z7JZVD5Xlx98ZLkRRmdkz8sokdJ65zjbyV07glM9qso9+4+6dzTc6pXhe+k37gPvfj8IWLWi89JXb5gZQR/g3sEIuLxpjjdrzZ+mSf1eFn7tcAH4A9vHgoxRf6Sp58tMWZD+XEB7uHaw7HEQ9nvFaHi8pyX/vWWw+/CFU57Bdr4bsV/D5Ip/O9iknLHu2L6uUZg/YcrGNnCOUexW5J5Vvld9TNFuLyIhzyrnOTneuipnBp3fsLkRer8FJmtX1Sx+7NEdL/is8ovznnijLBy7n23uXS/0tM8r6I4C38Em9SlXjlFVX+3y0eoqK68vM0eB/j//B9BnbkjNxOdBBJ91zjJ/cQ7x5//5//49//5PyaTyWQUm8Bxq7yY/D5pnGQCT1bjncXjt8Kv6iKb3HnnePIvj1Aj4j9e4C2rIs7CrxuWuCtfYy38avL7ZPyA3E/G/z8/oq2K/uHHI/BTgRG8/FKek7i6+3T/6Qn8kZNHXGenKH0+q+6qf0P+9vl+8uJ5+uYZ/dvnJxx/PPxxncqNJnfD51f0/3hd28Kv3lZyJFzcT8L7yeG5jt/gJ/8xuQvHS2nxz+PPw/hzuvj8FsnYa19vYoqDEcH/+n2S1Uky+d//e3J4evj8rqGeqB7eUC1eUH1RKT8p/ZuN/XXs77ti8r8nSMcwL9v6+jUcv94Vk3/91xH/B0CHZ6Dp4hbUE7Njrb8e7idfw/vJ1+Ilj3+8GqQPd/LetfcTt7ufuO3rAeVMfp+47QS+GsWnlyMPL989kZSdKvoSJHle3LndBJrcOZO/TA6f3/XKaM2+5pkR", 16000);
	memcpy_s(_windialog + 32000, 6360, "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", 6360);
	ILibDuktape_AddCompressedModuleEx(ctx, "win-dialog", _windialog, "2022-04-20T10:46:39.000-07:00");
	free(_windialog);

	// win-utils, provides helper functions for Windows. Refer to modules/win-utils.js
	duk_peval_string_noresult(ctx, "addCompressedModule('win-utils', Buffer.from('eJzVVt9v4kYQfrfk/2GUF+BKTEpeqkSoJQmnoFzhikmj6DhVG3uwt1nv+mbHgBXlf6/WNglp4NqnSl3JMrue+Wbmmx9L74PvXZq8JJmkDP2Tfh/GmlHBpaHckGBptO/9IgpODcEFlULDzKDv+d4nGaG2GEOhYyTgFGGYiyhFaL504XckK42GfnACbSdw1Hw66pz7XmkKyEQJ2jAUFoFTaWEpFQJuIswZpIbIZLmSQkcIa8lpZaXBCHzvvkEwDyykBgGRyUswy10xEOy8BQBImfOzXm+9Xgei8jQwlPRULWd7n8aXo0k4Ou4HJ07jViu0Fgi/FZIwhocSRJ4rGYkHhaDEGgyBSAgxBjbO2TVJljrpgjVLXgtC34ulZZIPBb/haeuatLArYDQIDUfDEMbhEVwMw3HY9b278fx6ejuHu+FsNpzMx6MQpjO4nE6uxvPxdBLC9CMMJ/dwM55cdQElp0iAm5yc94ZAOgYxDnwvRHxjfmlqd2yOkVzKCJTQSSEShMSskLTUCeRImbQuixaEjn1PyUxyVRf2fUSB733oOfJ6PffAWurjgqWykJNZyRgtpKhyJFgWOqpBnBd3UsdmbeGzErw0lNkaYSUICBMYbLPQbjlEwsSxVrZcFfneFspZq4y1O773VKfc1VTwx/ThT4x4fAUDaL241DrfEWFhHy8EwaA+c+vp9adbzp+3e5hXBftqXSlA7aqjF0tbVUnFbmkZM3AWHgSBKNikMsYXRaEkl9+35XSuZYxnr9a2R222Mu7CSqgCO2+1/haAW47Q2GSuWXY4LSzSscU6y61OkCBfVUIVeOd8P47T+geUW4ukRYbfxXnEsoJJgqIRnxuneINl+6nx9qx5dyurZ7Xt532IctmuuBgMdKFU573AHlaadP5WIJVVyi4LItQMIQvG/fJVaa4axytN56/bXN+M7gMXgO1Wsf0ArcUinH6c3w1no8XiVxmRcQNisWiqfrFo7DXjcrEYbXJlCGmxCLmIHmcYsT1tdaEVIrsJY1v7QneLkAvS0KbVl5++wmAAp/skn98fobJ7Ij1MVohcV7ejqAtSs6n22978f7FWs1V3EQwGA2AqEH6GUziD/kGqk+COJON/GkIXaFWPvQOJGWsw5MbydrpHqdAJWndHsXhEwOUSI+7CGiErLAOhZUF1NrGxDzZFpYLDScxlbHebPycTobXHmdAiQarb/3N9ONq0W1vgADd4MA1y2Xa4gUKdcOqq98c9DQyH67KhYHubVBPZDcpMsIyEUuVLsC+ByiW4/yGPTlTyYdgmwMAJVl5+Ofl6KI497QU7vVldOG/md+dfNOnO9vnc955dCfheZuJCYYCb3BC7jGhc79yD538BLT/byg==', 'base64'), '2022-08-03T14:24:19.000-07:00');");


	// win-deskutils, desktop utilities and idle time support. Refer to modules/win-deskutils.js
	duk_peval_string_noresult(ctx, "addCompressedModule('win-deskutils', Buffer.from('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', 'base64'));");

	// Windows Cert Store, refer to modules/win-certstore.js
	duk_peval_string_noresult(ctx, "addCompressedModule('win-certstore', Buffer.from('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', 'base64'));");

	// win-bcd is used to configure booting in Safe-Mode. refer to modules/win-bcd.js
	duk_peval_string_noresult(ctx, "addCompressedModule('win-bcd', Buffer.from('eJy9Vdtu4zYQfddXHPhhLe9qpTQbLFAv8uBc2jU2sRdx0mBRFAVNjSU2MqklR1HUIv9eUJadOBcgTYvqhdRwOHPmzIXJ2+DQlI1VWc7Y3fnhR4w1U4FDY0tjBSujg+BESdKOUlQ6JQvOCaNSyJzQnUT4haxTRmM33kHoFXrdUW/wKWhMhaVooA2jcgTOlcNCFQS6kVQylIY0y7JQQktCrThvnXQm4uBbZ8DMWSgNAWnKBmZxXwuCgwAAcuZymCR1XceiRRkbmyXFSsslJ+PD48ns+P1uvBMEF7og52Dpe6UspZg3EGVZKCnmBaEQNYyFyCxRCjYeZ20VK51FcGbBtbAUpMqxVfOKtwhao1IO9xWMhtDojWYYz3o4GM3Gsyi4HJ9/nl6c43J0djaanI+PZ5ie4XA6ORqfj6eTGaY/YTT5hi/jyVEEUpyTBd2U1mM3FspTR2kczIi2nC/MCowrSaqFkiiEziqRETJzTVYrnaEku1TOJ89B6DQo1FJxm3j3OJw4eJsEQZIEi0pLrwNLf5DkS6UPZDotaVUyoVnvBsFfbVI4t6aGphrH1hob9i+VTk3t0Mc7bLTxDv2OMZ+ANh/euyhLa64pha00qyW9z41jSKPZCskxLtwqbi1YXRNOyeUnakGykQV9No4vUax/UQrOW2LWCBwLJshc6Ixc3B98Cm6Du/gy4i/UuHAdiCWu7HNh9w8Oj/C9Itt0ZpIkSBKctXdcC/FaFBVBOGekEr4iNtXeJYlSXFGzxfEKQ3hFzQMUoe+keAPx1ytqfnuA323uRivfLw9kWa3q4CElKRXE9DSiV5gj7XM9Ews6NSnNyF4rSaFbrROxfCFib+DAGEZ3E5Yy33hP+lTuv/d3P+93XK0q+f+NzpJjYTlMqRAvTJDLK05NrVGxKhQ3oBuS1T3jaoGwG5Nh//efSZNV8lRYl4uiP4i/GqWZ7Ez9Sdjfxx7evMFG3bj+IBZW5uHAH/ZvPu7117CSpFvwYRdzxRAZafaN3k4no/Fxr5XXq3aNUBNS074ldFMaR/DFtY7dRZiTFP6VmcuUUsVIDblWvTb2CgtrlhBrZ6U1sh2iD93cx7Y0aVVQ7L1ZdthvhSv0/nuyfodPi6PNracLY/iMPFrndLjeRI9rePhY1Lq79QmkwlFH+ZPxbMfkv26sDNebqJslw26N7gbB8G4bvZKP13CSdXiyDs+/4Kjjqd1P575F4pQWStNX618nbsJt1iL05sawN9OLnidwuClMhIOtw23VfzAATNma20yb+yZu72Jpu/ZvCBJIPw==', 'base64'));");

	// win-dispatcher a helper to run JavaScript as a particular user. Refer to modules/win-dispatcher.js
	duk_peval_string_noresult(ctx, "addCompressedModule('win-dispatcher', Buffer.from('eJxlUU1P20AQve+veMqFgIKTuqeCekhDqlpFiRSHIo6b9cQeabOz3V1joor/jmxCC+pppXlv533M9EItxB8D101CPvv05TKf5TkKl8hiIcFL0InFKXXLhlykCq2rKCA1hLnXpiGckAl+UYgsDnk2w7gnjE7Q6PxaHaXFQR/hJKGNhNRwxJ4tgZ4M+QR2MHLwlrUzhI5TM4icVmTq4bRAdkmzg4YRf4Ts37Ogk1IA0KTkr6bTrusyPbjMJNRT+8qK09tisVyVy8s8myl15yzFiEC/Ww5UYXeE9t6y0TtLsLqDBOg6EFVI0vvsAid29QRR9qnTgVTFMQXetelDQW+uOOI9QRy0w2heoihH+DYvi3Ki7ovtj/XdFvfzzWa+2hbLEusNFuvVTbEt1qsS6++Yrx7ws1jdTECcGgqgJx967xLAfXVUZaok+iC+l1cz0ZPhPRtY7epW14RaHik4djU8hQPH/ngR2lXK8oHTcPj4f5xMXUyV2rfO9IQ+WV9UNT7Hn6H71ATpMD67Z1dJN0T3Opneb0PWU4DVrTPNqZbhM1qX2Pa1aO+DPFKF0LrK2s85jLgUtEl9Wgn9wzHF7Oz8Wj0rdZCqtZS9YhFfTybeRK/+SkyGuRHnyKR/Y/V8rV4AleAGhg==', 'base64'), '2022-08-21T19:27:42.000-07:00');");

	// win-firewall is a helper to Modify Windows Firewall Filters. Refer to modules/win-firewall.js
	duk_peval_string_noresult(ctx, "addCompressedModule('win-firewall', Buffer.from('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', 'base64'), '2022-04-24T22:30:10.000-07:00');");

	// win-systray is a helper to add a system tray icon with context menu. Refer to modules/win-systray.js
	duk_peval_string_noresult(ctx, "addCompressedModule('win-systray', Buffer.from('eJx1k0Fv2kAQhe/7K55yMaTUIHILQhUlqWo1AikmiXKqFnuwN1p2t7NrjBXx3ysbaBJFvc6M3rz53u7wUsyta1gVZcB4NB4hMYE05padZRmUNULcqYyMpxyVyYkRSsLMyawknDoDPBJ7ZQ3G8Qi9duDi1LroT0RjK2xlA2MDKk8IpfLYKE2gfUYuQBlkduu0kiYj1CqU3ZKTRCyeTwJ2HaQykMisa2A376cggxAAUIbgrofDuq5j2bmMLRdDfZzyw7tkfrtIb7+O45EQD0aT92D6UymmHOsG0jmtMrnWBC1rWIYsmChHsK3PmlVQphjA202oJZPIlQ+s1lX4AOjsSnm8H7AG0uBiliJJL/B9libpQDwlq5/LhxWeZvf3s8UquU2xvMd8ubhJVslykWL5A7PFM34li5sBSIWSGLR33Hq3DNWiozwWKdGH5Rt7NOMdZWqjMmhpikoWhMLuiI0yBRzxVvk2PA9pcqHVVoUueP/5nFhcDoXYSYZju1WeMD3D60WnUtSfCLGpTNZqIGOSgW6Ub4nmK5ZNklnT64vXLqxWiik8So0pDNVn3d4/gR6TH4DppY/X7uXEv5l8t9dP/hVeusLLBIf+pBM+inatXvSkTG5rD9/4wLJBSdoRn7LpjKEyQek2G+kc2x3lMDKoHbV8uTK51ldjZNYEllnoiNOWzBEUaK988HH0trviznnroT8RByG2Nq80xbR3lkNr/3j/Ec8Zy3V7fkbex07LsLG8xXSKqFbmahzh239g4hpvtI6U2NbofdL6gqj7g75yrQvKo/4EB3GYiL8ZGV7u', 'base64'));");

	// win-com is a helper to add COM support. Refer to modules/win-com.js
	duk_peval_string_noresult(ctx, "addCompressedModule('win-com', Buffer.from('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', 'base64'), '2022-04-13T12:34:25.000-07:00');");

	// win-wmi is a helper to add wmi support using win-com. Refer to modules/win-wmi.js
	duk_peval_string_noresult(ctx, "addCompressedModule('win-wmi', Buffer.from('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', 'base64'), '2022-04-14T07:23:25.000+01:00');");

	// Simple COM BASED Task Scheduler for Windows. Refer to modules/win-tasks.js
	duk_peval_string_noresult(ctx, "addCompressedModule('win-tasks', Buffer.from('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', 'base64'), '2022-03-28T11:39:32.000-07:00');");

	// monitor-border is used to show a rectangle during KVM connections. Refer to modules/monitor-border.js
	duk_peval_string_noresult(ctx, "addCompressedModule('monitor-border', Buffer.from('eJzlXHtz2zYS/7ua0XfYy8xVVC1TDz/Ss6PpOH5Fc4ndsZxHp9PxwORSQkMBKghZ9rW+z34DghJJkZRIS1bknpNxRGCxu9j97YJYQKn/UC4d8+GDoL2+hFaj+eN2q9FqQIdJdOGYiyEXRFLOyqVy6T21kHlow4jZKED2EY6GxOojBD01+ITCo5xBy2yAoQheBV2vqofl0gMfwYA8AOMSRh6C7FMPHOoi4L2FQwmUgcUHQ5cSZiGMqez7UgIeZrn0S8CB30pCGRCw+PABuBMlAyKVtgAAfSmHB/X6eDw2ia+pyUWv7mo6r/6+c3x60T3dbpkNNeIjc9HzQOAfIyrQhtsHIMOhSy1y6yK4ZAxcAOkJRBskV8qOBZWU9WrgcUeOicByyaaeFPR2JGN2mqhGPYgScAaEwaujLnS6r+DtUbfTrZVLnzvX7y4/XsPno6uro4vrzmkXLq/g+PLipHPdubzowuUZHF38Av/uXJzUAKnsowC8HwqlPRdAlQXRNsulLmJMvMO1Ot4QLepQC1zCeiPSQ+jxOxSMsh4MUQyop7zoAWF2ueTSAZU+CLzkjMxy6Ye6Mt4dEaCM1obG/dnZoW54QNfl46Bt2nr+5Z4Lv3H/EOr17zxhwZfLK7A9OSGwXCSapBEMOr0fcm8k8APxvkIbjCa8eQPNPQWrcskZMUspCGPKbD72bgacUcnFLRc2CqNaLv2pAaEQZ95c3v6OluycQBsqAeU2ZQ6vHGoqJU89Q3sCBiNOV40Q9gZRsptzZCio9YEIr0/cGOXIQ7HTgjb0BuaxQCLxgkh6hz8Lfv9gVHS3abvhKP1biTQD+R604dffgu5ghOb1AWWf20blHOXJ8ZRDKskVukg8XER2Rl33Ci05n6rD7ohLbSJxShsxjk3nzNjvjU1Yt8QF6Kcud6n9Voy8/owIgbpZSYmMDukNgXbUDRqUC8ZoolDS1MF4h0x6lap5qj6cDqiUKEyLuK6hwDUR5AONM6Py30oNpvA0qvCn7upKPjSqh/AYipi2Qzscoek0QYDhKSQE2ipPizviQhvYyHWnvCZztQUZK7dEXfCJCKoymtHcn2g7S/525Dio4m/SYEqu24xqTIZKKIYfLiodxoBaDakiiqufeh2u+TDeFpdsqsSKHSZ3Wu9PjRjbX+lvpouOrEEjqn1hHpIPa7C7FAulBmxBskOvptuQOqJagx+XEnvLpeSDNPb+nJqtWe5B2MYD1WjUpmJnbPmoPz7OAJMIGUcmETILmj2UHeZwo2rKPjIjDIABZ9nAyInY+KDZ7Djg7DCFwragPbGEnyKNBH58Ok8SiWrlSRcUjzlPTVM/ReZYjY+bmWRCkhF52oJmFf4JPyaEz5pnQYTODnW4WBymcxSGFYXok3ilh+qT1XpCyNZbKUGbR4G9tHic/ARonCyzRoDTaFxGsdFuQwP++gviTbtV+Cm2pB1MV8RvaTGoQ2sD/e8rvRm+bCZ9uTffl2k54WkWgG3Y+5t5J02vVNzOXT79SF+ll1tJL+8/c8Q+h4efYEmdATYQGFrt1bp5J+nm12sI5g1IzlMQ7P3fOHs36ezGGlbhzfXYUjDcXD/vJf3cXFNQ/31Sd4CNvU129H7S0a0XFNCr3x+tzFvL4G+VHn6d9PBOMQ8/xpsea7C7F6+aTB4ey6XvwpKJvx1/jBWpXcpG95klarVN99B1oO0XXqL1RJt6Q5c8xGrA+SramipXTTsg9T4yKh8CJfRQM2iM1AAtzjzuounynlEJx1RgK85nYwupWktJB8hHMqyiTrqpY/wjPpHM4tW0xNJuHAKFN3GXmS6ynuwfwtYWzVEfcozYaBUY58dN+P57SLQLzuVn/9gjfylH4Svw6c2XZtP80kV5FljK8DujEoLPNUj0nB83a5PTmqxgTcg6EWT8njIsIiicZJYWDf9vcqB+mcxMtGvSLlOv7K5Eu86Z397MGYq9wJlkYCZUL13BSEbUCp656sgoEZnB5zyrSVrxHQqX3iOKPa0AHzNFai09mvAHnAVpDbagApNxldkJh8VnVVYH+iYcmDMfxpaZz9SW/QN/jRlwFm4ztqBSg3eoPsd6s9E2GT7Fil/Sn0Hf1bTXCOinqAuePUsgso6djhjqgBEwTSwhc6YM+qDsMwIRCCM1UF0zgDFCn9yhuoDgkK/6eF+/Q3j6woR+8G8yBKfh6cyVR8Z96h9BJCb9WXX8TO/RXThp8xNxM0Ml7ahvxvpayRu9XCcUCQ5m1ZUGnO+FaMTrwI6io+aXw2p6xsE/WQkooZjZs7J1Oz/O0ihkoDXKnfC6KFW+O5LBRRFvsQSzZ9WgqefdrEGziKzu6FYz+sBtzCsqh4ARO0FL3R9a4LmQdQ6mHgZe7tL/4DvKZA7jZAAiO8PX63CliPLgQyeflUE3ltK2A9Tu1eLJ7IlQ9pkuB+bwveX54DxRcy2AjghbPaR95s8B6sANucAyF+bv0cmFcr8wsOL8vCJUK9WWA3VQjHlOTAdKrgXSoazVI9ov3D4DoEMXFATwW58kD06CmtMqQRxTUwfgal46NMflUB0JqufD9VTRtSA7Km312M69LS2M7ogrFkMmG+4J830gwxW+WhXjmXdtK8Y1Z34pxnRRGom79sgdkwfvkl3zYYEXtkKW7lM7gGTH4uy5pCw7l7weXnY2Bd6SlppPTmwtO538S+RSs8mdrZadT4HoiZbD4nIWLHu6aNGN3L2cJXxMNqHrYZFaSsdR1RMikFXkpKKiqmOq1SIMfh950j9CmquqqsM/YVGeff0tbJAClXwusCf4iNlZyoQ16SWKPtVDv0ClBq365cLX7znfJ7SAYpXZhED/4GoGCyl3lv+VOMfUA8JDJw/ltX6IVwrhJ03qY/VGIfOtDws40O0Bh3eE2S6KGrSyTyQj5eT4qEhdOaWiHLnfr2u38CZeJI7VceeWk5OoTtbzo/2ZV6HTaooLwqDokdZ8zSYXcRcR+VdzG/eO4ziNBhz4HxuNRiL0N+CELONG2LrN2sxj1r3NMutcgy44kUwAO6XquG4ftPL4YP8l+OApx6vKb986CnbyeOD1y/DAHDM/6cA4ETFp9Z91O2wvj8Oam+Ww4gf5GT5L34es2wW7eVzQ2CwXPMHMq4mZZNF/3e56ncddO5vlrkUXRjZh6djPY9fWxtl17iqx6IrOAqV1NSJL45TvvcIz7tB2QytHb/gkhkcu+8z2Lb1Ly3f754Vs12auJbzAjVv0msKi6X3TLVxRU2/eZq6IqZfZ1i2Zj9a7K0zcg3iBO8T4rYjFU/y2S3lxi2/ejvAJFl9ikV91QD3vpjF5WP0Cd5AzJ9c5JrkJi1MRm2/elrG4zTdplXrOXeXszaYXuMGMXXRaOMGNWKHym3vz9p2Fzf3tlqfJ0LXvP1O/puiNqbT6xlBwCz3PHLpEOlwMwi8oWsRDqIwp22lVDkKVB9weuWji/ZALqb48wnCc9f/xRSZ9K5B8PYxy9r8euZBz6pcoM/ja6JCRKw+SvY+6gBD++R8rC28U', 'base64'), '2026-02-14T15:39:57.000+01:00');");

#endif

#ifdef _POSIX
	// Helper to locate installed libraries and binaries. 
	duk_peval_string_noresult(ctx, "addCompressedModule('lib-finder', Buffer.from('eJztVl1v2zYUfbYA/YdboSil1pGTvDWGN7hpihkLHCBOGxS2MdASZRORSY2k7BhJ/vsuJUaxnWQY1u5tfrCsy/txeM/hpTvvfe9UFhvF5wsDx4dHH2EgDMvhVKpCKmq4FL7ne+c8YUKzFEqRMgVmwaBf0AQfbqUN35jS6A3H8SGE1iFwS0HU9b2NLGFJNyCkgVIzzMA1ZDxnwG4TVhjgAhK5LHJORcJgzc2iquJyxL733WWQM0PRmaJ7gW/ZthtQY9ECfhbGFCedznq9jmmFNJZq3slrP905H5yeDUdnB4jWRnwVOdMaFPuz5Aq3OdsALRBMQmcIMadrkAroXDFcM9KCXStuuJi3QcvMrKlivpdybRSflWanT4/QcL/bDtgpKiDoj2AwCuBTfzQYtX3venD128XXK7juX172h1eDsxFcXMLpxfDz4GpwMcS3L9AffoffB8PPbWDYJazCbgtl0SNEbjvIUmzXiLGd8pms4eiCJTzjCW5KzEs6ZzCXK6YE7gUKppZcWxY1gkt9L+dLbioR6Oc7wiLvO7Z5WSkS64N8ijQUdMki37vzvZZGGpNFWCiZIL64yKlBGEtcbdnlVkIRGMmwqzOdkhNraq2oQhoM9GA87TaWZMHzFG2OoJBUhj9cZhLF7JYlX1BOIenMuOjoBWnDmOBjGtVZqoBYm1SWBh8KkxHywpIUIUmpoRjf7CtMIrirJFtFfuhBEhs5Qi7FPIy68LBfg4vY6oOFQXEzR7VkEgL4ALY1+AjgHjANmUwEsd/3BA10fQMEq9CeRgpN+PawDaYNk2C0oFaR53ymAfe74ilLTyZ4qIBnIe31ji22OsaMj6dtyPnMxtU+BWI01jQ+miJQeCBN8XviILjidzahK37UxlZrmybWEhP9cmSr1MneHtWJJoLdcjMRwc7u15SbM7SHUXeLT43t3mcgxv4twyiuS2I64kJQI6EN4/acYWxUWSvFtFqI8Q3axnyKOagy+hoPQeg6SxAtiSzURAo8niVDqHWcTbhCFHfW9QTqFA91wdaPy+vv9PXzBPaCwkijsIMcBdSIzNKK86qobKt4y2rJnpAtpSHZRt60Ieg4VeHbmE57vWA3NnimgUkjArKLcF8FrVWcy6SaJK8rwbni6Y+LUi/ClbPUDKK5VCLEhzPPFKM39qcd9/UoyZHy22qQgPvUURA2zC6l4EaqA9syJHbODJ6sAb7UgyvqbgU3FRDBw86kW1D9iQuqNiHKoZ52NoBn8GzawZveIzB49w5eXH4cgbbBj4gzmmsWVfq1qX/CFKz69IpMn639a5nuZHoahGu8qRjegXYOIjY3Bt3gcaI63p8qT7l2BPXYj/qeeEVNVWN3toa+osxzZ3pSRiWoh7177L+m1yL5n90fYjcI4NdX10+2uf5H9PveUqZlzrDP+NfX2CvLCqG7b4+bw48eze/nbk8qcpkax78AD6qD/w==', 'base64'), '2022-09-16T19:08:46.000-07:00');"); 
#endif

	// monitor-info: Refer to modules/monitor-info.js
	duk_peval_string_noresult(ctx, "addCompressedModule('monitor-info', Buffer.from('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', 'base64'), '2022-04-02T20:22:49.000-07:00');");

	// service-host. Refer to modules/service-host.js
	duk_peval_string_noresult(ctx, "addCompressedModule('service-host', Buffer.from('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', 'base64'));");


	// power-monitor, refer to modules/power-monitor.js for details
	duk_peval_string_noresult(ctx, "addCompressedModule('power-monitor', Buffer.from('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', 'base64'));");

	// service-manager, which on linux has a dependency on user-sessions and process-manager. Refer to /modules folder for human readable versions.
	duk_peval_string_noresult(ctx, "addCompressedModule('process-manager', Buffer.from('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', 'base64'));");

	// Helper functions for KVM
	duk_peval_string_noresult(ctx, "addCompressedModule('kvm-helper', Buffer.from('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', 'base64'), '2022-12-13T10:41:20.000-08:00');");

#if defined(_POSIX) && !defined(__APPLE__) && !defined(_FREEBSD)
	duk_peval_string_noresult(ctx, "addCompressedModule('linux-dbus', Buffer.from('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', 'base64'));");
	duk_peval_string_noresult(ctx, "addCompressedModule('linux-gnome-helpers', Buffer.from('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', 'base64'));");
	duk_peval_string_noresult(ctx, "addCompressedModule('linux-cpuflags', Buffer.from('eJytXHtz4kiS/3scMd+hjrhb4xnbGLAx3b2OCyEJW9s81JKM8TyCkKEAdQuJlYQf09v72S+zqgQl7JY0s+foaAMl/ZSV78xKXPvpQA3XL5G3WCakcVZ/R4wgoT5Rw2gdRm7ihcHBQc+b0iCmM7IJZjQiyZISZe1O4ZdYOSYjGsVwLWmcnpEqXlARS5WjDwcv4Yas3BcShAnZxBQAvJjMPZ8S+jyl64R4AZmGq7XvucGUkicvWbKHCIjTg3sBED4kLlzrwtVreDeXryJucnBA4GeZJOv3tdrT09Opy6g8DaNFzedXxbWeoeoDWz8BSg8ObgOfxjGJ6D83XgQbfHgh7hromLoPQJ3vPpEwIu4iorCWhEjnU+QlXrA4JnE4T57ciB7MvDiJvIdNkmFQShXsVL4AWOQGpKLYxLArpKPYhn18cGc4N8Nbh9wplqUMHEO3ydAi6nCgGY4xHMC7LlEG9+SjMdCOCQX2wEPo8zpC2oFAD1lHZ6cHNqWZh89DTky8plNv7k1hR8Fi4y4oWYSPNApgI2RNo5UXo/BiIG124HsrL2GCj19v5/Tgp9qPBz8ePLoRma43kzl1k01EyRX5+u0DLtR+4gp0MqNzL4ANq+YtEVfFx/jO0IhPH0HFzp7P+E+dVHVtfHRMnsJoRs4IPkICPx23W5Ourji3lj7pmrc//PDDFamSs5+ajZ/J2dEHAs8cBg+hCzfDcu7to76eub3Obx95UbJxfdIPZ5Tozwlsle0/D0rLIjU4kkYfNosF8rUkjGlncZocx0Qh2d4fpclxbDWDc85xHG8FOIm7WoNJb0AyUS5K37YyKBccBfnin9ipFll0ASoNFp+/MyW7s5bY2fIlBvvyiTKbMQUuucG+moW7FKSBhYOiEXVJp18AC/0JOqI8KHXczkC1OZTaN8fqzXUbzBwMdjMtxFFMQ5Vx3mWVEZdz77d1U6ajLrTRvrf1gaNbNXwxNpx8tjiWJWMIPezTVRi9EOdlTYkFRk/LCu06w+W6rI7XfvgActMD5hzzZaVkUM7fkpUSwbuETpkDyRVXfziS0S5ScQ1HsqhiUl37m5h0cWE6PYYXw77Bown4haMCZXUyFLekfSuJcN/EKdw5mHOzJQMJNW22Th68hMByAf8HGTKEZppROAVTAW8e08gDGQSb1UOBKau9bu/WvpHRhH6KldJqrtkyTQ2hpZVZEle4vwMHExbIUFFNQwYRaoofk0fPJeB48jWqP84QIfSyv/ET8HAzQCjpRrpjW7aXhlBN+FgZ6bXu2LKdoQWByjo/Hdp4cS7auN/PkCVUsxJD4lN0Y0O+sbW7sZF/p633uvZgODSluy+3d1dYwI2pPydxEIbrXKibjM43hLLdgM+ITpxlRN0ZBrJ8sWaiTkNoWCVZVYiyScIVJBJTMvVDsPdpGCRR6OfiGUrrXMJrivBuKCetc7LeWkGuBXV0kv4AEKQTpNkgEFiF3po0YNvqwP6+yM6MJS9KXyuVurRF6iKSlnq+yO5tVen1+Mbqe64eV9DTW3qBo09jRV225b5JVMhyi9zSYCzf3BBs1Z/pFN2a5sXFLr0/1seODJKacF8jsAj5aGn7mwxNRwK6eMsESQhxfOX9ITLRPMjrjqlc67ZMW2pO69ma1hcPFXLdIWvw5flAlgZZlCnjCMPiC7n39voZDgvx9ELQNJZVVp/bLVDiY9I6Z5Eg3qyhwEryo1JTGwzvkO1b4NQikOuwGj6V5TuD2plFfd8sONjWDpzIDeIVTdyS1tBuSdbQyOeyrg5HunXPNtWQs3h8BJRYEZ1idfJCVsi4XKYPB9fW7eAHCaq+Y3y0Ccg6fII4Wcb19CzHkPxGY8ugHaAFgAmzFA8z6bk7lTzHkFVlOw71vGDzvOXeCspKVjYyBjW3lHTfTE9ZtMM9NTPsgTL9+Xu29hbQx5aUHjZl9qD6fGxBQQ4pABR9mK3ilflw6r1ljCdQo0p4DZk0BRGqVxzqKB8LMlzl1oJM0UJuN/e4rdIgcTcRgeW3EN+S38c0p2/K9U+lQoZrkFUYHEMet/TDAAJJLsxlBuZiC8Pvzg89zcy9re29ZjP/vvMMDy539+XTqg4HtqMMHCz+MggikuPHEH+/QGGfsKYJk3ZCIjfJt6tbM7MR4cxsCDZfaBSAyYNpseYBMOQ23y8qlpMhrZ46MP/JfYm3QJjFRaQKV+dLWbHUm4mpW93+cJDFFZrN21dSbQHZsgm22i+Snd6xpT2ndZQJzsiL6Yn+CBpJOi52wWwX+y0FmVHHsbP0Cc3ugGOdLtG/TmmJvFkkCM0GkPZDSttOt+OXGEppH72mocBzNlAfxOvUL+WAsgIzi3oho1LWKvhzsJZuTq6HQ00GFTYAS2TlTSGBQ5cOPhB08on6BR65qw9UEZUlyPaWTn4BkAscBQv3/oD4zq4uylknJoTVrONJEyr0jMp0ulltfBcbdiYLIH06XbqBF6/ys6yh2ZN0KE2znCUluATJaJfUu0fZojWX1N6dcp/Vo235VREmdIJtQFTOtBeXW3Y4Q3PYG17fSzJKEzmMvkm4Dv1w8UIoVJhlUwtgOMi+Zyidni7BNndOyIvJlyB8CrCH+kAhwPteccqKzm1ovvJtacWGn89CkDh2lWMgHLVVhVcgtnx6ee6SwbzYsWDpxiK7ketjL2E1VR4s5Gkaawntg7fSbBu4OaO8LwTXVNsEEsGCqAbqONHUfhbwcqeqKyyATwK0qnLlkcKcJ/6XxUw7DSc2MhC4EM2wuw1BAxIWL2BpOKgYnT24WMthzeH5XvICPhvBahwSyviCDUlindjNnbGkiW0q1uBwJ1W7ycVaqIUfIccdTLqW/imbVNR32Cherotz7PrTYPqyy+H+Uuta3bau86M1ZHVN7h3O06yOlSiBVyG2rZ8U5Ahqr3/b+6R9khDqDGG7Ur6h4+h2Wmefp2kcIInSpGxPp3+nGI6M0uQ7WoErhpsrBGK0AaVcjV2YVjwFrSY1daHnaRrHek3xZLr2sbnRO/nnxvW9uQcCqs49H8IUnR2Vpnm07SOdp/kdtjxSbX/kBwGi7MwPontILYZku3MMF2iPdFzKe+q2k8G5ZDh6sMSzMEg21mBzdkLzOzkOdpMkkDYDgcATrdixBhNIQV1mgxJmFPQd3xGIzacrTMj9EnoKnk2mpM61XIUCDKIJAQvKJUHrXMs3cwW3wdFA7ipknNtc6CuZh3O17m4wa2Oecu2/nLizWcHpQL0lg3CtFocD9VantJmNHdOSgbgu2xAEiOPGXyC39MIIXWgf3HZhc8KEMCCjcc3F1LbGGaOmPtkDpKJ+qsnktEPjWif6zDtxzUDsaGsFpwaamuU7Vz/Ng+Q5AbrwpBhyKkQucJDnk7qMwzUQm6KwwL3k+Wl+r42BNCSQxpkE0khB8k1h3Ngd7ZynTW8A4Z/nO8XhqKPLd3IdZB+X1hxzaKoDVjedbwM0V0OxUhYIg6KmK1rPGMAbo8+T3vM3cynqznw8neGlWG4OoduyuNPsCT4un9qyZp8MIrIk3gTkPcDa2Nadzqg2vsZf5bGH9iv0XU3NljIMpKwHPMNMA4+6h3b+5kcZv58mTsrskTvsEeg8+NqyxxH1VkbPRBVS58dFXROL9kc+W1HUu7SUgZaRbppSiaWyOnNzD6ncyLCHWV1JkyhrV/q7ZIlnBY9emnSyJGpkKDXWD6qJLk6phErNNtQvCpQHtEPI90LuQ1WiYFEh1uCapFVR9TnGpCA/KeV4E30gITZ3iBMacNBUU3KxVOvedGTa0j4Q1M8VYNsJsmEavayhGKo+sxcF1DHELHWXO0xGXRa2DJ2KqjdkKvf1WGVQi8hdL18gHVmga3jMd5sIiWRKqGlVDWU63FyGLvMmPYG+SBMIfhI76+Ep0o0bL1NyCmCypKQNIlgoR8f2aO8i0xASdEBOlSzCFbap+zyz8Aq8JgACRdsG88V+ZwjWM4QxY+pjQku3lSNUfHPfXcTvv3scBeWIMKFWfnNFuemyQwtBDmnJrWZcrdnwHzpFHw8xCnvxkCBNevq1ot5zrrXkfrMxJy+QlbCjxd3JIlbuj5Bt5wvCHqEgsmQKYdh0ih2P7fiOmC8oqNJ5bM8CNt+o0Ulxy0u12m9sWkRVWET2NRvMlxcyUOm83ufFnlEyIDfw1tidKqxQbP1c2UcUzohlQUp+JmPYSs+4Hti2Lm8unbvxYpDcAt06XFC8O3b+ZFp6V3fUGwmuLR8/gdOe02S6/DOhfnS3v8V0DMcGxYg97DPdhdEXNwo3Qb6mGdgCzoKl7seQguef6AKPh+YrRGESO6Mejcvv1/5oDLDozkKm5sAWa7ZzbZRHvNOcVyQKa7hzQRazcFEiJezdvd6oUN4emy29o+wXVBhQtBexDeq48300objnJAQf4gYzqHEUtfw2HTY+loUUqszOOoU98WJlm7wVtLI03dD4zNwOVGjfAAzCmBXWYc5ro087vEAW51QHjL4vGX3BRofmkJ3UZ0GFijjbBu8uP01DiTsvqEB1q6s61kTF3GuHnB7ZYaQC0czDaMXGeKdi3rBkFzlFH3QkbqYFyqDzn0B3zDcYIvRJcxOXPOAsyDr0IF+kpURvsnHLLOBlOl+yoxPt5iRm05fTEtOXKQt6PVXmgXCRPTdOSI8FfK6l/wFHWEduvJ2TwV20tkVhOlrCunY7flRFO29cE3fLtnckjdBsnkFvXUiMWKqSX7UYg+um1Ee8lJMQC5W/uddFLG3wTKsnXeW2l8HOHBNyzZ+7mMAVuCTV7EiGeilnIZiVMe2XRd8Jwzi/16m/gdhM552amEjr1vU9U4pJx1DsUg1UVXEmveY+bJqQ8E6M74dT7u0cOl0G3B/0Ctp6iNvYx70ogZtfMqia+Qa9rdSlQFIBrp4bqWiXpb3ZAoKNwQh7XBMbNKynSwogzFSfz6FQ98CaXoi4lvztb2zuD1/rV/ltppu7iWk7iqPLutXe6cPN3YlpF55ZmNZQhTe61lHUjxKQdBaJLbmuOHYxMlMn329M6/t6VZemhkTOLAaE9YCVjMX+zniFKSzpI58IYJOyfD7WiEMRTcvUWZbumEPsT0mcTBOaSoVc04BGbOY8gciF2f0KdGAhzqPCCBvk0wRb927k4XBD0fCReBqerEkPbG4fiDz6f3qYMXD03sQ0jYG8t3PZA+0me40ARwxQJoMSw71oNvvmuB2MzjWbfJIhX5nYpq5OIA71JKJ3syyY0WyvwJNd/PYJOx8oELRtd7R9ioUxIltZcvOYzkR0XtZuHJebTOwor3SznZmC7wAznrxZspR9VK6W2B3Y3ti+k+X2bsuCruf7BK7BHthUtMrjJw+S5YIevq2P9kltvDZNYZPYSyx/HHVrY/1idiSKpVEBI5jxZrwYPzEjOvPSaiaKsHVRxlb5Qyx70r3DHVxuU4advd7G4ADgEjLbRBhTI8hL8Dsocy9a8QNl1/cLuITaxTtynXtTse2JBqVop6dnnylOGytbJfmeFp3mVy72RO1eC+3c8e484xBwdafoXBo4ts5vLszykSH7cufnN/uCsSh+V2ya8JO/aZkyn0s9C956E/wNqefKwQHofeRLcSQXLIDjvJXzveeEBadGv2B/bg++nQqVzYLGvOPlrjyI0mfP9UtS/YUG+d3SXt3pQrzSIajL8nyXAuM6m0ASDQG4FJJK0WMvlCJkZTfKQNW1jC42z7KHtswAdg3xrBWLBh6bDyWiNS5adu38ys4E33yjaEPhltpysszDCVxC7KU7E6O83z0FH/SNHefbrxPjtKMG1+UX6j19bFrG0DKce4mmhozV9enz9qgzPyGWOxHtTELMkLbdOSnZyN2maWj7gOdvbVOKwvkH1KN+n0/yZ0DTwGti+yoi4iIcdhrxV7ktIn1gjvYBd+F2TAOydiNXTCaQxYYW1hXORNnfdxppv89Ilx3QnoAlg5iwz5jPh7fYsJvMu9mdC4mqJWZna4IfZY+iRv27lOX4mPb+sB48adRnUYV1DsHfpFezgykxGpl91l8b9Ll8f0aqemc76vMu3yzsa7ujpH3Td5miVuuypWNyZ6WvLO16+xl/lSlziw54Fe0ft7YjP0uad3JnnzdxglGLRamz52Ynv1fSN+o7ub6TjbAOircAp7l+3YYu2Xa46cmlyTvZILcjOOx0Rfe9QnesjMaNfbC0Xw5L5TsFXUim9bFqOoPJcNC7l/i4M0P8YvEM02nWJQIj36xnLv9CN4QmoPS5fSm+zV7cw+3r5j7haSK82dqN+C4yfkMHOQEuCueZi5gC4nvFFGGWDQh2/5n4dKtv74MLS9yGPpz07Q9HdqcGGZzdKS8FUYTv4e/67+ygCAvqnbMuOVVkOf19rUuLVyndYl1glxGKR0m8csitwT69hk1HaVlD5FNop6NXRd2lX3RrOOmqkFhr9k7/pKr0FxqFJNwkTBFVm5V3+FLLH1bom+NXNJ5naiNJr8p1vS0Nwss+5sWWneEmmlIx+gMikjpBJWsvsN2LeqO7/4TW1rJPYJl0MXcrC6Z9kpxjGglTJO0TqWrhBkJg7dPGRRNxA7CL6Eg+8ymavbB1/ZXmtlOHj4vlv1OuvZZY2g7S1DETPKSAf+bIqK/su5u06Nx3N2JIC/IY7EWUY67Bhu520PUsezHSLsBf8iG8fjqEp8xmf6KVy7+wPDTlILc9d9guluax2rvr7HMkbZHCUmkc0d/JUHXxdneHf9+jmJtmVwbbU3ozPR4txtEtGWdP5fXndRiggMHRoT5ZdOrh9Lib/30MjqxqMnI7iwweee6DPyUaLROtoJqZDIx9UaRfN7pR6jX4r3HRyhy/lpys4tR27iRqt1+eFNR27ki185LQ2h2mdH/B8PkzRiw5fbc/KJU+BZar9Ua7hvsQw2E9GiyS5dH+VsTfVVl6/gwQxR+lqR6yDyZivP/w6JRCUtD1fFipPXhBLV4eHpNfD+HX70cfgFa8+jROZhAt4FcESIeHH0jm4zCoHmI2AzfONwFna3V6RL6yP83D7vr5ikxPk9BOMHZVYUffMuBecIp/CYdWK+DSSQ2JqwGXvGAekn8BK+lanP78iwDY4W+/BYfk8N+H8NZ9+kJOuv8mh18haYdcak4qwLTDyq+VD9hirXpX9Q/e368G3ZP6h59/9pCoeO17SfW/vWOCPdljUnlfAYKer/jn+Nmvjd+PcZQE0vcKwcUU+n/ir5VjUvX+66r+v5VjuBEX8TGf4TGf/371DM/4jM/Y3fDbb/y/96SOt36WbuXP+PXz7x8I+ba95Vsl8/Z3ePvtt8PfAvrsJbDvDN9oFOVwX+Lxk+slOgBUj9jf1fHmpCo04HQNWRueM5ErEK2PbYTDox8Pvv7I/vpREr3wF+I9/qzC2canoDe8ELsi/7CHg1OoKmNa3VeXUxD4qnqET8Vbv/FfU5wEINXno2JssCE/e7M3r2aveo0yfPgMlnHKCzLwmhCWkpe9u0C0fD0GsXxFSWzo+8xfIfomUQ3/qB/TLV++R+c35O7/Ad07ZDo=', 'base64'));");
	duk_peval_string_noresult(ctx, "addCompressedModule('linux-acpi', Buffer.from('eJx9VVFvm0gQfkfiP8z5Bago5Ny3WHlwHJ8OXWWfQnJV1VbVGga8F7zL7S6xLSv//WYBO7h1ui8G9ttvvvlmZh2/c52ZrPeKl2sD46vxFSTCYAUzqWqpmOFSuI7rfOQZCo05NCJHBWaNMK1ZRj/9Tgj/oNKEhnF0Bb4FjPqtUTBxnb1sYMP2IKSBRiMxcA0FrxBwl2FtgAvI5KauOBMZwpabdRul54hc53PPIFeGEZgRvKa3YggDZqxaoLU2pr6O4+12G7FWaSRVGVcdTscfk9l8kc7fk1p74lFUqDUo/K/hitJc7YHVJCZjK5JYsS1IBaxUSHtGWrFbxQ0XZQhaFmbLFLpOzrVRfNWYM5+O0ijfIYCcYgJG0xSSdAS30zRJQ9f5lDz8uXx8gE/T+/vp4iGZp7C8h9lycZc8JMsFvf0B08Vn+CtZ3IWA5BJFwV2trHqSyK2DmJNdKeJZ+EJ2cnSNGS94RkmJsmElQimfUQnKBWpUG65tFTWJy12n4htu2ibQP2dEQd7F1jzXKRqRWRRUXDS77yyruR+4zqErha119H25+hczk9zBDXgt7L2FeZMO0zvve/iMwmgviOb2YU7xDaooY1XlW54QjGow6A7ZFWUKmcEW7XstZdBzdhGjHAsu8G8lKT2z71lGuqmpwakSoxAO8MyqBq9fVRRWAe6oXjrdi8z34memYtWI2EbIIy2zJzReAC/HYLxomaMTb6/x8Cq18yGjAglDLpyCCcvU5zGTQmDrpX+Ampn1NbwRO4QNGpYzw67PDIWXEE718AdODZSc1FAYz1J4wzPZuhFPwTn6h8N2kSpYVSRGTy5vNqumKKhnbkA0VfUGyMgnaibCtFEjI1MaEVH6QaSplamkX8WpoMPFC7pl2rNRhaKk6+LmBn4PqJZtYo3Qa16YPpcJvPySoUZ88gP4jVrTsxSvym/bh6hQcnMCy9oPLlNiRZN2gCHwIs4Oo2+z5/Yq6eDBz7ALptvVmU7iuoNf+LejV3DRKrtaUxSaCDf8OCe28QXbUN93jF+uvtF47Wv6MEy73xzTprfGHbUqdWr+SP8TH8a3cz8Ij9Nz4dCHtw69Ds5w/WDVGebsZThKNi1rBn3qEUTzYq+ljcybCmmO7URawwRuz66oyf8tuBKP', 'base64'));"); 
#endif
	char *_servicemanager = ILibMemory_Allocate(38001, 0, NULL, NULL);
	memcpy_s(_servicemanager + 0, 38000, "eJzsvXtf27gSMPx/P4Wap2edLCE3aE8Lm+0bQqChECjh0kJYHsdWEhfHzrEdIL08n/39jS62fLcDvexu/TtnS2xpJI1Go9HcVP39SducLSxtPHFQo1Z/ibqGg3XUNq2ZacmOZhpPnuxrCjZsrKK5oWILOROMWjNZmWDEvpTRGbZszTRQo1JDRShQYJ8Kpc0nC3OOpvICGaaD5jZGzkSz0UjTMcL3Cp45SDOQYk5nuiYbCkZ3mjMhjTAQlScfGABz6MiagWSkmLMFMkdiKSQ7T54ghNDEcWYb1erd3V1FJr2smNa4qtNSdnW/2+70+p3VRqX25MmpoWPbRhb+31yzsIqGCyTPZrqmyEMdI12+Q6aF5LGFsYocE/p5Z2mOZozLyDZHzp1s4SeqZjuWNpw7PgTxXmk2EguYBpINVGj1UbdfQFutfrdffnLePXlzeHqCzlvHx63eSbfTR4fHqH3Y2+6edA97fXS4g1q9D+htt7ddRlhzJthC+H5mQd9NC2mAOqxWnvQx9jU+Mmln7BlWtJGmIF02xnN5jNHYvMWWoRljNMPWVLNh8mwkG+oTXZtqDpl4OzycypPfq09uZQvNLHOq2Rg1Oe6KEnsllTZJCXthO3iqXmNbkWdQ0JjrOv103u1tH573r/ud47Nuu3N90Oq1djvH191e/6S1v3+93e23tvY726iJpHPNUM07G9nYutUUvDqVDXmMLaQZtiPrOsMvTJdaQac2Hb81N1RdX2ugA2xP9rURVhaKjt+YtnOOprKhjbDtoJnsTCpSco9Oe3n6NDcer1dPRnNDgVlAd7S1Pm3sgLblVt9mzXQsy7SK5gzTRVt68pksBvtOc5QJEj/Aa/oRHkW2MZJYv6UN9z08FnbmloGKWeertBkA6yIkJ+Aw2gXQKh7Jc92Jhhg7NzpHGHJR8eBZYp36+uSrMF2s4Z7p7JhzQy0a8hTz2QBSwzBRsBzwHaKTJrGpJfxxBJU2kIRWEKlJmyCVKoqpwkKSOr3DTu9Eop/YyEmJzSdf4+gmQB9lBMCS++UhagVJaCRrOlZRkSOYlod+km6tIKkkRfWW/tNE9dqLGnrtdh5tIKlz3u2tNSSx0p1mrDU6rCtQNd8g77Eyd2BCi4o5ncqGykfIfqImKkq0z/RzxcIzXVZwsfqf4uVf/7laKf2nOi4jF35xKjvKpEznIrB0gLsWAXU3eAFbw8wyFWzbFWzcltBnpI1Q8QYvKo65b95hqy3buFgCTAAs/1sozoYoALm8wYurTfQVfXWbdCaWeSeSzqlhYdvUb7HKCY/QJsLGrWaZxhQbDsyuBjgJUdXXUsWxtGmR/YShkOES1BP8VJSJbLWcYo10XCpI6DWq/lUoXv5VGFgD42qlVCi+3hjYX56VqhV8jxUX72gDVf8qVlZeD+B9yS2l+YvRlgFVT2nTX76gp1VS51lVqzjYdugUXNavCJpCGOgat7KuecPHLg24k65rBhu82yzDKUM6b2HTt5ItLKt9uottaxZWHO0WF0Fs4eTgLR5owRY3w5EtAW3J6o6m4/7CUEjFUsUx+46lGeOiQHmDwcB6PTCA7iQklSr2TNecYpW+FObmVtbn3kbqo0ANNVFtE2noD9qVio6NsTPZRCsrWpBsxWmu/jWwfy9etlYv5NVPVyulgf17s1j5vfSMzSYBdqldCewX5opW/+03F3GcrGGGeDfpt8YVpzGGch/iSVnfgp67BM3W9JHsTCjykploxEoQSEEzyPwTOJEs9bR33Okf7p91to9aJ2/SeCsTbgR+E+whx0ICEUlQve/IliOJ64DU9Eg9ASEcpbwt8q9HV39drv5/GytPr1aqZSRJEYu8+lfx9UahCGtzUPkCa3pwVfq9VPgiFS//kq5+L0lfioP+Somvbdqz4JLN2VVLnJYmclc3rHxOMt7fa1e+hXJfvKytvpJXR1efG19L1bEmsurrMprge4GX0qVWGVnmtD2Rrbap4uJMtmzcNZziBN+XUf1FCbrma6N4ORgUpKsSWY/P6uLceD0XGOPTJpKqEnRZ+KwZKr4/HBWl/0gl9GcT1XJhidOdC48wpmqVCCmyNb5FKqElfYFsE0002zEtTZF1l/Jv8MJGimnAcQmEfHsmK9iuDmXlxtZle4JtZM+tW+0WVoYjK05FYHtzgxKs4uhF2RrbIlmPQlxuM3peR3YF32u2YxPmJ1WHmlG1OVipBJJA4B1IBNW5bQVee/CViaarYvPkxTXbMaUSIVLgt8I8ldGl5MG6qiimocgOHZbQdXPuzOYOMAKpTJe7zX4wBuHxXNJoxXZUc+5UTKMoqbIjSyIdKpO5cQPzzaCuNBF5JTB/oLkAOGxZKeBYvzKAAzj4XnN8cGxHduY2AGJjoi+Cde9kzenca06x3qjVajWB+rkkB7gg5GwtABipdaPpOukHUghzKRIO9jW8XbuTgRxtCgfiuUO3ZpiSy9qVuwbcFp82fcsnEpYAwCes+sRT2g7FItuUgiuOzlgUq+/ax3MD1lJIoHdpx7dwLiV7Yt5JZSStrs4sEKWdRbNF2H/fkR0c+HIga8ZRd1uiogV0t8LWsnQl0ClMGSacWwDFduwpZdK0O0KdmaaSGqyJZnGgrsQUJ0ydtgFy2ExTI/F+apBF7pjoFlvaaOGyHVJVFDOFuXQZ70xTQZgDvlkTmLVjzbFYnsBiooWkGTIZL2Gzvi90piUB0EjWbR+k6l9FWvsL+UcG/c0XFQs/LKybskr/GlnYnmjGGGQgIn7y5koxnY2UyRVzbGifBFlEQI0L0C9uwkjmFm6RXycm6OHG2CJd987zMKEWdjaFw71bwi/mhY7J9EjeO+x1wqfxZm3T92poYfkmeJrnp/TjTv+kdXwSAaWeAcpxZ+vwMKpyI7ayuESLFnYCiMP3jiUrDnD+njyl0hXsqRxnQAPOYobNEfK+EeKxCf+UoiRkx7zBBmwCvAYTy6XBQCpVPpqaUZSqrrAOf2766gP9bz5xX91NQN1ZJMwDNRn0ysycweEPuiLW58oM8ahGZVbdxoG+Mqy4vTTwXc89q34VGZmApr45t5Qwoni7ichCr12UoA0BOwRkYGZmFp7JFt4xdRVbdnFE/hVbBEyp+tQBWZ6ffGe67IxMa0oaJfoAaBPwTiQEiWHVP0kuZDYhBKjIBKG7fBt/IswImwl6XvqzFiQFVq9I/6UA0Gs+f/ZEGzlFOOvSAitsMCuBAqXA+Ymoj7iImHXcJfQHZZgg12mGx4DgoXux//g5vVE1i4hf0F5ocyYCbcXdYqVO5323fyJ5HB97uge/iouwcia89okQQdEozupH1ESfvwo7Fy1+spi59F/ZxhYeFWtltF6qdA3nTGYi1seKZtNzM+ym25Z2i4FAikURyG+odl+jT4MQqPDTA/MWWwbW00HU/SDqAoj+RLawekRnKQFGo+aD0agJMA7vjHQAdT+AuggAdgOL7mLxEOo1H4R6zYMAUt0bzXACuC++QL+j9RKZAcfcmo9G2CpSxcVp13DWGvudogvDku/6TP7wwahnhsG10R6sSHW0Ow3P/bvExwqXf6T2Ye+k2zvtXB91etvd3q6UvvO4UF/EQj1qnfaXAvnfZJDbeWCtx8I6Pu31cnasEQuM7OHLjHUtAeTh0TIQ64kQj5LQ52kVgCtapm63FDApYjVIpY0clB4B6/LKE5GLoe9JizhA4WHoldncnhRd8QpI+/hw/7rXOdnq9rZb29uibJC3+nHn4PCs8xAInR5YYB4CgRlxJJ8sk4bI2ks/S34JG1Pmlo9ax62D9ptWbxeazdpkaCPJ1+RpnzSWuQZnYpl7GMHgc/XwuNN/c3qyfXjey4GUdT9S1nM1uUR7oa04V3snh0fZ2wpv2XnaetM63j5vHXeOjg93uvudvNS27m98PedcHp53jjtnYErL3OJLf4sv87XY7/T73cNecJgfK1TB4GO2/83MbPmZ4yM9OhDpOEog1jVjfi9xCdMVRa/nMxs06Ne72GES6QnRx0ed6bIrEJluciIR/eFEEg0gPo2dTY4ukrSZRZFHRWvNJrVAjRepwkNBJWNEG/G6xyXa0IwKeLXgYkEzNAfUabpmO+gLciwkDQwJSf9XQl+QfHeDVnfgb6mQCEb6LCV/h3OVpRnOCBU+FzZReumRaRW1Zn1T+6O3swkmrQx1MnQCPjTpefGZVobTdrlQLpSy9Ag+NFhdqHhZvyoTqaVcQJkh2FCzac+HtmO5UGplehblL0qr7DdVGymNq9JqPXMLpINuzbLF+ljN3EeiCKfVLhtXzWbBomrQwusCE0cLGwUmphU2M3ZKU5uFTBNPmFpRaTYbWaYcZj1bMRc1BMmNq/JMU/PMHB8F6DIbVxkrfc1WjC+N/9iDAf3PBvo8GBTIHJBf/H0Z/pppKrzk774WykWt2ay/LhQ2gJjLhMjKll2GDmfpaZZu8j5+TZ3FwldpYIAtYmCEuYZrawgozyzsCOoDRPUb7t8eU0d0A0FNtNc/7FWIXqIY5J0CbE9fQhQhRXb89AP1CvG9iaocvW/e7sOd3H7tPo+w+3jmnNVVUEE2ue58dZXQfpOxHvQFjS08Q9xC8i/dqbJzqyiOwv8qlJGfXyC+EdE/1jNxtx/EM34E00DLcI2vT9gTK9+qsnWnGWEBdyorRyCOsVVEXTBC3IX6fxDPNuZSw78RA9jl4L5WWx3c114O7mvDwX1NGdzX8Orgvj66YlYuCjjRw4qdExC4PsiKQ5xwkS7PDWVCPo608Zw6DHqnAxTw9fEcLX4j/hW/ydPZpiT4X/xBX+uO7+2f9O3Y/7ZA3/5vbvrfSwz0zLQ3pWjOPZUVxrCJySgSrYLdiGL4qWAFAfsoHREVz+AFm4cmkipS4Dd9Ub0cVNlUhDDv0VS6jxuszHgcxw34HBYXISbmgAQTig3Hjtqtwo4eZeTgKQQFWAtmFiNmaqA5l6I1lbxzpjPYF1RmcSkjxcIy1aNR62yGJVqtos69os9tUHmT+jAM+dbUVBvsPbp5B3uBDIYtzXaIl4sjj8m/i6muGTcVHzzSm5FdMWfYIEYRdzRlJN3dS2W09nJdWPZkwbvdJgZfPzy7okymphqEFYYysilfo26AqoB3fzkiJOimDUNoopG66WEw3LRu2hQgqxGA5dF3m7o8Fj3fmpk+dzSdCBerumY41BVBEub3KjyCyLGuu0YOoaSFgTyDRQXPO5SZqSK2CkcqrD2/34kPCSNVNG9pY8O0sEo9UL6GoLFZ9YGaG0Ax/k5nBMmNZYGxhdffUZQ11F0bWRchs0hK0mYUo6JAg5yKvo30WXP3Bo8h0dLJewHz66eLkjqjmdbCz5Oo3dVyPANtpLXc58Rap06spFrYiTWaOp6S0uClGmMcRZ4LCiknsGj/q4oUM+iowaLp3HaIzz5ztEOq6SAbj8Hp2vajAnFT8gpF/Irb8GaY2H2ec8R0W/IV8mPAxcLIJnYTr1ZFs7d5Z4vR09kzHSR7Q6L+Kdxa7GvG/wscEejCCRmZAyuM/Ul1iq4d+mvqYtmaa7q6T4ULumeZMxKUVEbyGBtOcLkENnRWuCK4UKAoN0UCC71GvLztuWSiDfcto/YjauPnbx3ZGnNXHA7co46mW+7OtG40Y+zOBdBdkTcs+IxSRRBIebWy+F6XbafL/UmrUqkEAICKIjtYiuQLwqADvCHFp9UdUOhrJEGxGeNMy0by0Db1uYNBRhhb8hRizBDDiIAtoAw7kn3IU+xgooXigxVefvniGubcddCyLHlR0Wzyb9ErnMzQuBzrlQ/35n6qA+f94zX8cUsjHpuFeqVWQNhQTHAgaxZOT3ZWXxZe/zkw/pgRPaqv4J9/qJri/Ckwb4AFXOGPG7z4c18eYv2PKvz5B52jP2FFBg4BInGjFY+WpFU6CvKbeI0Asawg6Y8qBxbT7hGdnJY1nhPuxbogAwqTeuIRT2w7UTEKHpKz8nhGxl5F4NkCJScSo8yHRVn2ELzxoFYEk3axEj9mXx9ih/01jOgqQyeg9jzAE1Ln3F0qsS1yNydYKp8RPcpuIKnvyIYqW+rh3AH2IJUR1RIJnwi6yEf0NWLieHgTwE6aI0aWJGzJldcy7FxsboPVRSYlfsvGiILrWjfHZAThKQ8tBr4Hsq4QdGdbkaRC7AT5yeKrj2vRJfzbb8JGRGJywcHHjnvPFk/cnPg5C4T17puyemL2PRC+dR7oatTCTehFYAnHT/el1PrfHPSG0r451gwaTwg/t2TlZmxB/CP84sTZPSS/iG5QunK95qJ6QtbjHzHO4kGCYBURUF8KUQjzHtNstilHEdwgmWXA7BzPjRaZOTpZ0Atv9GD7pD51TSS1Tk8Or6lvrrBoAoXA+5YXeo2kP+BkW/2T7BZ/kMN59c+gL6uFCQhhC2a+ysf0g38D5qUZBwDi5Utc+CQZ8+kQW1SRAu5+Bmj+WAEi4fDCMKGJM8oLauAjdyvr/tn04fItxrOWrt1iAZfu6Fh/hab/RDXf5L0W9lq6kROobQtCatj8MIT+UaUbPcGrV7Q/V0BTMprroMNkNRjaeZVS3FxEYBcQ4xvhycQyHUfHXYYM1oRGvcnJiA/A+3Qq3xfrZfq3gjXdBVxFdQj7YFzMrRehbCLtQiE6vCoRdzhBhyV6dopiUronzrMI7Sjt21P2DaQ5daoZMacYBpmog2zEo6ldEdQyTScszEWdrT19z+VV2ZVONRLaKcqZ2Q4b/nMCiYiMrMa+Cys2AEjYXH1HEWFbYK+7xhGoQCOx1JYNOKzSXBALNDSdCRKhgWDuB+NHWkQveHNJh/Ook5XInLzX+TZ2zVgl6l7hABNm41FYa0a27Tt8RRWIO4WFD/CBeX0a06CrCuFhAJGDZYP06VuIFAvZP7B1S5MWCMe7oWzjsH44cRqPBOf2uLmMxiRVKuqmIuvVKbYn12yEdtW3TUFyF9lYANW728LruOUgFCZMqMpOMsLuS4MrwmNLnm7hrRDvWV15RuNjaVsJuoIs2oAyooc+QM2+NgQ1YpUeQ7ZlPDUNipjAAU6qkEqBtulpM1kVQjaJAKcI6I+gQjRxcUYp6+CYtaB6dJvqgPycKMA6LaxgbUasbcgydR3CSjcEM3AcDbmR20F+ioLiJtcaMdvKKtUL/knk0NXVVDEzSq3LQJJgdhc+LEIFF7UyqofiI1igIFFceZVhulggYYqOzDcgYS+JHZSoj7amXK0m1KR9z6rmZv1nZ4RUvaaiY9mYz1jopC9WkkY7gdXWz1N8p0U++xRVxI8BDlGutaOMpiTjSDxpxFg7RBNR9HSHTDu0YcGqE6WGDIMRrRwURNiYwzs7XDhELKDOjRXNZl6ObLQQ4Mz+RBu8EASiuwXCYNni9duKSDtkQyR/JU8nSaKFncB2AaaXBM0uSjE9ZTE3xaCPzHjSaWikGbKuL1g0kt/ME2XgidrQ4k2IYZtLBAv3yXml8G7uCjBDzQDTp+8s7ok0zaawWeTW1wtVWexTrECQQ/qJ1NkL61MMkw+MEoxGtj+BScSowcP31VqoXbKYNR2LSlv6O6CvRTFqBlI4j16BR1yGheyo4FDCSEtlpGKwG9NFEre9+0UNsT0a8YiaMYGVgbQp4tTzmk2xB0nGK0Tt4ceY5xcjEqCFidUJ5D/NUOA4bTiSjTQVG47mLIhAP7PMWw00FZAII47jCOKCr0O//YYuA8IsCCvqUCoHDzfwfko81qI/3Ed/mVnm/ULQ6tAcMjxfRhI6BDIW+kztzID6yvWQMN0oSmaxqlHs/WsKA4mR6qQkLlKtoqP5UNdsmtXwozlEpqEvkDwCHxp8i62FkIGQrL+qOG8k5yBGNqgOsAp5/gJ9FBw7iLhXBtkxtOkRQdDfM3aQZ/LcMtZ5HndKAFS4MOjLBMEEiyh2RoTfTZqZiZUKznWidb1aJVnaWmNK+dyBEjnyDZierPEtJITA9yDlaY6+qKAeoJtqimbgBMaYGYemg/3FpkZ2u0ySP7q2A9lG9gRDcj9jNncqIf1GwN9CZK6QmsKl/4f5hvpSm4jGw8Bx0p/qxGvcf8bIkfcEPX7uExT0Z314/hMP5HI5UFDYz9CXBwVF5UJJXBsx+VFE4T2C4IU14h1BIbNJXNaUmJO+kEEl7VDmS6cVaHX5/Cp+EcSfc2u/ddprvwlGd9JCMHVtL4PgZhRToGm5wgMPJHNBYXXkGDuHfZazNtJZ20tiFu9HZd9dg22XOlLNLFOdKw6DKV35U+vx6Xha/WugrhQHFcjB8vuz7L6XU1k57HNTMkU0y8YVOpuzc7l8t8FcLhlrqBAXPrZmfMd1Ia8J+G5b8h078lUkKnVviqilChoLn5hwVHCh3MqxC4FwGpK0tok8h8pAUolbWRd6ikjnoSvp0qKrz3Z7TyXHMm2UH5kyC5IyJKPg2Wo4TDj6g8KvJpVRvVYqo6FYijQUKBIt+8nkKCegXEZ/oCF6jVbraAM0AkkiPKsiJGvxTw3dzKNJ3qNkzwU0SPnVKqLOgWgiGyoI7ERL/P5gnwiT7GxAJAm7DEKnPgenB0Rz/KrcrF7xUSQwdL+zdVbnRMU0brFF/BM/2qZB/BRN8l/XZRFGcRVMr/GUNPnlCyc2+FkhrhUhF17vk+DHG+mm65XM5qvL7Yy0XV/+wTCrAuBxsyZYSbfNqawZdohjUcMQEx3mNrZWmX0SRIc+1kdFL91S2EvCg4+oUEvkqTT7ichdkbvbuQJF1BzD/FK0QDI2mGISEwCTCZ2u1qQrXzPhbCXertBE9cZzYRldkkypXuISv3glG6qmyg4z5JSRShHJfrEcrzPZcbBluGkxi683xnPtiw74KQ2qwLIH9u/PquOpN2qe14enVGQwfLm1SqJWg2zKbnfcg4+b49RN8uKVIeK7W8CvBvEl8hzPNSTbJBq36PY2Ks8Xpxk3j2dEjyQy7ip1dkjpXFRZcQ6iuLYAI4MP0IOoy2vqUru6Ch0xMpGZcBaNojKOUTIP3LWgiYS1xSaD8BKXMD5zSmRqZrGjMfYbzjFovUimMcKOMmFcnjkZk5AhSL5vaSFP44DGJMJlMi7rI51b4nHsuvgKlpVnYuJRJCiG3NLMvrOCYi0hXFUm6CgIE01UJIMOIEKTFwATdHOOzNwdOo9SDT3TbjHNAtfVM5DpBMaPDzwbdnon4oiOoTMiSOAx9GoUbVylgg3VPtecSZFPUylNS+NjvuFZ55CjRaWgxOICKrHNXEg6zNDgFtlkSWISxSl3dDlowL+xMNkmUraKDGklHaZp0wSTM1s6TAJZQXUq2HiWohclZlikVcu+Yci6JtsbgpRTRipRS23wNelNXEBtVSqj67mmbjDOUCZGABw4HPgOAFzh43A9KVa32dwK+mya7FqBw2ramZfkcSNebk02hEhPNf8R5Fr3GOsh6NKaHEbT71ZGfK39HsGkIFFuOoL7GmH17ks45wZB+RP0VeTZbN9UuPI4m/GTBslFEAw5ZURp6EJGaAqiwhx2yfD8r1wfXrKvR3/yawyQ3w9zKVfxSMnyAO4VAacc7gPuOlnT/tBzrDj26POOmAfZXYeh2Qi61GaeFdFnP2FiKsEGwhgUIHkSnwgeHAwimBA/p7glA4jP6YQfPIKE3O3DpiIuVbgNhbfxoH9EYAZ8rvqRyoUk3IaIl1qKxEYOhx+x4lRUPNIMfMQS50KUbRlJ1xZ3kpTK6DOod2IUHEl9cB0tUbPZ5ClefZrBpC64XpYpPSAtev0FV0LRb3MDSdudg1Zvm73I04XrG+7eGNmHhCUAFVOo33WdjBCsoLowRCmJyGlTTSSZZCQSsCk2KMhaXiSwgkwZXlaYm6U7O2KL7FuoYf69tX/e+tAXqdeHVbKnUJHaR71z2BOncy9TYTT6bKyPRAk5+ggewXEJLcw1n917TtMp8U+RqISPdI/PIsEVhRYAm+xnjbiwFenw4D0ZBvmQEE5BRQdPO0DulyLe2exMQlRFoDMgIqgykY0xjoi0EGeH1k/0m/bQFdj6syAgdvw51CEKdZ+05gYiV5DBHKPd0y4bdfQAyfbi6hpilDnR0i8/GLKV8CeqR++xc93RZjoWj5ru4ZB32sY6ViDSjzCp+Yw7vyfOSqADr/kLkI02Ig4c4fkilBwkbLpWmgguA4pdMIpp2KaOTzWVZNeFOlHrgKrTuRqdpD+YQ87yL19Qj7iXF8nPP2LnOkrdJUOsyBirq5pBJ/m0ux1GFDmghFcO/BCbfkoHnOSQS1cIkg2qIidN8p07jrb4whnPtSobdezGfE2Sp3SN7TB7o+CT3Hc5T/RmkTX9GUHKdHAUIz6IZUgzv4Fq6GuUM0hQV4geqtFh3eLnSMIYyDEoQbuTwieqVVSvr8GdYF6TNppSEXaVZ16wsD3XnQpqT7ByQ3gf7UoUOMc04XoOGS61kW9lTaeXCsI6daNPNBsZxCRt4Zlpge/5BMu6M1lEO2sIqqmnTeivP1tzqM4yWI3yWkmd9AROIN5BMLB/n2XUT0Y2C9s+axXgvEaBWwWI4QUFuhS5HoLbfEhC860atvVQBFGpgLreljaD4MfYOepuh6UI2aaWt0Q5gqdX9npA+haJFQ4QolJI0QrFEkiU7jUDJCUHdZ/e8N7E4kaz9ymMTNghX1irITxo/MKMPLCgt3+CtioE7CDjjHlwmk0xL0kIpE4E/QDIpFMiZ59hUiDCaMRpMMQ7E4UNkSVAWD5J9r3pHeI0XSfrgHAdGoZ0N8EweNlxK5MNPkLaIrsl6TmfYjJe6FQ2HjE0Tcd2LHnm8omycHIPs92EBkNYcHc7TSVDJ6P083W/Ds4/k3NjubmMUBH//STMahV1iR0W++6BIgL1KqNAC4/hClp2qSuI59TpjJJYFEixi8Rh+d4pk3t5zTmXJlnyHbjNSidBUxDVSfoc3roEcxuX9V3/pBihONEvj7myCmBjFuVVSF0eoRX3C7qZ9eJR2wQXkbUrzhfzrTBz7u3DPK40VcLJ36HUFciWVMIa9E9KYEXycNFvxFxJIehgxOaYDdc3mnJDOpkiS8YP0JxlHR9x3J2at7BguP/nzMK31KlQ15GrWUEzExwVsY0gUgBkzZl8R7ZQzamEMUAnKYCDQEe90N2/xVxIqzfLzUjA8wXy7QVv5GU3Jxd5ij06PKp6IgKbFLgzmOkjYlP20TtaSuiJH48E7u6BqA+63sUGtjTlQLbsCQlQ9pcmbtAc47sHlTZx3O3JwJ6P4FtRaqm38kxba1RUPaY+q3WAnYmpFqVDCIZps0G3MlXpGPMpmzCb3uvSuT/P3hitma3Cuzm2Fr4rZDr3uSu2iXUj29jC9RrZKrZp1kNWNVMVcqcnq5CxERLoQmu8Ia5X2aoR1YF/VNnwH1EzW8WWDtGeDm4ZatfQHE3WtU+4r6kZW8XKzQkkij/AoCOxJ9osU8UdC/NGIgo3kpcOvQMoaek0As3tYmdfth2yOYbbZMHoIk9149Mj+GnvpDV3JqYFIRnBfp6xq5mLLwKsU6gkZtAnkQBdw3lZfF5GzyNshaQbVNgzLXvXMuezUKNHJvF/DyoeiesjHxjN0hgtH9MJiiOEotD1MmqU0VqjjJ6vr5dRLfS/iN6WKmeyTmXnFBmM3GRLyCg0Qn53XoxqVSSzCIosRveM3W1QKrNW43oa3VveNq0bfyuCe2zgUyFeNSg+4TfCsNh6KSYMI1HA5ioGqB655ZK2QNVB7XY7rhOQ4GHt+xZrfvL5Lpqg/JUtZUJvSpfuX6xLGRR3L9bRUHMQu5o+fs53DyqM+PvaJ+KAs5517nhWX/F+domPENxYivcvX5SkK9BJpRXZiC8iRWnfvqI4hVwCnM0YJLVms8DEB6XVtUYsNvM2C49IPn76wcZ8ii3Z4ftQ0HAcYk/UK5kvd0rqfjmnCJeblJH331odfaF/BEO9gCooQLKQY2+ZJf8giC0muWVZV5mMKLow0J1E3DuKhEdE+ZAl0LQbXdwj0V7xe0ZwQMI1e/Yxmai8tUG7PWUCSPaaYq3QZuVytqBDfLWKTiYY9dsHSAePH9B7NZ6/QG+1rQpqmwbAJFkyNVlHM3kMzuh4ZFpUBz/VjHEInoxsWNYzyxxiliIYIuoWyDQwgiMHVm6wihQ4dCmygUDocjFWCePyE2qixotGfX09HtHxaLI/RWB45jDWgyIYUrj4UDeVG1Zh7QWk1IBrzBiQAHiv7ArcEMhbWkVF78t/3Lol4e8oQnDImoiO1t3czLI3wxlXM+f2MSEPchyKppOoa4FC6KZ5k/xLP/K8wtY0FTHYTUdrwt+1tbI7eWVkfyqLi60cWkBlX7cpGLKqo/vJI6l4f1+jGtpI4Q/RQspTDuK33xjUp03UWFtP4FGcnwp8yhaCsuIj/805uRkyOPY8k0SDzQDO7wIl/onsT4kuSpydul0n14uOYzKyRfqRQ6MRSrt4wiQ3VQnDZRKRJva87P0ZQ5EfA5cN8OdjRbzj17vjlC82Ln9VzjUVN05Pdl5GwVA1e6bLNGOOHxSDkxcgDXTkMUsRl7cyMAJ/KaO1F0ExEVEh4EzWqcf6xyhxJZI4GDkDNUS65iJXFszCJah1R2QwiSluRPLiOk5ZvZWNYJKrcP+F6xzIXp5Q1MtmIZ4wQkd7xqFi3Iq5ZB0hE3lv2SX0vE5YgNBs4oHT9J1YfVdmIP9Gxiktei+j4QOf0Z2mYmqF9blPIW93y3PazCTlzByrcm1Hb1MPkwfZH/Ua+oKKDGGvyasGMG3C6fPIjHdUYGZTxCjQ1x2pnFdUJKOMGCDTtbmbnTCLUeP0hkcQUmuwj42aiARaj0Q7JwzfG3kGIQDE5g7bE/PugtkWUUS15MlgK0iMOimR7BSsp4lLPFl09/CTVYHhClqfkauK3ghponnOFSnaWwu48bWtTFGTrYhYns3zs0HJ+EJEec2WY3wpn9Ka/Egp2/DTQGxptn/SzCuhQrEOsGeyTt1wnTnEZEee4j9Hv4bH5y1bDMsSLojYLyierV2H+Zr7XjgARFCz+NAqdEVEKdC5BZC+FfRsQo9SmqBeKAndFkDF784pjXjGylxjgcQmtkM3A/+YEjRx2acOuZt9MUJGgiR6yaMKL03xAZP1o3QOFT9TR54NJJ323vbgct3QZpy9b9FfouClLDw3HGhrIZWjF993WHsWHouGtzvNWGXeDwspbXUFWHu+xpFHPRYeU5J+ixfkx5u3nQ8VCBbSD2RlohkYElp/6J90DgaD9tyysOG4ViZnMOBH2sHA1S1R+Uu67gpIfhg90gsQ7+8fZ8WgInFx+vZEGDVJ0Z3MSq4QvRZDsPHA+UMSbGzE0ZtLBSDqHJiqNtKwWowr/CAqYQTSncpjkplNip/XKLRG5NeKpY8wRuIOcmQ3pxtyhbo2QtASZ1rZNe8MX9RlQipVOvBHZ6pBqH0FtHnRhzMPAOkICW2MCQpL7wUKONmYsyPLnGo2cf9+GnoLOxek4VbdGzF9X0dglZkUI06q7EhDOquy9AKQigh0OqD+ACiBPJzhbvo3TxLVSF8o02WZq7hfR0jjvgZziDHxoJRpJjCeQOvWiwyHFp8YdpNIPZBO6v9JZR8xJdNb0GcVfucmOdfs5MtHw9bUDJxg/W6uMV2KHjHr6HymBhyi6Zvl1we7HqClCAnP8oFC3CBNQaTJ0f4GK6wWD135Hb0she1SgQeyv2HjdxAuzVGx375utU+6h73k/TFKIZmhQ7/9Rkquxagts6MIHg6baTF/f1lG66V4O4yvZycmN5Un9BpC/yF4r0SQWK0iFzn8S84+rq9AN0vJ/UzpkIp1eRE3q8E+ksIpskkqKdJFoe74upRAmOu1dKITe8wpr3N81m13rnda3f3T4w4bRT+ZSiL75ume8+IZUss7R9jSTJWOoVpF6t2x93bpzkSdeoGFvUSvUWMdMmA1liYLL9FXtYoU9jGxp7zijHbGbVIxZ4vissNYa8AwXpRR5AlfGFnOU3Kks1fwmNwoR6O/FKO1Cz7p7Iao14rSqUGimRwT2dhBASTBRYqPfBZI3GrTczFkG+MDTpBkE+DSNwHwrQ6BgowvpsBMEyECClE3pULR7XWc7JCG+oyJF7JPAbFHuaxVmNxiiacIHAySJoMCoIlQUxFTZKVpykMAvBQibOz0vYuWBAwY+A7eLYOIqTybkQiqB65ZMcPAhmcJb8Qfe92avmQEG6IVPUPdbr+1td/ZFuutJ7OF5AUm3KRDEHPJcBuRQIg/hIuyasFALMEMTZzkQZSh9nI+Z0nHLOgQ36x7h9ftN63ebgfEwPsd9qT0Kpm3h1h7qK0y4neORHwKO1vWsuwB6RI5tlxbznUOY474cOxHjdqXWhbaIuaZhFUcP0H8qOSuSTary6zu6GjGZda0a4gXTnLJhOLToDRFDUqUydvbmP8H24/rYUGqR7tVCGMFhhjS2PRPDo+OOtskFY139CSBmnGoTMIl0YR07gVMFiHl9jKnzZlPz0L7nzTCJB1vMulTlxxPxZHkbZBNh5PUTxQklnRKQY9MLeaMtZ7e08hmXaIB/VjRTzYkDHTmasGI6jjD7PG2QGVbMcy7YgmtohkJebOcE22K4eYAar+OGusJT53tmwwSKu3exEQEWhh7kYdQu4NijChD/57OKI0f4//NsQ2xkXAHYghDx6e9Xre3Ky4r7+NR67Tf2ZZKDxXXyc0Y+I5HlkeeVNeC0QdxA/P2K19QTNFnqOM7fb3sNpz19JFtSMiV1GWbCPzL70Ti4Bg4yKtQe9FIdusQru6CiS6WiGYQ6qcSCEo1zcAToiAWCPAAi8+sAun4iHMiJqvFnDtFm3PjMjQJ6wK+lBFhyMtsumKuS3eFxwtSKTJ1MMzye2nsA3kF3EJp8iDN8gg8Z0YrFL2+y2VkedYAi7gOy5vuT/AntDYTLbnhkTS9oMcYNLrD8qJ6kkrTCfPhnPqOPmDb5HJsjn1aGK3b+3T6dxujhC7k1ILbRSxO816REkM/Xxj0vqt0Bu/643rnCTaJRdfTlgepu9NddLfERB6RcATi2UvYZtdE3kaYQDRLizz5pVW3k5yRoKaXnf85uODRX5oBv2pld1OE8m80g1yC+pzs33ANbZqGDC7WMXWdZTNwLNmwNaBZSIBA9ru5AVFJ4P2vYlnVNQNvsnQ7cB8HxAtMZLh0Z2LaTjhrgQ+L7tJjrinEEvRgDuktuQQeiSJCnEPNpfDRYAz40ow0Vs57yJky4N3PhAxfGG2Ub1MGBSqD/LjaT4YKQQSQLadYYkfXx1Z9ojTvoTTDLT1ss+wiJPjFp1IUh1CmKWUUqo9kq0izhSgncf5zk3+iGTIqVcHSZEqNrcsbuynOWAgcTe/G+wcf5+MJkpFCsxoQ9gHhS6pmgzwNt/MRZKEh3Ny6CUlRSOYHg0QlI10bYWWh6JhWNC0SBKVQkZpcPZWoPv8mVEK8tz02n6w4RUSaJNiYZRR3ZJ+wky7qsCZ8xv200s4EG8U02smGDpTBHywbFOQqouhY+EpLP5ekHxKiU9s9tJ9kWivXVjHNj4M/TJx7hAH5OiCnIemreLMXdmnNN4BUInMdLFi9R+JpsJ6IRoXvWNc0Fbd8vX1+eLydPbjSh5qwuyxLgVGccC1vQqMxkIFnJtRKiMH5M24/TdaARjYWj5Gl+pYwjdw9KhGZkY3GvOYeyUmoz+ChnM6gyaVZMX0Q7NIRUe5gXX+JNtD6y3JU4KkXQ0bNiclLJsWzElKAkfzTzDkSep22Cu07DdwNk4a2Xva7BQTm+4HMXpFtTFRXG5mL1rMXbaQXRQFpnZksRMtdNm5Mg+syd21t+a7585R/i86tP6Bz3Pb4aB3L7bLwJNoKQm6oof4SAe+2MO97WX/ViFk6JNLESE8RwMvH8v5EZtgg3LBRDvS4jKBnZd6BNPaWvB8oni+Vv5XY5R7D5gQnomSzP1DLKOjHFRXMm1hHdJMK9z3G+co3jqQTbHSTHsUEI/PFZ2RaReY9CQZptEn++sPFNPgdyorzcMfMuGEnTJDfPSpuH6L/yorz+8vySxGBmfYR2plvskXk4kgxfmokcvozdzfoHfY66RE8/MnDQTPsUHk7yz0Njjvs", 16000);
	memcpy_s(_servicemanager + 16000, 22000, "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", 16000);
	memcpy_s(_servicemanager + 32000, 6000, "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", 6000);
	_servicemanager[38000] = 0;
	ILibDuktape_AddCompressedModuleEx(ctx, "service-manager", _servicemanager, "2026-10-06T00:00:00.000Z");
	free(_servicemanager);
	duk_peval_string_noresult(ctx, "addCompressedModule('user-sessions', Buffer.from('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', 'base64'), '2026-10-04T00:00:00.000Z');");

	// Mesh Agent NodeID helper, refer to modules/_agentNodeId.js
	duk_peval_string_noresult(ctx, "addCompressedModule('_agentNodeId', Buffer.from('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', 'base64'), '2026-10-06T00:00:00.000Z');");

	// Mesh Agent Status Helper, refer to modules/_agentStatus.js
	duk_peval_string_noresult(ctx, "addCompressedModule('_agentStatus', Buffer.from('eJydVk1v2zgQvQfwf+CNFOoqQZOTvdkimwbYLLpOt01P9cJQpJFNL02qJOXECPzfO6T1QcmO064O/iDfvJnhvBlqcLJONCm0WnED5JJo+F5yDYxWSzQaDzxEqgx4FiJmyRykneD6bUYjVgN5kX5K7AKRSJGCMXEhEpsrvSKXl4Q+cnn+jpL3hNEpPvF0WvACplNK3tQ+3hD69sPV7adrGpERYTVN+pixyG2eVpvocHCSlzK1XEmSJTb5M5GZAM3SRSn/iwYnz4MTgo8LS4Ac7/7xnOwAMa7NMdLfyEVEnoldcBOX0ix4biuGMWZrSy3HZNvaMjTD7HYUGpLs66205+8+3rCzKCK/k5D7Z3jbGF0KDbMRPAV2MXSRY9YX0bgFFslGqMRVQ5ZCVBtWb3Y/qqzd0wL/+nI3iYtEG2DOTWzVF6u5nLOoJq5STBObLgiDaI/MJ1LpIp5pWDJ6K9eJwJJ9BlMoiQr6DCnwNWS0ZnVPlWzHzaFoT0/7LgyrMsCDNqWw77t/R7Tj5zXroUcczvepm2+/3q4AKJTXa1vXDS0QhofrqLaBTr+XoDdXrnWYelgOsUtgjZ/YMl3B4qG5+sJj3Z2soWCYzhAByyYEl6zvTTNuFpZ+YYkB1BkjZTxDp7jxTNJVNiLUR0OH6FGUMCJucxv0iQvOta2T2b4gHF8qOKYSzgUJlkZxip1h4VpJCT5o9uxzHPnPmhLHQD0uqo1tTzcVf4wENN2RYbTtSUQtOgisEYMzc3JHm2A+hD46UJDZS+wHPLzQE6lQptcAXlG7eRUuuTK7YvxR5jnoOEca5vvU+Nbk+YbVJYv6dM72ocxb60QIlXrdLWuB9kwQHj9qbqEZWDXSyXtIzvoGyzhVxYah3bCdP53MPZ0DhLvbXoeBMHBcO05mh+uuYaXWcCXER24sSNCmKugLOjmEd1U9Iqvj+uiBjyjkkP5eVUZPFf9XEb+ohl9SwosqCI5mTwfbduJUkPAdw7YDCS8GN8+sM9x2LnRjE21ZOxSx/Y0SEAs1Z/QfN7fwRMjfYBbEj1NnYCGO4+aA50I9JCKeuY3SWHwBIQbsPV+BKi3bK2JQwI6vrzJ5EECscss2SW3gNHTnnvplZQZP3LLmNIbk/OzsrK11cAnUYw0jwbFpFyD7g74F7AfqhrSf/dWMxsG+uwrot8ndPbm+m0xuru9vPvxLm3eYvfyCI6xcQYbZ4u2AakC2/aucsDCBDEyqeWGVNrQTbZP+Xl7r41mF4a1D9524D7xjdAOzWGlsm1z9dFju/HrOD8Acql9oB/OvEq/jaqWvVFaiH3gqlLbGX8pe86Pd13CnklEgFrybfwDySlmh', 'base64'), '2022-02-07T14:27:31.000-08:00');");

	// Task Scheduler, refer to modules/task-scheduler.js
	duk_peval_string_noresult(ctx, "addCompressedModule('task-scheduler', Buffer.from('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', 'base64'));");

	// Child-Container, refer to modules/child-container.js
	duk_peval_string_noresult(ctx, "addCompressedModule('child-container', Buffer.from('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', 'base64'), '2022-08-21T15:23:09.000-07:00');");

	// message-box, refer to modules/message-box.js
	duk_peval_string_noresult(ctx, "addCompressedModule('message-box', Buffer.from('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', 'base64'), '2026-10-04T00:00:00.000Z');");

	// toaster, refer to modules/toaster.js
	duk_peval_string_noresult(ctx, "addCompressedModule('toaster', Buffer.from('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', 'base64'));");

	// notifybar-desktop, refer to modules/notifybar-desktop.js
	char *_notifybardesktop = ILibMemory_Allocate(28481, 0, NULL, NULL);
	memcpy_s(_notifybardesktop + 0, 28480, "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", 16000);
	memcpy_s(_notifybardesktop + 16000, 12480, "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", 12480);
	ILibDuktape_AddCompressedModuleEx(ctx, "notifybar-desktop", _notifybardesktop, "2026-02-14T15:40:48.000+01:00");
	free(_notifybardesktop);

	// proxy-helper, refer to modules/proxy-helper.js
	duk_peval_string_noresult(ctx, "addCompressedModule('proxy-helper', Buffer.from('eJy1V9tu2zgQfddXTIOikmtHclykQO24C2+aRYRN7SJOWxTpBbQ0llhIpJakfEGbf19Qd9lO0i6wfvCFHJ455ww5lJ3nxjlPtoIGoYJB/+QVHMOgPxiAyxRGcM5FwgVRlDPDuKIeMok+pMxHASpEmCTECxGKmR58QCEpZzCw+2DpgKNi6qgzMrY8hZhsgXEFqURQIZWwpBECbjxMFFAGHo+TiBLmIaypCrMkBYRtfCoA+EIRyoCAx5Mt8GUzCogyDACAUKlk6Djr9domGUubi8CJ8ijpXLnnF9P5xfHA7hvGexahlCDwn5QK9GGxBZIkEfXIIkKIyBq4ABIIRB8U1zzXgirKgh5IvlRrItDwqVSCLlLVMqhkRSU0AzgDwuBoMgd3fgR/TubuvGd8dG8uZ+9v4OPk+noyvXEv5jC7hvPZ9I17486mc5j9BZPpJ/jbnb7pAVIVogDcJEJz5wKotg5925gjtpIveU5GJujRJfUgIixISYAQ8BUKRlkACYqYSl08CYT5RkRjqrLCy305tvHcMYxlyjwdAAGqiQg+kChFi5EYO8aPrAQrIiARuKQbGIN5fGxCF/Q8dMEcm6MsRnOzdCCFMfRHQOEMEsE9lNImIljZEbJAhSPodmknW5Fj6xddgqW2CfJla8kt/QLjMZjabhaY8OzZ7rRNmY+b2dLK2XV0eL9T4dYZ9EugSgXbg5DpIk9QgBREO6Nq8Z1RvxcgLI2ikXHX9u6tDPe9U2K7o1abFMsQxvDt7fzSaiTSPuiZJ+MsgRZc2BLL8Fajtgx5RGi15rASjygvBAubxXhEoxI0fif4ZpvLXOn3Umejhtm4FlERhR8t0CJPHjfOP22BSUQ8tJyvn2X352fZfeoEPTDNwp9ifR6blyirNvyRezXMp9qEVySiPlF4sdFNgKqMfJu3rob0QozxgvmjaoikKuSCqu3h0XooIlKd84izeijhQo2MlsSDzo0q44qwvOwH3MoCK5aVZeXuN4eOYzbg6sgzfR7gB6hQ8DVYZmkEfMRFxgfiVOqG7UWpj2Wv1U1If5U5bkmgtqpiUB+efq8m2LEVv+JrFOdEorVHLNsaGj870jtj0nyYbxGe0V7kjCu6Da7N+u375ZgNttCFFwXHahWM2wiv8522K7qF0Wst6ZQ78r7whi3VuubG/o2yEQi5VA31LdDbft41bs3dvlvt3abc2qUvQ3OnOdULzh4j6L5bvcxo7VLVpyOnWiLrkRaD2rE6YRcGBZl8IUYSf0mOHnWrg/KAIl3inz+bKC2YvDLHcPJbhfnPak8qtVVFnzhfb/vHr750nzq2QqksDdXRnBMiJLqsHDmDkwOjr+Hl6emL091NcL+UjCmVQFnWR802o2ZD3rsK80bb7LFFi6vSNu9Ls0xpajWHQ9a4SA6GVE8s96PUITXKToN+6KZ4oE+X5k25foDL/SsTtG/TAz7RgHGBbauK6CWJ5E40SRX/lmF/CzFKUFiKiABV+yGNx1RqPcUjsGUWQ2XxdJRAvQEZrst4q/i0fVySNFIuo6q+dm2BkkcrtDLRrdtYoMpIxtxPI7Rxo7eMhHGxvRoCh80fPaMoTDFVfuuVTZhfZgqH+6LzEJ/HhLJhVgbjbmQYs8V39JTmT5nOkaBQW6tNqwemhjN7OwcgQDWEymbrkaeqojI7T1SdX+eATP8Z8f8vGv8CD9ZbTg==', 'base64'), '2022-10-12T13:17:18.000-07:00');");

	// daemon helper, refer to modules/daemon.js
	duk_peval_string_noresult(ctx, "addCompressedModule('daemon', Buffer.from('eJyVVU1v20YQvRPgf3jxIZQSlnIUJAcZOqiO0ghN5cJyauRUrMmRuMVql91dWjYM//di+CVKVlPUl6VnZ97MvHmzGr0Jg0tTPFq5yT3G5+NzLLQnhUtjC2OFl0aHQRh8lSlpRxlKnZGFzwmzQqQ5obmJ8QdZJ43GODnHgB3Omquz4UUYPJoSW/EIbTxKR/C5dFhLRaCHlAoPqZGabaGk0ClhJ31eZWkwkjD43iCYOy+khkBqikeYdd8NwnO1AJB7X0xGo91ul4iq0sTYzUjVfm70dXE5X67mP42Tc474phU5B0t/l9JShrtHiKJQMhV3iqDEDsZCbCxRBm+42J2VXupNDGfWficshUEmnbfyrvQHPLWlSYe+g9EQGmezFRarM/w8Wy1WcRjcLm6+XH27we3s+nq2vFnMV7i6xuXV8tPiZnG1XOHqM2bL7/h1sfwUg6TPyYIeCsvVGwvJDFKWhMGK6CD92tTluIJSuZYplNCbUmwIG3NPVku9QUF2Kx1P0UHoLAyU3EpficC97CgJgzcjJi8M1qVO2QvOZ6b0X4TOFNlBOgyDp3occs2ikC4phCXt28MUFXhSxw3xhMKalFxrSZhmGqTDCzyHwXMvk6W/KPW3Umdm5z4J2ho9MAXVkj3M20IWSvi1sVtMp4h2Ur8fR0M0fvznc2t2GEQNKLIKFRHeokPGW0TNKFkaPGgvFSzxCEj7Rjua5WPNPWWwpc6Uej9GarS3IvU8L2N9EvFecN6jzuhB7hk0Gf07iS17qRUuvybnhfV4/RochVdTnPJl9GEN12v9Xlj4bYEpKpCjUfk8xtHwxJY8WRefytH2VXO6v05zqTJMOVH9/SO/5h8cdLEnjA9Sjl500geirfSDKDOajrg+UCz3W/fY76vtpSP/lOCiKroD5/k0cawxXSrFku5MeHq+aIvv+VYzORHQ2HHeBfGYLLGtc5q0H1y+zyc4bmXS+8bzRdtM9dANIron7V00TOb8Md9K78kmqVBqYMnH8Lak4Z7dJLUkPFXOR8xa8omTm7xWLqbYU9xZB/0N5+4GvNgnARJHao0pWy9+sMqv+qvcQfNoVotfbubXv0XxEfCwY5PtrSY7QirDnw1QNEzogdLPUtEJiXD8keQ7yL189w3sL5vHjcvMhBdRfPhwvkRzPiNr/0cAezLBUdx/T3p+pdXgEbPpcCPEhof7H8KvnGDpcAFYn8JuWOrtKITd3De3fJM4/lWlwbsY79qoZgU7WVD6e8U1+8d4Qv95m1SKrJua4OOHjx/wPKx5YTHGe9Wd1lrX7tZkpaKkfour3USToDrimoZJfVQa/QfwlvRs', 'base64'));");

#ifdef _POSIX
	duk_peval_string_noresult(ctx, "addCompressedModule('linux-pathfix', Buffer.from('eJytVFFP2zAQfo+U/3CqkJLQLim8jS4PXQERDbWIliFE0eQm19YitTPbIakY/33ntAU6eJzz4Pju8913d18SHbrOQBZrxRdLA8fdo6+QCIM5DKQqpGKGS+E6rnPJUxQaMyhFhgrMEqFfsJS2racDP1FpQsNx2AXfAlpbVyvouc5alrBiaxDSQKmRInANc54jYJ1iYYALSOWqyDkTKULFzbLJso0Rus7dNoKcGUZgRvCCTvP3MGDGsgVaS2OKkyiqqipkDdNQqkWUb3A6ukwGZ8Px2Rdia2/ciBy1BoW/S66ozNkaWEFkUjYjijmrQCpgC4XkM9KSrRQ3XCw6oOXcVEyh62RcG8Vnpdnr044a1fseQJ1iAlr9MSTjFnzvj5Nxx3Vuk8nF6GYCt/3r6/5wkpyNYXQNg9HwNJkkoyGdzqE/vIMfyfC0A0hdoixYF8qyJ4rcdhAzatcYcS/9XG7o6AJTPucpFSUWJVsgLOQTKkG1QIFqxbWdoiZymevkfMVNIwL9sSJKchjZ5s1LkVoMUJfTxytmln7gOs+bOfA5+IWSKREMi5wZ4rGCOAYv56KsvWCD2oLtemKKAvE8g3g3D99rDL+2cbwgxBrTc1KP70UzLiK99Dpw79H2YMW2C9XcCrUh4oo2RRE9r7dvlsL3MmYYBXitw08DeG4k2txqx5CGRo5pdmLhBz14+TSJLM1nSaz5/yXhIrTKo8IxXUo4uOpPLuAPsOoRpt4zrFHH3R6wWJMOjH/Q7cCsA60T+gatAvw6PurV32LWa7drm57P/dl9/RDHrUhTI1vWZmMcUX56CiJjrIGOU28qsOZmKryPzCrGzRk5fet6czbDZ0oj/VT8fxsVUqkrPwisGrrB26V3WrBrJx6NBsWT79mKqY87M9nuN7YHaIN30tSxx/Bl80rbi+W2klmZIymI/m9G07ReVdtQd52/UQCQ8A==', 'base64'));"); 
#endif

	// wget: Refer to modules/wget.js for a human readable version. 
	duk_peval_string_noresult(ctx, "addModule('wget', Buffer.from('LyoNCkNvcHlyaWdodCAyMDE5IEludGVsIENvcnBvcmF0aW9uDQoNCkxpY2Vuc2VkIHVuZGVyIHRoZSBBcGFjaGUgTGljZW5zZSwgVmVyc2lvbiAyLjAgKHRoZSAiTGljZW5zZSIpOw0KeW91IG1heSBub3QgdXNlIHRoaXMgZmlsZSBleGNlcHQgaW4gY29tcGxpYW5jZSB3aXRoIHRoZSBMaWNlbnNlLg0KWW91IG1heSBvYnRhaW4gYSBjb3B5IG9mIHRoZSBMaWNlbnNlIGF0DQoNCiAgICBodHRwOi8vd3d3LmFwYWNoZS5vcmcvbGljZW5zZXMvTElDRU5TRS0yLjANCg0KVW5sZXNzIHJlcXVpcmVkIGJ5IGFwcGxpY2FibGUgbGF3IG9yIGFncmVlZCB0byBpbiB3cml0aW5nLCBzb2Z0d2FyZQ0KZGlzdHJpYnV0ZWQgdW5kZXIgdGhlIExpY2Vuc2UgaXMgZGlzdHJpYnV0ZWQgb24gYW4gIkFTIElTIiBCQVNJUywNCldJVEhPVVQgV0FSUkFOVElFUyBPUiBDT05ESVRJT05TIE9GIEFOWSBLSU5ELCBlaXRoZXIgZXhwcmVzcyBvciBpbXBsaWVkLg0KU2VlIHRoZSBMaWNlbnNlIGZvciB0aGUgc3BlY2lmaWMgbGFuZ3VhZ2UgZ292ZXJuaW5nIHBlcm1pc3Npb25zIGFuZA0KbGltaXRhdGlvbnMgdW5kZXIgdGhlIExpY2Vuc2UuDQoqLw0KDQoNCi8vDQovLyBUaGlzIG1vZHVsZSBwcm92aWRlcyB3Z2V0IGZ1bmN0aW9uYWxpdHkgb24gcGxhdGZvcm1zIHRoYXQgbGFjayB3Z2V0DQovLw0KDQp2YXIgcHJvbWlzZSA9IHJlcXVpcmUoJ3Byb21pc2UnKTsNCnZhciBodHRwID0gcmVxdWlyZSgnaHR0cCcpOw0KdmFyIHdyaXRhYmxlID0gcmVxdWlyZSgnc3RyZWFtJykuV3JpdGFibGU7DQoNCg0KLy8NCi8vIFJldHVybnMgYSBwcm9taXNlLCB0aGF0IGNvbm5lY3RzIHRvIGEgcmVtb3RlVXJpLCBzYXZpbmcgdGhlIHRhcmdldCB0byBsb2NhbEZpbGVQYXRoLCB1c2luZyB0aGUgc3BlY2lmaWVkIG9wdGlvbnMNCi8vDQpmdW5jdGlvbiB3Z2V0KHJlbW90ZVVyaSwgbG9jYWxGaWxlUGF0aCwgd2dldG9wdGlvbnMpDQp7DQogICAgdmFyIHJldCA9IG5ldyBwcm9taXNlKGZ1bmN0aW9uIChyZXMsIHJlaikgeyB0aGlzLl9yZXMgPSByZXM7IHRoaXMuX3JlaiA9IHJlajsgfSk7DQogICAgcmVxdWlyZSgnZXZlbnRzJykuRXZlbnRFbWl0dGVyLmNhbGwocmV0LCB0cnVlKQogICAgICAgIC5jcmVhdGVFdmVudCgnYnl0ZXMnKQogICAgICAgIC5jcmVhdGVFdmVudCgnYWJvcnQnKQogICAgICAgIC5hZGRNZXRob2QoJ2Fib3J0JywgZnVuY3Rpb24gKCkgeyB0aGlzLl9yZXF1ZXN0LmFib3J0KCk7IH0pOwoKICAgIHZhciByZXFPcHRpb25zID0gcmVxdWlyZSgnaHR0cCcpLnBhcnNlVXJpKHJlbW90ZVVyaSk7CiAgICBpZiAod2dldG9wdGlvbnMpCiAgICB7CiAgICAgICAgLy8gRW51bWVyYXRlIHRoZSBzcGVjaWZpZWQgb3B0aW9ucywgYW5kIHNhdmUgdGhlbSBhcyBodHRwIG9wdGlvbnMNCiAgICAgICAgZm9yICh2YXIgaW5wdXRPcHRpb24gaW4gd2dldG9wdGlvbnMpDQogICAgICAgIHsNCiAgICAgICAgICAgIHJlcU9wdGlvbnNbaW5wdXRPcHRpb25dID0gd2dldG9wdGlvbnNbaW5wdXRPcHRpb25dOw0KICAgICAgICB9DQogICAgfQ0KICAgIHJldC5fdG90YWxCeXRlcyA9IDA7DQogICAgcmV0Ll9yZXF1ZXN0ID0gaHR0cC5nZXQocmVxT3B0aW9ucyk7DQogICAgcmV0Ll9sb2NhbEZpbGVQYXRoID0gbG9jYWxGaWxlUGF0aDsNCiAgICByZXQuX3JlcXVlc3QucHJvbWlzZSA9IHJldDsNCiAgICByZXQuX3JlcXVlc3Qub24oJ2Vycm9yJywgZnVuY3Rpb24gKGUpIHsgdGhpcy5wcm9taXNlLl9yZWooZSk7IH0pOw0KICAgIHJldC5fcmVxdWVzdC5vbignYWJvcnQnLCBmdW5jdGlvbiAoKSB7IHRoaXMucHJvbWlzZS5lbWl0KCdhYm9ydCcpOyB9KTsNCiAgICByZXQuX3JlcXVlc3Qub24oJ3Jlc3BvbnNlJywgZnVuY3Rpb24gKGltc2cpDQogICAgew0KICAgICAgICBpZihpbXNnLnN0YXR1c0NvZGUgIT0gMjAwKQ0KICAgICAgICB7DQogICAgICAgICAgICB0aGlzLnByb21pc2UuX3JlaignU2VydmVyIHJlc3BvbnNlZCB3aXRoIFN0YXR1cyBDb2RlOiAnICsgaW1zZy5zdGF0dXNDb2RlKTsNCiAgICAgICAgfQ0KICAgICAgICBlbHNlDQogICAgICAgIHsNCiAgICAgICAgICAgIC8vDQogICAgICAgICAgICAvLyBUaGUgaHR0cCByZXNwb25zZSB3YXMgc3VjY2Vzc2Z1bCwgc28gbGV0cyBzZXR1cCB0aGUgZGVzdGluYXRpb24gc3RyZWFtLCBhbmQgaGFzaCBzdHJlYW0NCiAgICAgICAgICAgIC8vDQogICAgICAgICAgICB0cnkNCiAgICAgICAgICAgIHsNCiAgICAgICAgICAgICAgICB0aGlzLl9maWxlID0gcmVxdWlyZSgnZnMnKS5jcmVhdGVXcml0ZVN0cmVhbSh0aGlzLnByb21pc2UuX2xvY2FsRmlsZVBhdGgsIHsgZmxhZ3M6ICd3YicgfSk7DQogICAgICAgICAgICAgICAgdGhpcy5fc2hhID0gcmVxdWlyZSgnU0hBMzg0U3RyZWFtJykuY3JlYXRlKCk7DQogICAgICAgICAgICAgICAgdGhpcy5fc2hhLnByb21pc2UgPSB0aGlzLnByb21pc2U7DQogICAgICAgICAgICB9DQogICAgICAgICAgICBjYXRjaChlKQ0KICAgICAgICAgICAgew0KICAgICAgICAgICAgICAgIHRoaXMucHJvbWlzZS5fcmVqKGUpOw0KICAgICAgICAgICAgICAgIHJldHVybjsNCiAgICAgICAgICAgIH0NCiAgICAgICAgICAgIHRoaXMuX3NoYS5vbignaGFzaCcsIGZ1bmN0aW9uIChoKSB7IHRoaXMucHJvbWlzZS5fcmVzKGgudG9TdHJpbmcoJ2hleCcpKTsgfSk7IC8vIFJlc29sdmUgdGhlIHByb21pc2Ugd2l0aCB0aGUgaGFzaCBvZiB0aGUgcmVjZWl2ZWQgZGF0YQ0KICAgICAgICAgICAgdGhpcy5fYWNjdW11bGF0b3IgPSBuZXcgd3JpdGFibGUoDQogICAgICAgICAgICAgICAgew0KICAgICAgICAgICAgICAgICAgICB3cml0ZTogZnVuY3Rpb24oY2h1bmssIGNhbGxiYWNrKQ0KICAgICAgICAgICAgICAgICAgICB7DQogICAgICAgICAgICAgICAgICAgICAgICB0aGlzLnByb21pc2UuX3RvdGFsQnl0ZXMgKz0gY2h1bmsubGVuZ3RoOw0KICAgICAgICAgICAgICAgICAgICAgICAgdGhpcy5wcm9taXNlLmVtaXQoJ2J5dGVzJywgdGhpcy5wcm9taXNlLl90b3RhbEJ5dGVzKTsgLy8gRW1pdCB0aGUgcnVubmluZyB0b3RhbCBvZiBieXRlcyByZWNlaXZlZCBhcyAnYnl0ZXMnDQogICAgICAgICAgICAgICAgICAgICAgICByZXR1cm4gKHRydWUpOw0KICAgICAgICAgICAgICAgICAgICB9LA0KICAgICAgICAgICAgICAgICAgICBmaW5hbDogZnVuY3Rpb24oY2FsbGJhY2spDQogICAgICAgICAgICAgICAgICAgIHsNCiAgICAgICAgICAgICAgICAgICAgICAgIGNhbGxiYWNrKCk7DQogICAgICAgICAgICAgICAgICAgIH0NCiAgICAgICAgICAgICAgICB9KTsNCiAgICAgICAgICAgIHRoaXMuX2FjY3VtdWxhdG9yLnByb21pc2UgPSB0aGlzLnByb21pc2U7DQogICAgICAgICAgICBpbXNnLnBpcGUodGhpcy5fZmlsZSk7ICAgICAgICAgIC8vIFdyaXRlIHRoZSByZWNlaXZlZCBkYXRhIHRvIHRoZSBmaWxlIHN0cmVhbQ0KICAgICAgICAgICAgaW1zZy5waXBlKHRoaXMuX2FjY3VtdWxhdG9yKTsgICAvLyBBY2N1bXVsYXRlIHRoZSBudW1iZXIgb2YgYnl0ZXMgcmVjZWl2ZWQgdG8gZW1pdCAnYnl0ZScNCiAgICAgICAgICAgIGltc2cucGlwZSh0aGlzLl9zaGEpOyAgICAgICAgICAgLy8gSGFzaCB0aGUgcmVjZWl2ZWQgZGF0YSB1c2luZyBTSEEzODQNCiAgICAgICAgfQ0KICAgIH0pOw0KICAgIHJldC5wcm9ncmVzcyA9IGZ1bmN0aW9uICgpIHsgcmV0dXJuICh0aGlzLl90b3RhbEJ5dGVzKTsgfTsNCiAgICByZXR1cm4gKHJldCk7DQp9DQoNCm1vZHVsZS5leHBvcnRzID0gd2dldDsNCg0KDQo=', 'base64').toString());");

	// default_route: Refer to modules/default_route.js 
	duk_peval_string_noresult(ctx, "addCompressedModule('default_route', Buffer.from('eJztVttu4zYQfTfgf5gawUpKHDl2sgs0rltkc6vQxFnESRaLpghoaWQTK5NakoqcJvn3DmV5fY3bvvWhfLBM8nDmzBlyyMZ2tXIs0yfFB0MDrb3mjxAIgwkcS5VKxQyXolqpVi54iEJjBJmIUIEZIhylLKRPOVOHO1Sa0NDy98C1gFo5VfPa1cqTzGDEnkBIA5lGssA1xDxBwHGIqQEuIJSjNOFMhAg5N8PCS2nDr1a+lBZk3zACM4Kn1IvnYcCMZQvUhsakh41Gnuc+K5j6Ug0ayQSnGxfB8Wm3d7pLbO2KW5Gg1qDwW8YVhdl/ApYSmZD1iWLCcpAK2EAhzRlpyeaKGy4GddAyNjlTWK1EXBvF+5lZ0GlKjeKdB5BSTEDtqAdBrwYfj3pBr16tfA5ufr26vYHPR9fXR92b4LQHV9dwfNU9CW6Cqy71zuCo+wV+C7ondUBSibzgOFWWPVHkVkGMSK4e4oL7WE7o6BRDHvOQghKDjA0QBvIRlaBYIEU14tpmURO5qFpJ+IibYhPo1YjIyXbDihdnIrQYypqIZK4fIoxZlphrSZG6XrXyPEnJI1OksIEOiCxJ2rPB80saK7V3nYdzFKh4eMmUHrLE8Upk8IlQ55f+sUJmsEu0HvGTkuMn1wnSYZKylPtRMo8voZdohjJynXM0QXomFWUrurGJLaAzGpr/ifMu7pjiFuYeeO35CDTFRjiyv2LR3asXZurQnK7hsTtZ4t+xBDodaLZa3mSq1GVq2RSbbR0Ba9I38mMWx6hcz6fZ6JYO6n7r4tT1pp5s28yu8LDCcC3LPW82OcdzyhUF7WTU5Kiw6Z+gwthGf+C9TbS9akfJfGl0sUfb1rU43tlr859Kr+2dHe4t4pYoFlLIfIneAeyAy2Eb3n/w6vanvbqKx+DSyn8W0LJQG9jY1mjAyeRoQHE21qMsgx/sOXl5scfFHyEFHcLPMKO1/2EzrzWUNtAqxCrO5TNVNoMqZiEezrlr/o27Okw4Hv4LivC6RnzbXleHl4bmuuXf8kNBZEpQ/tDY1L4uFKeEi2y8qTSFQ55E84WoGHhIlQypujqej2MMz+jKcp1Gn4uGHjp1+N2hzx/TjVSs8LWhSql8KVwnYoYR6jsJN/RI5NcVPNGhjyLvjtNeHH7bjL1Di1U7HQhJ6R7lQAzomK1xwIVvbyzizlPKEkUPL0D3WQqlItRl+Ve4d55tLYCtZqdTK6dq8O4dbB0UA481sK5T8mRg6z25gtd7517gmJt74Sz6zRk3pzTx/eRPE7Qct0/MR5Pj5DjwS3E/wOHidnxjzWzvNSdhL2a9r6P/c+4INJrucdgl8XdjUtVWl7fSX+a2e/afzKymp2E4dMsM+WnCDN0Ro1laQ0avHYeeIvst53BWKUYyyugioLeSVMbeW+seK3MlqU/l6mt73mRRQDaaXC0xGw3G9Jyk/Tk1ORmMmCJmG90s7+k1Tgqp/gL2YXjV', 'base64'));");

	// util-language, to detect current system language. Refer to modules/util-language.js
	duk_peval_string_noresult(ctx, "addCompressedModule('util-language', Buffer.from('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', 'base64'));");

	// agent-instaler: Refer to modules/agent-installer.js
	// Embedded from modules/agent-installer.js.
	char *_agentinstaller = ILibMemory_Allocate(17993, 0, NULL, NULL);
	memcpy_s(_agentinstaller + 0, 17992, "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", 16000);
	memcpy_s(_agentinstaller + 16000, 1992, "FUFTPWxQp6Ct7pvswWCTe5Fe6oe8Eo5pmcgKjc9RpJI4e6Ryydh1brZ1KqlVcDqiTFMvu+fBK5WabeAXJafU/kzlsOs7spNm7vBqIB2q6tnd0Wsl0q7BxJdPaQxSF1VWH43EXJlCHSr05qMYjbm71WUkd8293MkqY1hmsm3QzonLBV18u99YK83fqmX1YRHst4F1855CiCgcfS26NJ6UvohGhsm2QhpzNyQeQtXtWFiFiZUW1cMbe5OHSuJqlHstERk2tXIlYEP1gYVdmO6dm8ZXcvlN0vDC6myY2Bx3uKkCupk7s92sZGfWfntwmCyP5doq6jR1V/8JpIB6qlcOQ167an3JWL5I+UdSDgIbtlI5U2qoZkmLBAdBHqSnou4ofaz6Ovjmsb1LtoqkDkh6Yi9ShYzUPaUxcvTYVH6Xl3yiTygvcqHvFZ2K63S0tL0/xgvrF1hXFXtPsSjStiq0KrUomdU1gt8zuhjK5Akzv/OyWqUoa6WYSXbyz0MNMn/Cb5y0xTKaKhtxlTAfWqVBwWdYuwKPRRsSIC/vY1cRy+PrVt/4zG9+9C7w3N5WFz5iCEvLTZabuAg20/bdi0Pa2e0qNn5o2TiTZzc4GxzjUVuYK2eIbXTR3+juxYBW/QeZh9nVZhtpMa6J2ApHTj8sG869j6+ZMv1o5yqRXeuLXf2qM+Fi8W88YXV72wEQ2UNq6G8cqTFIgqBYNyC57N4r0OfionELR0XWi91etB2r7mKlyzQPz0BgpXPyB1HRWvkuqy6Lou603om5oArPyLYoDJS+o2wTOWle3c+dccWiO1falhlqgiZm/3LBwxU3NtmrdfSiqI8w8AclPgr+6SO/lXHqo5s0B7nPg11abt01C98H9Jk3DFru+4iPghdssfsA/duEvPeIiUYdJWjyyAvLtl8EC2ZpsgmBvSIjXvtT8R70jCKmWB5p+HLDMCUrjqNXyl4vQHb8A0bmLGGc6gnJJLZOILT1UjoBQHrIhlMVBZLeFgjurShRcpOpiDPM1HMKbBYykzxLp7w/dddOWntXoZCyGp2Y23tQGHCSHksxw0RIXQEpcSRcpXMcOouKQX1qfigt0JW45rCBCcB7enZCF4YVdx0vaHZUzGZZ3bhIxPL5rD6m2wS1ZWC1BZ2sArL9BEXftG4QVYLv3TDPCVZrmVPJNF2yza2fqObebX52A73JXHlq0aPRm+1KWmGnIYfJT3WxOGne4sg2QbiscntWCrA2DC4W4y8JYv+iOwcNBM3KIy3XqtgvVt0hEmjVWXVcsptOlXJN3yfhxI5VtwLakQNsqPlxWCuTZhfFhnQhioRKvTtsR4kTP4Ki9ooKLOjhbZYpfHUQqcrvV7mTCbW5b6iZLaM2AKFUZ6nwShFqf7BEFJW9o28u+RS6/tBSur0d56FEXZTZNa5Ga7EvCS9r9gWkb7ox9BsgDoUBtTQGA+EI4wsNlyZIvaJcJ+ddmYVde1mlhrXLpr/p7ZRhYB06bZSuacbPM/a9F6xWz20CunHDShQQpbwj1Q+NW321lfPxZwSFK4lbBX+7t4rRKfi58eAhK4MMozFmDZAHKnldZDEUXP2mza8UwfJX2UqZLfnNJvIYqO15+gDtUNeCcU3t+uo2vTT8abNaNhOoRjfZdNxvKytGb/lmpQcfVIeUGS1GeGIzMHrROz8CkWEAVDeFxVJhMX4fqAt232bX3HUbIziajVd1SU6fvvsYViAey+oClshG8ljKKvrqyWE0Yrq9TYHR0o8vGckBsGchHSduEoT5hAQH05v86i7N6lMivV34x68HlZ9Z7i7bf8ym004jVvGTxsguu1ak4+MjgRnNVOHRkKnYUmBrRJCpdyQ9Sf4InsKVVefpecfWNJIjhHzrkpC1ac+3DaKtTF8lNVyuthA6O1bvHlYplw5QlFgU3SVezItWxg9X7kE47wOGGbzGzJh+YDrBnjUngBFCDAJ237r9r/iG1/uIG2ih83brLeL5/wHrUDKa", 1992);
	_agentinstaller[17992] = 0;
	ILibDuktape_AddCompressedModuleEx(ctx, "agent-installer", _agentinstaller, "2026-10-06T00:00:00.000Z");
	free(_agentinstaller);

	// file-search: Refer to modules/file-search.js
	duk_peval_string_noresult(ctx, "addCompressedModule('file-search', Buffer.from('eJy9V1Fv2zYQfheg/3DLi6TOlbP0LYYLeEmKGSscIE4XFNtQ0NLZYkqRHHmKbRj+7wMl2bEjaXMCbHqRRd7xvvv4HY/uv/O9K6XXhi8ygovzi3MYS0IBV8poZRhxJX3P9z7zBKXFFAqZogHKEEaaJRlCPdOD39BYriRcxOcQOoOzeuosGvjeWhWQszVIRVBYBMq4hTkXCLhKUBNwCYnKteBMJghLTlkZpV4j9r2v9QpqRoxLYJAovQY1PzQDRg4tAEBGpC/7/eVyGbMSaazMoi8qO9v/PL66mUxv3l/E587jixRoLRj8q+AGU5itgWkteMJmAkGwJSgDbGEQUyDlwC4NJy4XPbBqTktm0PdSbsnwWUFHPO2gcQuHBkoCk3A2msJ4egY/j6bjac/3Hsb3v9x+uYeH0d3daHI/vpnC7R1c3U6ux/fj28kUbj/BaPIVfh1PrnuAnDI0gCttHHplgDsGMY19b4p4FH6uKjhWY8LnPAHB5KJgC4SFekIjuVyARpNz63bRApOp7wmecypFYJsZxb73ru/Ie2IGtFE5twjDHYdhUA8F0cCbFzJxq5Q7bpGZJAsjb1NulFNC/O129ogJja9hCIEzmpZGwaDaTLvklGQQaqMStDbWgtFcmTyqpjfVyz0JswjBkssPF8HlfnQfZ85lCkM4wCPT0ChFPUgMJzScRUdem6Mv97hsDRIMQeJyl3e4XzE0aHtg8DGCTZ2bQVvyYgf7gcdy4HEA22jQiLBnEJ9Qkg2i+Mb9uMk5EZo4YUKEBqkHZAqMGu7uiRODjLD0CwODthAUnGKKMg1aIVGcuMoUh+xVI2Fz3SZr2+aaFume56gKOmAvavHdAcCcdyPcGTlyw+CBy1Qt6xOmEhxkKDSaug5dXbsqJS6AgWTEn7Csca2NesIUTCFTIT5cQKIkGZZQWVuYo6wKAnDFLdm4Dcu2B+ftJBamVAi9mH3Bzswg+/48lOKcFYIu/bfp+dht4//3im6GeJ2km/7QqelTbCvJtCdeiWNkFi6j3wNHYNADR+GfLR583jiDYDiEQHBZrIIImh4tfEMp/l3YWBc2C4P3tNbYirLVfH66adhqum1LDsKRMWwdc1u+w72GWmg+OTHJ8tMT20WMbcbnFEbOr91zmXGBz/YC5YKyj+cdguhA245YdcJ9Q4anZtnm17JJLUMoLP7f+/MKSf1jwWyagKIgGrStVfagjIv08JJRDnyrQwRRjCtMPjlhBP3Cmv6My35d0s9x2rA7oAcBhiALIU5Xfd15bNjF49HZfxJ1ezSxpVQVFFsy7nYUDJpTuqSEWg/eF6ZKhkHKiAW9564RJqdnWp73DsqPQ0hiUlMyXC4683ZHrOCy7Bc719hq4Tr5H7JTdmVxQ1h61qUNH+Gn1xd3GVPXV4e6Z/QqRG8oviMChvUyWunW9Dsa4cF+oDFd+wGbf/N3jrji9NaNdIqvc9nJKybD8zCCH5zM9t1+p7GXJLY7t9fuAXFHi3V15qZ9Z3V109R5X32d2Cu6v3Mh2uO3Ru8q9u2L7+qqV41tfW/rul2u0kJgjCutDNn6Wnb4z2ng/Q3oGBEE', 'base64'));");

	// identifer: Refer to modules/identifers.js
	duk_peval_string_noresult(ctx, "addCompressedModule('identifiers', Buffer.from('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', 'base64'), '2022-10-27T08:44:49.000+01:00');");

	// zip-reader, refer to modules/zip-reader.js
	duk_peval_string_noresult(ctx, "addCompressedModule('zip-reader', Buffer.from('eJzVPGtz2ziS313l/9CZqxpSa5mWZccza40y57GdW9d67JTtXGo2m0pRJGghoQguAMV2Et9vv2qADxAEKTmZrbpTqiILj+5Go9EvNLnzl82NY5Y/cHo7lzAejUdwlkmSwjHjOeOhpCzb3NjcOKcRyQSJYZnFhIOcEzjKw2hOoOgZwn8TLijLYByMwMcBPxRdPwwmmxsPbAmL8AEyJmEpCMg5FZDQlAC5j0gugWYQsUWe0jCLCNxROVdYChjB5sYfBQQ2kyHNIISI5Q/AEnMYhBKpBQCYS5kf7uzc3d0FoaI0YPx2J9XjxM752fHpxfXp9jgY4YzXWUqEAE7+taScxDB7gDDPUxqFs5RAGt4B4xDeckJikAyJveNU0ux2CIIl8i7kZHMjpkJyOlvKBp9K0qgAcwDLIMzgh6NrOLv+AX47uj67Hm5uvDm7+dvl6xt4c3R1dXRxc3Z6DZdXcHx5cXJ2c3Z5cQ2XL+Ho4g/4+9nFyRAIlXPCgdznHKlnHChykMTB5sY1IQ30CdPkiJxENKERpGF2uwxvCdyyT4RnNLuFnPAFFbiLAsIs3txI6YJKJQSivaJgc+MvO5sbn0IOp5fHJ1cwhd0R/hs/P5jodt26t3ew99fx/s9F4/lLbDz4aW+8/9Pz8QTZj805ZwsqCEzLXfC9oskbFDPjZZ6Se3OEkJyEC28QnKguBSxZZhGSDNGcRB9fsjQm/FUo535MhBxsbnzRAkIT8HPOIiJEkKehTBhfwHQK3h3N9sbeQI8qBuMHp8NUfQUiT6n0vR1vEHxgNPO9f/5TUYnjHvUXSQVZBwbOLIDs2DBw0ZJ9JJloTuqhG34FBAmHYICroc1CxWINNBBzmki/HHU3pynxi66UZLdyDi9gt80JBWRrCv76hMCWhbNEqrfCf1ZtaSK8QUDuqZDi+iGLfEQ2GNSDDTrw05y3+BhTXk8zcDxWjH00RITcSx5G8oLcSz+3ZCPISRbT7LZkxXQKowF8gTwQbMkjEkQpE8QfTCAP3nMi8C9O5JJnE3P/MnKPW16Dy1muWK6H7OzAy5CmoIAptRCRTPIw3Y4pJ5Fk/AGw4QGycEEEyHko4Y4t0xiIiMJcn3KUDZqpkwqJkvigAn9FPpBIQjgTLF1KAnko52IIMaefyHZKpCR4+EhC74kY4rkHLwg8kDz8RLgIUxDkdkEyKSBMJOEV3IzxRZjSz6g5ZkzOQZA85KFkHIR8SIkIDCYUY0l8qtYyVWzpPQI4bZmJMCHllCRMBZnUO2QBDaJ5yI+kPxooKUSh+2JBkHxJGpuTUC6k6j2ehxzJ6oJp4H1mAv3xx9ac8uhMYezqLkDuajIPPfjxx1pMfd8i6cUUvCMcY9P6yxS8f3gD+PoVXHPCrjmfvcGgfaQdfGpoInvdbQjITiWo16W4tLlZq81Jc6Igt2dZrBR42YwGyy/bYQqjSTUKfmliKjg+ga2tcki3wsCVNGa/Lee8UxsSBJ2CM+Mk/FjJT1OrlKB7edRSHWbXe04++N5rNR/+cfaqOPZ4XA/Bgy11ZMwphbKpSKjFujAzeYBaUFtA2Oo1dy1tjcgMmf+/bikjlgmWkoBmCdv1vVOt12l2q1mnTH8xQ/KHFjanq2BhCGU098m3bCpZvWt58F77MmrbCoC3RF6rRt/c+jx4z5YyX0rTEVLWL+IklOQNp5IU83AdQ/gCSRreikPw7mYePLYABWhaCp3c6qv9srzVxzLfU6v2hlDZVL/NIpQg9PhLYOVig4hH8GwKjb6SmzzSc5C4HgegCVedoeOrYzjGHYUkpCmJG+qmtQfGHitpNFwCE3YlDgb7ilXkNCd+xRXsf2w4op9pnpP4coZ22JcYUgwhiWt3Q6F5r/vPTgCVNM23OQnRjpuTvYk5QUFC5YTfk8ou38wJhDya00/KL4g4zdEmz0jKsluB4YsKvpiCCOQTyeBuTjLIWKFxxJJ/op9IDHnIBXosJtKXSF8SF+g0WUFMEpqRV5zlhMsHxbYheBjeCW9obtgtkYdtSXHsKmoxTlDE376btLuo1ZYw7lMMywzODJpDLASFGAT5Usx9Y9Zb+k5LnIXh0SVB4HMiXV7mwNwoFPJpvWoUbIWhdUxKoCY5OPIdgqjkzwQt6GdiwsbfTwa+zDDyxhCSxNf0M3FiqnSRic5QUE6caquyhMEUWmgb/j/4z3AcGl455+wOfA8zBQlbZnh6az1pyMbEbEMQCCEol4LkKY+9U8Qsk3HB4Lie+8ylM5SKvCvCUH+leGGKgJjiHs2X2cchJOlSzAft8Q4QDjpfhULs3Mz5Uls2BbN0ObfAg9mDJKJFffkxBDLi0d64pKls75pHk0Jw8Lxc/t1Bfc8KKsTF7FIc1NlTBHShBdN49ONegR8/ivF+H66aUjUWN3yZpj0THru7arfmG0htEqG+n05FR3M3Yav3T8ewJ6EM19y99RfioPZx2G5LaBam5ql64nFaU5xWsUKtHoWjb/H9Avfnbw/JYhI347c1kLq4jM6HyWQ0LOvz2D7s3eSonFO1IYZ0VfmnEcaxfqf6aM8sE0yDbl32vRJQacMu2VsDBjQPB2aP/r/oJbLAcCzmIc06DU0PER3NDsG0XDCHSQ5myyQh/HcWox+06xhgyobLndRjSsEyc0yNEeXR6hzQszHYr23uyNGTh0srbDSjkcZmtXKfjRiw9uK2q7y4DglPSNnHuP8F3vx2dnN9CNu7z5s8NfCqJRWuG35NrC7UD9c0+2h6g1WjTzgfakfkioTxEPQmreeKjX0P4SjnpgJRezbw9vTqSrs+hGNWw3vnDWvUgSBpErxXQ89JIm2RwbOP5GHUiTuFyqX4OdK5tBrnL1OtfDqBo3YarA4zrPn69BDOGfeGCvnXr+C9zsh9TiK8GiJZjPdaVQrIecZaISy0D0w34dvTmreT3knKifX1BgYC78/8kbG3A0fg38OKnR04YRmBN/XtmTI1KomtMuWzlEUf2xMrjVuvwfLue7BC24s+ubw4BVwAZq9vMB7mJGK8nSowKL9g8DvjBFCT9Ng9ksVOk+9Qe25V3LGCnZ0aPdwwRf3qtY5974r8a6nuB25rAPoEWSwdWpmILl40s064f8XmqAgsiTHjpCXmsEShfg1BW/VDGzG8gP3RXw/gV/3V7ne5KA2mV1K7BuebOq9LsynxV+pV2kNSFoXp31R6pqUDrb4nq8KVCsrQT7A3Ui36cCLhr88yuTc+P8VLkGdTvGpdQz1ZJPdpqbPsU5jSWOkmNQ3mat43q6jmsexYyVSvZNI31fsvkhEepvBqyXMmCLxMwyL5a0HdPTg/9Q9a3qEFzsgFwO9EzlncDeznVcBe0pRcYI71vJD/LkjjlXSpzPZqOG2S3Nusj6yZAcLk6dQpU7v7g0bOxUGdoWokK4IIpNHvwN6tAVZNGFjJjiZZ6hIklOErJqg6l9Pe9bMkEUTCFh6ozo3pZrXDx2gg3+pF3ky+wYvewUViV+//n3O2vfquidxLksUCZuSBZXGZRf7mw+2wE31rS2KHlu8whqV56RITbW/cc0sj9KfLZAe+vJCDw4ZIuuLwLgwu49YyXK6pTvvFsoiU4VuH++a6YzFdLzDsfVN+J86ZajtgCr/pAxSmKYt85OoKbXeubIxeFPyn4bMYx3YFCNh+USV2SQzXOmPu8H7a0eX6Xk5jXXujwdDY9BbBuNG60dqyxva27wwbtw2N5HxxZ3WUpqYvUreqe0B9vem+nFt9veuQCpW2ryEHNIvSZUyE7x3iVS0m8+tevD8skER3sT8oLmV1p+tOHVZFvzZ6IUMuxRsq5+p++DvQ1z/su6b6WgovAoqbQb8+QhxLaDj5oC8ytF8q1CEUk6rhg2r4MGnusbIa9WpQD6u1rH1p31qwyZvlDEsPs1sM3oz2Isu2DbuDiR3+63vY4qxbKsSoKzDxWKOKzIuddVGVHfVtnbom7CvwknXpVJXxU5Pe0ndW+sIQHeMa17qkW3Wa3tcHR99uiXHDxW934yYtOk/WQlPbqCPrXO7ODma4qZgTK7hTgFSdmfqLE7FMpbCVlr7HaRUigMtiG/ttgtRc/qLqzQ7BoF8VrjWFtjmPkI/+IKjqGJr3hr5rrH3T2g0v0McOB6w3HmsT0N42TFy0dg7q5OjmqLhhKzbO5eZV5g13Vd0GrHTJjCml2YhYFoXSfxu9s3FYDlU7X/A0BFXXEHpxrbnHiscki9f0IiwOn+o0V7TknGQSypSlS6BRB1gUVC5FtaauiZ9dB9ovu502t8O4FpPdNrbodFS//BuNBq5PHc6SEeqHNaDgnK2GFW/a6r1LBT5Zi6LHdN6TKXH092dL3IUFLjhBkbKuJzj9SgzL4Url/dBLbFUlIjNRQ50XitsZFY8bPqztfAJ8T16iDe346nh7b4znxozZVWDhBFoG7iugfnOyoxtW4Wv3ULUK0mtzhf2wxuMVsM5DIeF3FuOjD7pM+oYu3ADVKndHTwZ4Eso+gKso1Imdl5Sk8VPTO45IZVWM0hTtAYYktUIiQ5gNIVm7dAZAH6WLsGRpEkh2rR3OViLqG6jdHdkUjocwGw8hGa82uL0iqpLp1+EiT0vKxzXp3pzcey36H1ebDKdOKuJxQ90WNqgx1FSRVtf3FVl1E9Z1zffkbbICX2fI6yDAZKHBGOXFNgrntFvrdLOr4sRnLT/METbKh5yoJ8fKisYpeNlyMcNENnyxq2oRrXqmpBzfjJVq5qraSMf9b7Nc0xrQLCGvUGNdpkT0p/jH6YLicxpBFKapIqNRYIhu2P80nbDSlaieUXlsl6WqPcXy8roS9d/kqhg81wgVx3VE6qgfV5F95wNBCkB/vKjLgJVOMssIXfGQq4TTTqyRrFVqLWQoa2pUHaadj0vi1iyWk6yaNbTljGVChvg4w+X7q5PLi/M/1qmTNyhEoOWjEC5avkB1s3cIXiIKH/qkqhH2htW51gTWZ3lUKbhKUGXwXhAp01ZZhMaIDzWZ7h42+JyEgmV9R7gAqY9h42Gq+iTVaK3KotbZxnU3zzamuVed8CTGA6Mr/sGntxnjmqLHNi0oacWqLEug2BDFDY2Ov5/k5JZK48ujtcw17wifVU5ral8ZWOcGSSvSzWqr+gsTiofUoHpI7Uk19lXw1l1XYEwsasQa61ClF706vjn8F9g/6LorVVelxydXuMM2F7xXIRcETtVdSfsBP3Or+iKFjpsi9cxU0jtpb+SaFLFF/6yxa5Yucagm7h/gcz411Vs1LVs1BkfWowHnhSVgLibe8CUmIEjslp269mIVf22R2T8Y2ssYGK6ngwc4UOdGVgJybhZaO/ueuoiL4EcYj/Z/VsYN/1h1WXpc8OGk4oOORQ9bZ6ntwhZP23eHCPurLpIB4Hea0cVy8R235B3xrfiOu3IMhV5eFxVeSSvB2R5dRx2u5zb6QujXTwih12HFUwLWdfZn7VB6PFoDmnKHnhwHj78d8oqAeB0O4MsoeBamcCSLNyf0iNbeOnt0er8eRMXXvXWktXFHGcpuaPttXnaaLVv4tG1fnfutQz+Ytrs7ZpUfnfHH/3vKrZrXvYdd8tgDwX7eqAPGfh8MHVa6Z+6P+2Ym8WHDQLmKDspPo9qiMS0l2Ro8Uhq6I73UN51H7pXtHnTUmj9acmWZT7e/ZZrxzgjIWHOn222MwfspDB1djzw2uD5wusuE2Q6zanmSy6yXZaVy6be5z7/AeNzjMiviXE6zLqmJt1my3X6dgyYQXwij3raCIfCf7jvX44vbVisOgG0YjydA8V0Bowlsb9MVJYkF0RZaOhjYvvR0ql8Hs1pZKbjjMWwVHLG85dFgAC/Krtq5jFgmaWa8x8H82HV3GPjDNRYGoL0/PT4p0/2qKM3mCDWKyiDhbFFGPJgtdVZBWfi2uz7rTAY4oeIj/Ic2IC6WtC2mE8yFinaR7i4PU+B7RtRTwDEVUTfCtvlzIrxhMkwhW422G9Nu24NxolLlOy4UTtBaaY7tWsGVWLr5Jubq1SszfNVUZYQ6MWuHpI1QhXAaR4WiKEzqWIGDaheQS51t7QDTqraC4hS6acHHH75+7cKx5V7Bi6ZWTEm2fo1+W582Co7bceMMz3f3w67OGkVwl+K7ahUb5HSnvV18aCTCOziI9X4miijm31JpafzpYOA3WiI7idWuJqztdbtPZ65oWqUaqizlCzh4/vz5T/Br8X1YdVVgW/tQZDA7+V9janC9wrlt0vI4NCgf1GtZ8qzMBDez5FT8g+ZWmlwnQVbkg1V9fp3HBF/lSAfN9w+tzBF7fNZ4JdIHoaItu5TSHFK7LzZsVUeKsJGbGhJytZHmHTg3ok6RJoZ/oQKWGtsU9tGX0oDfjtT7dEb3z0dG427RuP+b0TguGkd7RuNe2bjf8y4DvqzfVmBuZcXsYjcXLF6mJCD3OeOqEuJLUZzOlTup9vhQfynR/1+plhWt', 'base64'), '2022-02-01T20:15:31.000-08:00');");

	// zip-writer, refer to modules/zip-writer.js
	duk_peval_string_noresult(ctx, "addCompressedModule('zip-writer', Buffer.from('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', 'base64'), '2022-02-01T20:10:17.000-08:00');");

	// update-helper, refer to modules/update-helper.js
	duk_peval_string_noresult(ctx, "addCompressedModule('update-helper', Buffer.from('eNq9V0tz2zYQvvNXbHwIqVSh3Bx6iMYHVVGmmjZyx1Kapp2OByJXEhwKYAEwiuLxf+8CoGg+JDvtJNVFJLHY/fbbFzB4Foxlvld8vTHw4vzFOUyFwQzGUuVSMcOlCIJfeIJCYwqFSFGB2SCMcpbQX7nSh99QaZKFF/E5RFbgrFw66w2DvSxgy/YgpIFCIyngGlY8Q8BPCeYGuIBEbvOMM5Eg7LjZOCOlijh4XyqQS8NIlpF0Tm+ruhQwEwRAv40x+cvBYLfbxcyhjKVaDzIvpQe/TMeT2XzynJAGwVuRodag8O+CK3JwuQeWE46ELQldxnYgFbC1Qloz0uLcKW64WPdBy5XZMYVByrVRfFmYBkEHVORpXYAoYgLORnOYzs/gx9F8Ou8H76aLny7fLuDd6OpqNFtMJ3O4vILx5ezVdDG9nNHbaxjN3sPP09mrPiDRQ0bwU64sdgLILXWYxsEcsWF8JT0YnWPCVzwhj8S6YGuEtfyISpAjkKPacm2DpwlaGmR8y40LvO66EwfPBkHwkSnIlaRtCBcH8qKw/BRSxIPBAGak5COFZY3CJFLRU2KDrSkNQOAOijxlhvAqJvSKzBTC8MznxkG5RmMoQJZswmaV4ieSTyw6kmSGFJEflEuC6w1qiBhow7KMmCbOkW1d/EhUyZ11lum9SCAhiSVLPvRgW2gDK8az2Dk1+X1xNRovrhfTNxMKyPWbOfn3w7n9kU+rQnjLZEKZyOP/lZlNL7h1mWdVKDS0x/pXOhFV2yJlXVF404Nb52d8TV8cg3pYfbhxH26GcEc8Wq1G7d2/t2F/fAXRk4r2zzx/Tq5SpMJezPUfPK9Ds7YIkzMV9Yb2uVAOi6G3u0pnKcPSI4FtWLAPdQMepFeUMJNsIMKa0Rt6q6zS38GmWzZ8i7KwhFGkF/6lxlev5bfdY7ekl26PUQUOq0WiyVktMa80YS1ExsWHOcW8hhi+g/C6EORUjmloSTjg5mtBeZpa9B1ibiIb04lSUkXhW5+69WS0sIDgh70DI/0j6VSutcmOqcTEvePXHuwGMyrOyANtc+Fq8Ctnmv3lsS0H8uWC6iLT2F6x3w9m7DuFt5K4R3fIUmfKKyxzgtKgnnYucvdCnag2FGlZKJoPT5/6LSlS8dqXfY5uFlQiFPic55TDFxAe0IaOC5ckXcmoUngqH1qYK0xuT1Oz/RSjSKMv1OW3+jDHSSYpko9m5bfM+Comh/KtVu6GjR5UQraTXMcZijWZenIB35/KCJ9BVD6Chhcmdh4mko4bgoYCjVZS504FYd1i9YSUjCf02logJWo/Y1vbuOq4/jz/a9hmrfHeVOVhusy6aFGbUMEafEfzH+dutpxkuE90rjK21i8h3C3DRn01nWo0zUdhlfU27Cwdmnr+oCHvV2y7BTmXD48teg8qDo/K1Kmuno9KShGFaFsmUXLfnLDqShZK5VWHppoSVxUNJY+xVRVoZcOn+VcumhMtrYvAnW/RPNQHj2XncecOSU/Dp2DZnH/GTrbSGcU87FGsad/wqG4Lvaabato5UtaV3ec9q6Lf8yGlUxbUxuTEz0d7LvYD0+4EGlVbS2TYO0ZAl7myUScqaQOhT/8Nx/hq/AUwGqbKtnxasBnlo4OsK1+eyjpSXUD1o9Wx2mnWfe/f97xyuFbdc42mbHP37A5P7nuo1PPTJd5Q4QZxXk7hL2mYLd1Hhka7Md75ttE6b3UOmkmGTB3Oo/WTaq85AOsH0lNDjy4ti015DQKW2VMfXTKXdNWSwt4q3X2HLiMkMIRUukuyQj9sgJv4fxv5ZVM6wmI9fW5bexoTkm7lr6nRPoilD53LQ9Oaw3n6WPmNKegeeh7l5lteO3QU2jwJW/nrOWrV2QNZ27yN2SoM6uXhLoPBXRBsZVpkGNPxTCpjLwy3/rL70v/ZA+A/MCxV0Q==', 'base64'), '2026-10-04T00:00:00.000Z');");

#ifndef _NOHECI
	duk_peval_string_noresult(ctx, "addCompressedModule('heci', Buffer.from('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', 'base64'));");
#endif

#ifdef __APPLE__
	duk_peval_string_noresult(ctx, "addCompressedModule('mac-powerutil', Buffer.from('eJztVk1v00AQvVvyfxjlYgdSp+qRiENog7BAiVQXEKIIbdaTeMHeNbvjuhHqf2fWcdMUAhISHxLCF9uzzzNv3r5ZefwgDE5NvbFqXRCcHJ8cQ6oJSzg1tjZWkDI6DMLghZKoHebQ6BwtUIEwrYXkW78ygldoHaPhJDmG2AMG/dJgOAmDjWmgEhvQhqBxyBmUg5UqEfBaYk2gNEhT1aUSWiK0ioquSp8jCYM3fQazJMFgwfCa31b7MBDk2QJfBVH9aDxu2zYRHdPE2PW43OLc+EV6OptnsyNm6794qUt0Dix+apTlNpcbEDWTkWLJFEvRgrEg1hZ5jYwn21pFSq9H4MyKWmExDHLlyKplQ/d0uqXG/e4DWCmhYTDNIM0G8GSapdkoDF6nF88WLy/g9fT8fDq/SGcZLM7hdDE/Sy/SxZzfnsJ0/gaep/OzESCrxFXwuraePVNUXkHMWa4M8V75ldnScTVKtVKSm9LrRqwR1uYKreZeoEZbKed30TG5PAxKVSnqTOC+7YiLPBh78VaNlh4DtWnRNqTKeBgGn7f74Dc6eb9YfkBJ6Rk8hqgS8miHjCa3G9YBXYlYM2iXsgv4dB7Sp/TXlbAgC1Xmk7uYY9fIAuLaGsl6JHUpiNuuhneQvQz+koKViXJhW6WjR/fXunVfgen0voijLvC+LxANE7xG+ZRdHEfjpdJjV0QjeBvx7d1w8p10iaPcNMQ369WIJvfDRsdMiAQn2okQy6LRH4fwuReJv3z4GLpgQiZjT+l1PJzAzQ+LorWHivrw7yuqdOInhQUyTjhpFY/6EcJlxIdMeTtjXb1BtnGEFcyuUJMb+DHrNv8yutR4rehSR9+v1ApFMwbFhyBLi+LjV/EcV6Ip6cCeU2FNC3HUO687sfxYYcW8toPbHV637jrI6uuSN9vHmz2r88iSsLRv9j70U3b/7/bDRf+y213RcIethiPLDmr/tHl3Tvpt9t01uH9Y97H/5/U/5eDibzj4zku/2sI3/o+jMnlTIvuB/3LJscYa2/3/l8kX1l4yWQ==', 'base64'));"); 
#endif

	// }} END OF AUTO-GENERATED BODY
	duk_peval_string_noresult(ctx, "Object.defineProperty(this, 'wget', {get: function() { return(require('wget'));}});");
	duk_peval_string_noresult(ctx, "Object.defineProperty(process, 'arch', {get: function() {return( require('os').arch());}});");
	duk_peval_string_noresult(ctx, "addCompressedModule('code-utils', Buffer.from('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', 'base64'), '2022-12-14T10:05:36.000-08:00');");

}

void ILibDuktape_ChainViewer_PostSelect(void* object, int slct, fd_set *readset, fd_set *writeset, fd_set *errorset)
{
	duk_context *ctx = (duk_context*)((void**)((ILibTransport*)object)->ChainLink.ExtraMemoryPtr)[0];
	void *hptr = ((void**)((ILibTransport*)object)->ChainLink.ExtraMemoryPtr)[1];
	int top = duk_get_top(ctx);
	char *m;
	duk_push_heapptr(ctx, hptr);										// [this]
	if (ILibDuktape_EventEmitter_HasListenersEx(ctx, -1, "PostSelect"))
	{
		ILibDuktape_EventEmitter_SetupEmit(ctx, hptr, "PostSelect");	// [this][emit][this][name]
		duk_push_int(ctx, slct);										// [this][emit][this][name][select]
		m = ILibChain_GetMetaDataFromDescriptorSet(Duktape_GetChain(ctx), readset, writeset, errorset);
		duk_push_string(ctx, m);										// [this][emit][this][name][select][string]
		if (duk_pcall_method(ctx, 3) != 0) { ILibDuktape_Process_UncaughtExceptionEx(ctx, "ChainViewer.emit('PostSelect'): Error "); }
		duk_pop(ctx);													// [this]
	}

	duk_get_prop_string(ctx, -1, ILibDuktape_ChainViewer_PromiseList);	// [this][list]
	while (duk_get_length(ctx, -1) > 0)
	{
		m = ILibChain_GetMetaDataFromDescriptorSetEx(duk_ctx_chain(ctx), readset, writeset, errorset);
		duk_array_shift(ctx, -1);										// [this][list][promise]
		duk_get_prop_string(ctx, -1, "_RES");							// [this][list][promise][RES]
		duk_swap_top(ctx, -2);											// [this][list][RES][this]
		duk_push_string(ctx, m);										// [this][list][RES][this][str]
		duk_pcall_method(ctx, 1); duk_pop(ctx);							// [this][list]
		ILibMemory_Free(m);
	}

	duk_set_top(ctx, top);
}

extern void ILibPrependToChain(void *Chain, void *object);

duk_ret_t ILibDuktape_ChainViewer_getSnapshot_promise(duk_context *ctx)
{
	duk_push_this(ctx);										// [promise]
	duk_dup(ctx, 0); duk_put_prop_string(ctx, -2, "_RES");
	duk_dup(ctx, 1); duk_put_prop_string(ctx, -2, "_REJ");
	return(0);
}
duk_ret_t ILibDuktape_ChainViewer_getSnapshot(duk_context *ctx)
{
	duk_push_this(ctx);															// [viewer]
	duk_get_prop_string(ctx, -1, ILibDuktape_ChainViewer_PromiseList);			// [viewer][list]
	duk_eval_string(ctx, "require('promise')");									// [viewer][list][promise]
	duk_push_c_function(ctx, ILibDuktape_ChainViewer_getSnapshot_promise, 2);	// [viewer][list][promise][func]
	duk_new(ctx, 1);															// [viewer][list][promise]
	duk_dup(ctx, -1);															// [viewer][list][promise][promise]
	duk_put_prop_index(ctx, -3, (duk_uarridx_t)duk_get_length(ctx, -3));		// [viewer][list][promise]
	ILibForceUnBlockChain(duk_ctx_chain(ctx));
	return(1);
}
duk_ret_t ILibDutkape_ChainViewer_cleanup(duk_context *ctx)
{
	duk_push_current_function(ctx);
	void *link = Duktape_GetPointerProperty(ctx, -1, "pointer");
	ILibChain_SafeRemove(duk_ctx_chain(ctx), link);
	return(0);
}
duk_ret_t ILibDuktape_ChainViewer_getTimerInfo(duk_context *ctx)
{
	char *v = ILibChain_GetMetadataForTimers(duk_ctx_chain(ctx));
	duk_push_string(ctx, v);
	ILibMemory_Free(v);
	return(1);
}
void ILibDuktape_ChainViewer_Push(duk_context *ctx, void *chain)
{
	duk_push_object(ctx);													// [viewer]

	ILibTransport *t = (ILibTransport*)ILibChain_Link_Allocate(sizeof(ILibTransport), 2*sizeof(void*));
	t->ChainLink.MetaData = ILibMemory_SmartAllocate_FromString("ILibDuktape_ChainViewer");
	t->ChainLink.PostSelectHandler = ILibDuktape_ChainViewer_PostSelect;
	((void**)t->ChainLink.ExtraMemoryPtr)[0] = ctx;
	((void**)t->ChainLink.ExtraMemoryPtr)[1] = duk_get_heapptr(ctx, -1);
	ILibDuktape_EventEmitter *emitter = ILibDuktape_EventEmitter_Create(ctx);
	ILibDuktape_EventEmitter_CreateEventEx(emitter, "PostSelect");
	ILibDuktape_CreateInstanceMethod(ctx, "getSnapshot", ILibDuktape_ChainViewer_getSnapshot, 0);
	ILibDuktape_CreateInstanceMethod(ctx, "getTimerInfo", ILibDuktape_ChainViewer_getTimerInfo, 0);
	duk_push_array(ctx); duk_put_prop_string(ctx, -2, ILibDuktape_ChainViewer_PromiseList);
	ILibPrependToChain(chain, (void*)t);

	duk_push_heapptr(ctx, ILibDuktape_GetProcessObject(ctx));				// [viewer][process]
	duk_events_setup_on(ctx, -1, "exit", ILibDutkape_ChainViewer_cleanup);	// [viewer][process][on][this][exit][func]
	duk_push_pointer(ctx, t); duk_put_prop_string(ctx, -2, "pointer");
	duk_pcall_method(ctx, 2); duk_pop_2(ctx);								// [viewer]
}

duk_ret_t ILibDuktape_httpHeaders(duk_context *ctx)
{
	ILibHTTPPacket *packet = NULL;
	packetheader_field_node *node;
	int headersOnly = duk_get_top(ctx) > 1 ? (duk_require_boolean(ctx, 1) ? 1 : 0) : 0;

	duk_size_t bufferLen;
	char *buffer = (char*)Duktape_GetBuffer(ctx, 0, &bufferLen);

	packet = ILibParsePacketHeader(buffer, 0, (int)bufferLen);
	if (packet == NULL) { return(ILibDuktape_Error(ctx, "http-headers(): Error parsing data")); }

	if (headersOnly == 0)
	{
		duk_push_object(ctx);
		if (packet->Directive != NULL)
		{
			duk_push_lstring(ctx, packet->Directive, packet->DirectiveLength);
			duk_put_prop_string(ctx, -2, "method");
			duk_push_lstring(ctx, packet->DirectiveObj, packet->DirectiveObjLength);
			duk_put_prop_string(ctx, -2, "url");
		}
		else
		{
			duk_push_int(ctx, packet->StatusCode);
			duk_put_prop_string(ctx, -2, "statusCode");
			duk_push_lstring(ctx, packet->StatusData, packet->StatusDataLength);
			duk_put_prop_string(ctx, -2, "statusMessage");
		}
		if (packet->VersionLength == 3)
		{
			duk_push_object(ctx);
			duk_push_lstring(ctx, packet->Version, 1);
			duk_put_prop_string(ctx, -2, "major");
			duk_push_lstring(ctx, packet->Version + 2, 1);
			duk_put_prop_string(ctx, -2, "minor");
			duk_put_prop_string(ctx, -2, "version");
		}
	}

	duk_push_object(ctx);		// headers
	node = packet->FirstField;
	while (node != NULL)
	{
		duk_push_lstring(ctx, node->Field, node->FieldLength);			// [str]
		duk_get_prop_string(ctx, -1, "toLowerCase");					// [str][toLower]
		duk_swap_top(ctx, -2);											// [toLower][this]
		duk_call_method(ctx, 0);										// [result]
		duk_push_lstring(ctx, node->FieldData, node->FieldDataLength);
		duk_put_prop(ctx, -3);
		node = node->NextField;
	}
	if (headersOnly == 0)
	{
		duk_put_prop_string(ctx, -2, "headers");
	}
	ILibDestructPacket(packet);
	return(1);
}
void ILibDuktape_httpHeaders_PUSH(duk_context *ctx, void *chain)
{
	duk_push_c_function(ctx, ILibDuktape_httpHeaders, DUK_VARARGS);
}
void ILibDuktape_DescriptorEvents_PreSelect(void* object, fd_set *readset, fd_set *writeset, fd_set *errorset, int* blocktime)
{
	duk_context *ctx = (duk_context*)((void**)((ILibChain_Link*)object)->ExtraMemoryPtr)[0];
	void *h = ((void**)((ILibChain_Link*)object)->ExtraMemoryPtr)[1];
	if (h == NULL || ctx == NULL) { return; }

	int i = duk_get_top(ctx);
	int fd;

	duk_push_heapptr(ctx, h);												// [obj]
	duk_get_prop_string(ctx, -1, ILibDuktape_DescriptorEvents_Table);		// [obj][table]
	duk_enum(ctx, -1, DUK_ENUM_OWN_PROPERTIES_ONLY);						// [obj][table][enum]
	while (duk_next(ctx, -1, 1))											// [obj][table][enum][FD][emitter]
	{
		fd = (int)duk_to_int(ctx, -2);									
		duk_get_prop_string(ctx, -1, ILibDuktape_DescriptorEvents_Options);	// [obj][table][enum][FD][emitter][options]
		if (Duktape_GetBooleanProperty(ctx, -1, "readset", 0)) { FD_SET(fd, readset); }
		if (Duktape_GetBooleanProperty(ctx, -1, "writeset", 0)) { FD_SET(fd, writeset); }
		if (Duktape_GetBooleanProperty(ctx, -1, "errorset", 0)) { FD_SET(fd, errorset); }
		duk_pop_3(ctx);														// [obj][table][enum]
	}

	duk_set_top(ctx, i);
}
void ILibDuktape_DescriptorEvents_PostSelect(void* object, int slct, fd_set *readset, fd_set *writeset, fd_set *errorset)
{
	duk_context *ctx = (duk_context*)((void**)((ILibChain_Link*)object)->ExtraMemoryPtr)[0];
	void *h = ((void**)((ILibChain_Link*)object)->ExtraMemoryPtr)[1];
	if (h == NULL || ctx == NULL) { return; }

	int i = duk_get_top(ctx);
	int fd;

	duk_push_array(ctx);												// [array]
	duk_push_heapptr(ctx, h);											// [array][obj]
	duk_get_prop_string(ctx, -1, ILibDuktape_DescriptorEvents_Table);	// [array][obj][table]
	duk_enum(ctx, -1, DUK_ENUM_OWN_PROPERTIES_ONLY);					// [array][obj][table][enum]
	while (duk_next(ctx, -1, 1))										// [array][obj][table][enum][FD][emitter]
	{
		fd = (int)duk_to_int(ctx, -2);
		if (FD_ISSET(fd, readset) || FD_ISSET(fd, writeset) || FD_ISSET(fd, errorset))
		{
			duk_put_prop_index(ctx, -6, (duk_uarridx_t)duk_get_length(ctx, -6));		// [array][obj][table][enum][FD]
			duk_pop(ctx);												// [array][obj][table][enum]
		}
		else
		{
			duk_pop_2(ctx);												// [array][obj][table][enum]

		}
	}
	duk_pop_3(ctx);																						// [array]

	while (duk_get_length(ctx, -1) > 0)
	{
		duk_get_prop_string(ctx, -1, "pop");															// [array][pop]
		duk_dup(ctx, -2);																				// [array][pop][this]
		if (duk_pcall_method(ctx, 0) == 0)																// [array][emitter]
		{
			if ((fd = Duktape_GetIntPropertyValue(ctx, -1, ILibDuktape_DescriptorEvents_FD, -1)) != -1)
			{
				if (FD_ISSET(fd, readset))
				{
					ILibDuktape_EventEmitter_SetupEmit(ctx, duk_get_heapptr(ctx, -1), "readset");		// [array][emitter][emit][this][readset]
					duk_push_int(ctx, fd);																// [array][emitter][emit][this][readset][fd]
					duk_pcall_method(ctx, 2); duk_pop(ctx);												// [array][emitter]
				}
				if (FD_ISSET(fd, writeset))
				{
					ILibDuktape_EventEmitter_SetupEmit(ctx, duk_get_heapptr(ctx, -1), "writeset");		// [array][emitter][emit][this][writeset]
					duk_push_int(ctx, fd);																// [array][emitter][emit][this][writeset][fd]
					duk_pcall_method(ctx, 2); duk_pop(ctx);												// [array][emitter]
				}
				if (FD_ISSET(fd, errorset))
				{
					ILibDuktape_EventEmitter_SetupEmit(ctx, duk_get_heapptr(ctx, -1), "errorset");		// [array][emitter][emit][this][errorset]
					duk_push_int(ctx, fd);																// [array][emitter][emit][this][errorset][fd]
					duk_pcall_method(ctx, 2); duk_pop(ctx);												// [array][emitter]
				}
			}
		}
		duk_pop(ctx);																					// [array]
	}
	duk_set_top(ctx, i);
}
duk_ret_t ILibDuktape_DescriptorEvents_Remove(duk_context *ctx)
{
#ifdef WIN32
	if (duk_is_object(ctx, 0) && duk_has_prop_string(ctx, 0, "_ptr"))
	{
		// Windows Wait Handle
		HANDLE h = (HANDLE)Duktape_GetPointerProperty(ctx, 0, "_ptr");
		duk_push_this(ctx);													// [obj]
		duk_get_prop_string(ctx, -1, ILibDuktape_DescriptorEvents_HTable);	// [obj][table]
		ILibChain_RemoveWaitHandle(duk_ctx_chain(ctx), h);
		duk_push_sprintf(ctx, "%p", h);	duk_del_prop(ctx, -2);				// [obj][table]
		if (Duktape_GetPointerProperty(ctx, -1, ILibDuktape_DescriptorEvents_CURRENT) == h)
		{
			duk_del_prop_string(ctx, -1, ILibDuktape_DescriptorEvents_CURRENT);
		}
		return(0);
	}
#endif
	if (!duk_is_number(ctx, 0)) { return(ILibDuktape_Error(ctx, "Invalid Descriptor")); }
	ILibForceUnBlockChain(Duktape_GetChain(ctx));

	duk_push_this(ctx);													// [obj]
	duk_get_prop_string(ctx, -1, ILibDuktape_DescriptorEvents_Table);	// [obj][table]
	duk_dup(ctx, 0);													// [obj][table][key]
	if (!duk_is_null_or_undefined(ctx, 1) && duk_is_object(ctx, 1))
	{
		duk_get_prop(ctx, -2);											// [obj][table][value]
		if (duk_is_null_or_undefined(ctx, -1)) { return(0); }
		duk_get_prop_string(ctx, -1, ILibDuktape_DescriptorEvents_Options);	//..[table][value][options]
		if (duk_has_prop_string(ctx, 1, "readset")) { duk_push_false(ctx); duk_put_prop_string(ctx, -2, "readset"); }
		if (duk_has_prop_string(ctx, 1, "writeset")) { duk_push_false(ctx); duk_put_prop_string(ctx, -2, "writeset"); }
		if (duk_has_prop_string(ctx, 1, "errorset")) { duk_push_false(ctx); duk_put_prop_string(ctx, -2, "errorset"); }
		if(	Duktape_GetBooleanProperty(ctx, -1, "readset", 0)	== 0 && 
			Duktape_GetBooleanProperty(ctx, -1, "writeset", 0)	== 0 &&
			Duktape_GetBooleanProperty(ctx, -1, "errorset", 0)	== 0)
		{
			// No FD_SET watchers, so we can remove the entire object
			duk_pop_2(ctx);												// [obj][table]
			duk_dup(ctx, 0);											// [obj][table][key]
			duk_del_prop(ctx, -2);										// [obj][table]
		}
	}
	else
	{
		// Remove All FD_SET watchers for this FD
		duk_del_prop(ctx, -2);											// [obj][table]
	}
	return(0);
}
#ifdef WIN32
char *DescriptorEvents_Status[] = { "NONE", "INVALID_HANDLE", "TIMEOUT", "REMOVED", "EXITING", "ERROR" }; 
BOOL ILibDuktape_DescriptorEvents_WaitHandleSink(void *chain, HANDLE h, ILibWaitHandle_ErrorStatus status, void* user)
{
	BOOL ret = FALSE;
	duk_context *ctx = (duk_context*)((void**)user)[0];

	int top = duk_get_top(ctx);
	duk_push_heapptr(ctx, ((void**)user)[1]);								// [events]
	duk_get_prop_string(ctx, -1, ILibDuktape_DescriptorEvents_HTable);		// [events][table]
	duk_push_sprintf(ctx, "%p", h);											// [events][table][key]
	duk_get_prop(ctx, -2);													// [events][table][val]
	if (!duk_is_null_or_undefined(ctx, -1))
	{
		void *hptr = duk_get_heapptr(ctx, -1);
		if (status != ILibWaitHandle_ErrorStatus_NONE) { duk_push_sprintf(ctx, "%p", h); duk_del_prop(ctx, -3); }
		duk_push_pointer(ctx, h); duk_put_prop_string(ctx, -3, ILibDuktape_DescriptorEvents_CURRENT);
		ILibDuktape_EventEmitter_SetupEmit(ctx, hptr, "signaled");			// [events][table][val][emit][this][signaled]
		duk_push_string(ctx, DescriptorEvents_Status[(int)status]);			// [events][table][val][emit][this][signaled][status]
		if (duk_pcall_method(ctx, 2) == 0)									// [events][table][val][undef]
		{
			ILibDuktape_EventEmitter_GetEmitReturn(ctx, hptr, "signaled");	// [events][table][val][undef][ret]
			if (duk_is_boolean(ctx, -1) && duk_get_boolean(ctx, -1) != 0)
			{
				ret = TRUE;
			}
		}	
		else
		{
			ILibDuktape_Process_UncaughtExceptionEx(ctx, "DescriptorEvents.signaled() threw an exception that will result in descriptor getting removed: ");
		}
		duk_set_top(ctx, top);
		duk_push_heapptr(ctx, ((void**)user)[1]);							// [events]
		duk_get_prop_string(ctx, -1, ILibDuktape_DescriptorEvents_HTable);	// [events][table]

		if (ret == FALSE && Duktape_GetPointerProperty(ctx, -1, ILibDuktape_DescriptorEvents_CURRENT) == h)
		{
			//
			// We need to unhook the events to the descriptor event object, before we remove it from the table
			//
			duk_push_sprintf(ctx, "%p", h);									// [events][table][key]
			duk_get_prop(ctx, -2);											// [events][table][descriptorevent]
			duk_get_prop_string(ctx, -1, "removeAllListeners");				// [events][table][descriptorevent][remove]
			duk_swap_top(ctx, -2);											// [events][table][remove][this]
			duk_push_string(ctx, "signaled");								// [events][table][remove][this][signaled]
			duk_pcall_method(ctx, 1); duk_pop(ctx);							// [events][table]
			duk_push_sprintf(ctx, "%p", h);									// [events][table][key]
			duk_del_prop(ctx, -2);											// [events][table]
		}
		duk_del_prop_string(ctx, -1, ILibDuktape_DescriptorEvents_CURRENT);	// [events][table]
	}
	duk_set_top(ctx, top);

	return(ret);
}
#endif
duk_ret_t ILibDuktape_DescriptorEvents_Add(duk_context *ctx)
{
	ILibDuktape_EventEmitter *e;
#ifdef WIN32
	if (duk_is_object(ctx, 0) && duk_has_prop_string(ctx, 0, "_ptr"))
	{
		// Adding a Windows Wait Handle
		HANDLE h = (HANDLE)Duktape_GetPointerProperty(ctx, 0, "_ptr");
		if (h != NULL)
		{
			// Normal Add Wait Handle
			char *metadata = "DescriptorEvents";
			int timeout = -1;
			duk_push_this(ctx);														// [events]
			ILibChain_Link *link = (ILibChain_Link*)Duktape_GetPointerProperty(ctx, -1, ILibDuktape_DescriptorEvents_ChainLink);
			duk_get_prop_string(ctx, -1, ILibDuktape_DescriptorEvents_HTable);		// [events][table]
			if (Duktape_GetPointerProperty(ctx, -1, ILibDuktape_DescriptorEvents_CURRENT) == h)
			{
				// We are adding a wait handle from the event handler for this same signal, so remove this attribute,
				// so the signaler doesn't remove the object we are about to put in.
				duk_del_prop_string(ctx, -1, ILibDuktape_DescriptorEvents_CURRENT);
			}
			duk_push_object(ctx);													// [events][table][value]
			duk_push_sprintf(ctx, "%p", h);											// [events][table][value][key]
			duk_dup(ctx, -2);														// [events][table][value][key][value]
			duk_dup(ctx, 0);
			duk_put_prop_string(ctx, -2, ILibDuktape_DescriptorEvents_WaitHandle);	// [events][table][value][key][value]
			if (duk_is_object(ctx, 1)) { duk_dup(ctx, 1); }
			else { duk_push_object(ctx); }											// [events][table][value][key][value][options]
			if (duk_has_prop_string(ctx, -1, "metadata"))
			{
				duk_push_string(ctx, "DescriptorEvents, ");							// [events][table][value][key][value][options][str1]
				duk_get_prop_string(ctx, -2, "metadata");							// [events][table][value][key][value][options][str1][str2]
				duk_string_concat(ctx, -2);											// [events][table][value][key][value][options][str1][newstr]
				duk_remove(ctx, -2);												// [events][table][value][key][value][options][newstr]
				metadata = (char*)duk_get_string(ctx, -1);
				duk_put_prop_string(ctx, -2, "metadata");							// [events][table][value][key][value][options]
			}
			timeout = Duktape_GetIntPropertyValue(ctx, -1, "timeout", -1);
			duk_put_prop_string(ctx, -2, ILibDuktape_DescriptorEvents_Options);		// [events][table][value][key][value]
			duk_put_prop(ctx, -4);													// [events][table][value]
			e = ILibDuktape_EventEmitter_Create(ctx);
			ILibDuktape_EventEmitter_CreateEventEx(e, "signaled");
			ILibChain_AddWaitHandleEx(duk_ctx_chain(ctx), h, timeout, ILibDuktape_DescriptorEvents_WaitHandleSink, link->ExtraMemoryPtr, metadata);
			return(1);
		}
		return(ILibDuktape_Error(ctx, "Invalid Parameter"));
	}
#endif

	if (!duk_is_number(ctx, 0)) { return(ILibDuktape_Error(ctx, "Invalid Descriptor")); }
	ILibForceUnBlockChain(Duktape_GetChain(ctx));

	duk_push_this(ctx);													// [obj]
	duk_get_prop_string(ctx, -1, ILibDuktape_DescriptorEvents_Table);	// [obj][table]
	duk_dup(ctx, 0);													// [obj][table][key]
	if (duk_has_prop(ctx, -2))											// [obj][table]
	{
		// There's already a watcher, so let's just merge the FD_SETS
		duk_dup(ctx, 0);												// [obj][table][key]
		duk_get_prop(ctx, -2);											// [obj][table][value]
		duk_get_prop_string(ctx, -1, ILibDuktape_DescriptorEvents_Options);	//..[table][value][options]
		if (Duktape_GetBooleanProperty(ctx, 1, "readset", 0) != 0) { duk_push_true(ctx); duk_put_prop_string(ctx, -2, "readset"); }
		if (Duktape_GetBooleanProperty(ctx, 1, "writeset", 0) != 0) { duk_push_true(ctx); duk_put_prop_string(ctx, -2, "writeset"); }
		if (Duktape_GetBooleanProperty(ctx, 1, "errorset", 0) != 0) { duk_push_true(ctx); duk_put_prop_string(ctx, -2, "errorset"); }
		duk_pop(ctx);													// [obj][table][value]
		return(1);
	}

	duk_push_object(ctx);												// [obj][table][value]
	duk_dup(ctx, 0);													// [obj][table][value][key]
	duk_dup(ctx, -2);													// [obj][table][value][key][value]
	e = ILibDuktape_EventEmitter_Create(ctx);	
	ILibDuktape_EventEmitter_CreateEventEx(e, "readset");
	ILibDuktape_EventEmitter_CreateEventEx(e, "writeset");
	ILibDuktape_EventEmitter_CreateEventEx(e, "errorset");
	duk_dup(ctx, 0);													// [obj][table][value][key][value][FD]
	duk_put_prop_string(ctx, -2, ILibDuktape_DescriptorEvents_FD);		// [obj][table][value][key][value]
	duk_dup(ctx, 1);													// [obj][table][value][key][value][options]
	duk_put_prop_string(ctx, -2, ILibDuktape_DescriptorEvents_Options);	// [obj][table][value][key][value]
	char* metadata = Duktape_GetStringPropertyValue(ctx, -1, "metadata", NULL);
	if (metadata != NULL)
	{
		duk_push_string(ctx, "DescriptorEvents, ");						// [obj][table][value][key][value][str1]
		duk_push_string(ctx, metadata);									// [obj][table][value][key][value][str1][str2]
		duk_string_concat(ctx, -2);										// [obj][table][value][key][value][newStr]
		duk_put_prop_string(ctx, -2, "metadata");						// [obj][table][value][key][value]
	}
	duk_put_prop(ctx, -4);												// [obj][table][value]

	return(1);
}
duk_ret_t ILibDuktape_DescriptorEvents_Finalizer(duk_context *ctx)
{
	ILibChain_Link *link = (ILibChain_Link*)Duktape_GetPointerProperty(ctx, 0, ILibDuktape_DescriptorEvents_ChainLink);
	void *chain = Duktape_GetChain(ctx);

	link->PreSelectHandler = NULL;
	link->PostSelectHandler = NULL;
	((void**)link->ExtraMemoryPtr)[0] = NULL;
	((void**)link->ExtraMemoryPtr)[1] = NULL;
	
	if (ILibIsChainBeingDestroyed(chain) == 0)
	{
		ILibChain_SafeRemove(chain, link);
	}

	return(0);
}

#ifndef WIN32
void ILibDuktape_DescriptorEvents_GetCount_results_final(void *chain, void *user)
{
	duk_context *ctx = (duk_context*)((void**)user)[0];
	void *hptr = ((void**)user)[1];
	duk_push_heapptr(ctx, hptr);											// [promise]
	duk_get_prop_string(ctx, -1, "_RES");									// [promise][res]
	duk_swap_top(ctx, -2);													// [res][this]
	duk_push_int(ctx, ILibChain_GetDescriptorCount(duk_ctx_chain(ctx)));	// [res][this][count]
	duk_pcall_method(ctx, 1); duk_pop(ctx);									// ...
	free(user);
}
void ILibDuktape_DescriptorEvents_GetCount_results(void *chain, void *user)
{
	ILibChain_RunOnMicrostackThreadEx2(chain, ILibDuktape_DescriptorEvents_GetCount_results_final, user, 1);
}
#endif
duk_ret_t ILibDuktape_DescriptorEvents_GetCount_promise(duk_context *ctx)
{
	duk_push_this(ctx);		// [promise]
	duk_dup(ctx, 0); duk_put_prop_string(ctx, -2, "_RES");
	duk_dup(ctx, 1); duk_put_prop_string(ctx, -2, "_REJ");
	return(0);
}
duk_ret_t ILibDuktape_DescriptorEvents_GetCount(duk_context *ctx)
{
	duk_eval_string(ctx, "require('promise');");								// [promise]
	duk_push_c_function(ctx, ILibDuktape_DescriptorEvents_GetCount_promise, 2);	// [promise][func]
	duk_new(ctx, 1);															// [promise]
	
#ifdef WIN32
	duk_get_prop_string(ctx, -1, "_RES");										// [promise][res]
	duk_dup(ctx, -2);															// [promise][res][this]
	duk_push_int(ctx, ILibChain_GetDescriptorCount(duk_ctx_chain(ctx)));		// [promise][res][this][count]
	duk_call_method(ctx, 1); duk_pop(ctx);										// [promise]
#else
	void **data = (void**)ILibMemory_Allocate(2 * sizeof(void*), 0, NULL, NULL);
	data[0] = ctx;
	data[1] = duk_get_heapptr(ctx, -1);
	ILibChain_InitDescriptorCount(duk_ctx_chain(ctx));
	ILibChain_RunOnMicrostackThreadEx2(duk_ctx_chain(ctx), ILibDuktape_DescriptorEvents_GetCount_results, data, 1);
#endif
	return(1);
}
char* ILibDuktape_DescriptorEvents_Query(void* chain, void *object, int fd, size_t *dataLen)
{
	char *retVal = ((ILibChain_Link*)object)->MetaData;
	*dataLen = strnlen_s(retVal, 1024);

	duk_context *ctx = (duk_context*)((void**)((ILibChain_Link*)object)->ExtraMemoryPtr)[0];
	void *h = ((void**)((ILibChain_Link*)object)->ExtraMemoryPtr)[1];
	if (h == NULL || ctx == NULL || !duk_ctx_is_alive(ctx)) { return(retVal); }
	int top = duk_get_top(ctx);

	duk_push_heapptr(ctx, h);												// [events]
	duk_get_prop_string(ctx, -1, ILibDuktape_DescriptorEvents_Table);		// [events][table]
	duk_push_int(ctx, fd);													// [events][table][key]
	if (duk_has_prop(ctx, -2) != 0)											// [events][table]
	{
		duk_push_int(ctx, fd); duk_get_prop(ctx, -2);						// [events][table][val]
		duk_get_prop_string(ctx, -1, ILibDuktape_DescriptorEvents_Options);	// [events][table][val][options]
		if (!duk_is_null_or_undefined(ctx, -1))
		{
			retVal = Duktape_GetStringPropertyValueEx(ctx, -1, "metadata", retVal, dataLen);
		}
	}

	duk_set_top(ctx, top);
	return(retVal);
}
duk_ret_t ILibDuktape_DescriptorEvents_descriptorAdded(duk_context *ctx)
{
	duk_push_this(ctx);																// [DescriptorEvents]
	if (duk_is_number(ctx, 0))
	{
		duk_get_prop_string(ctx, -1, ILibDuktape_DescriptorEvents_Table);			// [DescriptorEvents][table]
		duk_dup(ctx, 0);															// [DescriptorEvents][table][key]
	}
	else
	{
		if (duk_is_object(ctx, 0) && duk_has_prop_string(ctx, 0, "_ptr"))
		{
			duk_get_prop_string(ctx, -1, ILibDuktape_DescriptorEvents_HTable);		// [DescriptorEvents][table]	
			duk_push_sprintf(ctx, "%p", Duktape_GetPointerProperty(ctx, 0, "_ptr"));// [DescriptorEvents][table][key]
		}
		else
		{
			return(ILibDuktape_Error(ctx, "Invalid Argument. Must be a descriptor or HANDLE"));
		}
	}
	duk_push_boolean(ctx, duk_has_prop(ctx, -2));
	return(1);
}
void ILibDuktape_DescriptorEvents_Push(duk_context *ctx, void *chain)
{
	ILibChain_Link *link = (ILibChain_Link*)ILibChain_Link_Allocate(sizeof(ILibChain_Link), 2 * sizeof(void*));
	link->MetaData = ILibMemory_SmartAllocate_FromString("DescriptorEvents");
	link->PreSelectHandler = ILibDuktape_DescriptorEvents_PreSelect;
	link->PostSelectHandler = ILibDuktape_DescriptorEvents_PostSelect;
	link->QueryHandler = ILibDuktape_DescriptorEvents_Query;

	duk_push_object(ctx);
	duk_push_pointer(ctx, link); duk_put_prop_string(ctx, -2, ILibDuktape_DescriptorEvents_ChainLink);
	duk_push_object(ctx); duk_put_prop_string(ctx, -2, ILibDuktape_DescriptorEvents_Table);
	duk_push_object(ctx); duk_put_prop_string(ctx, -2, ILibDuktape_DescriptorEvents_HTable);
	
	ILibDuktape_CreateFinalizer(ctx, ILibDuktape_DescriptorEvents_Finalizer);

	((void**)link->ExtraMemoryPtr)[0] = ctx;
	((void**)link->ExtraMemoryPtr)[1] = duk_get_heapptr(ctx, -1);
	ILibDuktape_CreateInstanceMethod(ctx, "addDescriptor", ILibDuktape_DescriptorEvents_Add, 2);
	ILibDuktape_CreateInstanceMethod(ctx, "removeDescriptor", ILibDuktape_DescriptorEvents_Remove, DUK_VARARGS);
	ILibDuktape_CreateInstanceMethod(ctx, "getDescriptorCount", ILibDuktape_DescriptorEvents_GetCount, 0);
	ILibDuktape_CreateInstanceMethod(ctx, "descriptorAdded", ILibDuktape_DescriptorEvents_descriptorAdded, 1);

	ILibAddToChain(chain, link);
}
duk_ret_t ILibDuktape_Polyfills_filehash(duk_context *ctx)
{
	char *hash = duk_push_fixed_buffer(ctx, UTIL_SHA384_HASHSIZE);
	duk_push_buffer_object(ctx, -1, 0, UTIL_SHA384_HASHSIZE, DUK_BUFOBJ_NODEJS_BUFFER);
	if (GenerateSHA384FileHash((char*)duk_require_string(ctx, 0), hash) == 0)
	{
		return(1);
	}
	else
	{
		return(ILibDuktape_Error(ctx, "Error generating FileHash "));
	}
}

duk_ret_t ILibDuktape_Polyfills_ipv4From(duk_context *ctx)
{
	int v = duk_require_int(ctx, 0);
	ILibDuktape_IPV4AddressToOptions(ctx, v);
	duk_get_prop_string(ctx, -1, "host");
	return(1);
}

duk_ret_t ILibDuktape_Polyfills_global(duk_context *ctx)
{
	duk_push_global_object(ctx);
	return(1);
}
duk_ret_t ILibDuktape_Polyfills_isBuffer(duk_context *ctx)
{
	duk_push_boolean(ctx, duk_is_buffer_data(ctx, 0));
	return(1);
}
#if defined(_POSIX) && !defined(__APPLE__) && !defined(_FREEBSD)
duk_ret_t ILibDuktape_ioctl_func(duk_context *ctx)
{
	int fd = (int)duk_require_int(ctx, 0);
	int code = (int)duk_require_int(ctx, 1);
	duk_size_t outBufferLen = 0;
	char *outBuffer = Duktape_GetBuffer(ctx, 2, &outBufferLen);

	duk_push_int(ctx, ioctl(fd, _IOC(_IOC_READ | _IOC_WRITE, 'H', code, outBufferLen), outBuffer) ? errno : 0);
	return(1);
}
void ILibDuktape_ioctl_Push(duk_context *ctx, void *chain)
{
	duk_push_c_function(ctx, ILibDuktape_ioctl_func, DUK_VARARGS);
	ILibDuktape_WriteID(ctx, "ioctl");
}
#endif
void ILibDuktape_uuidv4_Push(duk_context *ctx, void *chain)
{	
	duk_push_object(ctx);
	char uuid[] = "module.exports = function uuidv4()\
						{\
							var b = Buffer.alloc(16);\
							b.randomFill();\
							var v = b.readUInt16BE(6) & 0xF1F;\
							v |= (4 << 12);\
							v |= (4 << 5);\
							b.writeUInt16BE(v, 6);\
							var ret = b.slice(0, 4).toString('hex') + '-' + b.slice(4, 6).toString('hex') + '-' + b.slice(6, 8).toString('hex') + '-' + b.slice(8, 10).toString('hex') + '-' + b.slice(10).toString('hex');\
							ret = '{' + ret.toLowerCase() + '}';\
							return (ret);\
						};";

	ILibDuktape_ModSearch_AddHandler_AlsoIncludeJS(ctx, uuid, sizeof(uuid) - 1);
}

duk_ret_t ILibDuktape_Polyfills_debugHang(duk_context *ctx)
{
	int val = duk_get_top(ctx) == 0 ? 30000 : duk_require_int(ctx, 0);

#ifdef WIN32
	Sleep(val);
#else
	sleep(val);
#endif

	return(0);
}

extern void checkForEmbeddedMSH_ex2(char *binPath, char **eMSH);
duk_ret_t ILibDuktape_Polyfills_MSH(duk_context *ctx)
{
	duk_eval_string(ctx, "process.execPath");	// [string]
	char *exepath = (char*)duk_get_string(ctx, -1);
	char *msh;
	duk_size_t s = 0;

	checkForEmbeddedMSH_ex2(exepath, &msh);
	if (msh == NULL)
	{
		duk_eval_string(ctx, "require('fs')");			// [fs]
		duk_get_prop_string(ctx, -1, "readFileSync");	// [fs][readFileSync]
		duk_swap_top(ctx, -2);							// [readFileSync][this]
#ifdef _POSIX
		duk_push_sprintf(ctx, "%s.msh", exepath);		// [readFileSync][this][path]
#else
		duk_push_string(ctx, exepath);					// [readFileSync][this][path]
		duk_string_split(ctx, -1, ".exe");				// [readFileSync][this][path][array]
		duk_remove(ctx, -2);							// [readFileSync][this][array]
		duk_array_join(ctx, -1, ".msh");				// [readFileSync][this][array][path]
		duk_remove(ctx, -2);							// [readFileSync][this][path]
#endif
		duk_push_object(ctx);							// [readFileSync][this][path][options]
		duk_push_string(ctx, "rb"); duk_put_prop_string(ctx, -2, "flags");
		if (duk_pcall_method(ctx, 2) == 0)				// [buffer]
		{
			msh = Duktape_GetBuffer(ctx, -1, &s);
		}
	}

	duk_push_object(ctx);														// [obj]
	if (msh != NULL)
	{
		if (s == 0) { s = ILibMemory_Size(msh); }
		parser_result *pr = ILibParseString(msh, 0, s, "\n", 1);
		parser_result_field *f = pr->FirstResult;
		int i;
		while (f != NULL)
		{
			if (f->datalength > 0)
			{
				i = ILibString_IndexOf(f->data, f->datalength, "=", 1);
				if (i >= 0)
				{
					duk_push_lstring(ctx, f->data, (duk_size_t)i);						// [obj][key]
					if (f->data[f->datalength - 1] == '\r')
					{
						duk_push_lstring(ctx, f->data + i + 1, f->datalength - i - 2);	// [obj][key][value]
					}
					else
					{
						duk_push_lstring(ctx, f->data + i + 1, f->datalength - i - 1);	// [obj][key][value]
					}
					duk_put_prop(ctx, -3);												// [obj]
				}
			}
			f = f->NextResult;
		}
		ILibDestructParserResults(pr);
		ILibMemory_Free(msh);
	}																					// [msh]

	if (duk_peval_string(ctx, "require('MeshAgent').getStartupOptions()") == 0)			// [msh][obj]
	{
		duk_enum(ctx, -1, DUK_ENUM_OWN_PROPERTIES_ONLY);								// [msh][obj][enum]
		while (duk_next(ctx, -1, 1))													// [msh][obj][enum][key][val]
		{
			if (duk_has_prop_string(ctx, -5, duk_get_string(ctx, -2)) == 0)
			{
				duk_put_prop(ctx, -5);													// [msh][obj][enum]
			}
			else
			{
				duk_pop_2(ctx);															// [msh][obj][enum]
			}
		}
		duk_pop(ctx);																	// [msh][obj]
	}
	duk_pop(ctx);																		// [msh]
	return(1);
}
#if defined(ILIBMEMTRACK) && !defined(ILIBCHAIN_GLOBAL_LOCK)
extern size_t ILib_NativeAllocSize;
extern ILibSpinLock ILib_MemoryTrackLock;
duk_ret_t ILibDuktape_Polyfills_NativeAllocSize(duk_context *ctx)
{
	ILibSpinLock_Lock(&ILib_MemoryTrackLock);
	duk_push_uint(ctx, ILib_NativeAllocSize);
	ILibSpinLock_UnLock(&ILib_MemoryTrackLock);
	return(1);
}
#endif
duk_ret_t ILibDuktape_Polyfills_WeakReference_isAlive(duk_context *ctx)
{
	duk_push_this(ctx);								// [weak]
	void **p = Duktape_GetPointerProperty(ctx, -1, "\xFF_heapptr");
	duk_push_boolean(ctx, ILibMemory_CanaryOK(p));
	return(1);
}
duk_ret_t ILibDuktape_Polyfills_WeakReference_object(duk_context *ctx)
{
	duk_push_this(ctx);								// [weak]
	void **p = Duktape_GetPointerProperty(ctx, -1, "\xFF_heapptr");
	if (ILibMemory_CanaryOK(p))
	{
		duk_push_heapptr(ctx, p[0]);
	}
	else
	{
		duk_push_null(ctx);
	}
	return(1);
}
duk_ret_t ILibDuktape_Polyfills_WeakReference(duk_context *ctx)
{
	duk_push_object(ctx);														// [weak]
	ILibDuktape_WriteID(ctx, "WeakReference");		
	duk_dup(ctx, 0);															// [weak][obj]
	void *j = duk_get_heapptr(ctx, -1);
	void **p = (void**)Duktape_PushBuffer(ctx, sizeof(void*));					// [weak][obj][buffer]
	p[0] = j;
	duk_put_prop_string(ctx, -2, Duktape_GetStashKey(duk_get_heapptr(ctx, -1)));// [weak][obj]

	duk_pop(ctx);																// [weak]

	duk_push_pointer(ctx, p); duk_put_prop_string(ctx, -2, "\xFF_heapptr");		// [weak]
	ILibDuktape_CreateInstanceMethod(ctx, "isAlive", ILibDuktape_Polyfills_WeakReference_isAlive, 0);
	ILibDuktape_CreateEventWithGetter_SetEnumerable(ctx, "object", ILibDuktape_Polyfills_WeakReference_object, 1);
	return(1);
}

duk_ret_t ILibDuktape_Polyfills_rootObject(duk_context *ctx)
{
	void *h = _duk_get_first_object(ctx);
	duk_push_heapptr(ctx, h);
	return(1);
}
duk_ret_t ILibDuktape_Polyfills_nextObject(duk_context *ctx)
{
	void *h = duk_require_heapptr(ctx, 0);
	void *next = _duk_get_next_object(ctx, h);
	if (next != NULL)
	{
		duk_push_heapptr(ctx, next);
	}
	else
	{
		duk_push_null(ctx);
	}
	return(1);
}
duk_ret_t ILibDuktape_Polyfills_countObject(duk_context *ctx)
{
	void *h = _duk_get_first_object(ctx);
	duk_int_t i = 1;

	while (h != NULL)
	{
		if ((h = _duk_get_next_object(ctx, h)) != NULL) { ++i; }
	}
	duk_push_int(ctx, i);
	return(1);
}
duk_ret_t ILibDuktape_Polyfills_hide(duk_context *ctx)
{
	duk_idx_t top = duk_get_top(ctx);
	duk_push_heap_stash(ctx);									// [stash]

	if (top == 0)
	{
		duk_get_prop_string(ctx, -1, "__STASH__");				// [stash][value]
	}
	else
	{
		if (duk_is_boolean(ctx, 0))
		{
			duk_get_prop_string(ctx, -1, "__STASH__");			// [stash][value]
			if (duk_require_boolean(ctx, 0))
			{
				duk_del_prop_string(ctx, -2, "__STASH__");
			}
		}
		else
		{
			duk_dup(ctx, 0);									// [stash][value]
			duk_dup(ctx, -1);									// [stash][value][value]
			duk_put_prop_string(ctx, -3, "__STASH__");			// [stash][value]
		}
	}
	return(1);
}
duk_ret_t ILibDuktape_Polyfills_altrequire(duk_context *ctx)
{
	duk_size_t idLen;
	char *id = (char*)duk_get_lstring(ctx, 0, &idLen);

	duk_push_heap_stash(ctx);										// [stash]
	if (!duk_has_prop_string(ctx, -1, ILibDuktape_AltRequireTable))
	{
		duk_push_object(ctx); 
		duk_put_prop_string(ctx, -2, ILibDuktape_AltRequireTable);
	}
	duk_get_prop_string(ctx, -1, ILibDuktape_AltRequireTable);		// [stash][table]

	if (ILibDuktape_ModSearch_IsRequired(ctx, id, idLen) == 0)
	{
		// Module was not 'require'ed yet
		duk_push_sprintf(ctx, "global._legacyrequire('%s');", id);	// [stash][table][str]
		duk_eval(ctx);												// [stash][table][value]
		duk_dup(ctx, -1);											// [stash][table][value][value]
		duk_put_prop_string(ctx, -3, id);							// [stash][table][value]
	}
	else
	{
		// Module was already required, so we need to do some additional checks
		if (duk_has_prop_string(ctx, -1, id)) // Check to see if there is a new instance we can use
		{
			duk_get_prop_string(ctx, -1, id);							// [stash][table][value]
		}
		else
		{
			// There is not an instance here, so we need to instantiate a new alt instance
			duk_push_sprintf(ctx, "getJSModule('%s');", id);			// [stash][table][str]
			if (duk_peval(ctx) != 0)									// [stash][table][js]
			{
				// This was a native module, so just return it directly
				duk_push_sprintf(ctx, "global._legacyrequire('%s');", id);	
				duk_eval(ctx);												
				return(1);
			}
			duk_eval_string(ctx, "global._legacyrequire('uuid/v4')();");				// [stash][table][js][uuid]
			duk_push_sprintf(ctx, "%s_%s", id, duk_get_string(ctx, -1));// [stash][table][js][uuid][newkey]

			duk_push_global_object(ctx);				// [stash][table][js][uuid][newkey][g]
			duk_get_prop_string(ctx, -1, "addModule");	// [stash][table][js][uuid][newkey][g][addmodule]
			duk_remove(ctx, -2);						// [stash][table][js][uuid][newkey][addmodule]
			duk_dup(ctx, -2);							// [stash][table][js][uuid][newkey][addmodule][key]
			duk_dup(ctx, -5);							// [stash][table][js][uuid][newkey][addmodule][key][module]
			duk_call(ctx, 2);							// [stash][table][js][uuid][newkey][ret]
			duk_pop(ctx);								// [stash][table][js][uuid][newkey]
			duk_push_sprintf(ctx, "global._legacyrequire('%s');", duk_get_string(ctx, -1));
			duk_eval(ctx);								// [stash][table][js][uuid][newkey][newval]
			duk_dup(ctx, -1);							// [stash][table][js][uuid][newkey][newval][newval]
			duk_put_prop_string(ctx, -6, id);			// [stash][table][js][uuid][newkey][newval]
		}
	}
	return(1);
}
duk_ret_t ILibDuktape_Polyfills_resolve(duk_context *ctx)
{
	char tmp[512];
	char *host = (char*)duk_require_string(ctx, 0);
	struct sockaddr_in6 addr[16];
	memset(&addr, 0, sizeof(addr));

	int i, count = ILibResolveEx2(host, 443, addr, 16);
	duk_push_array(ctx);															// [ret]
	duk_push_array(ctx);															// [ret][integers]

	for (i = 0; i < count; ++i)
	{
		if (ILibInet_ntop2((struct sockaddr*)(&addr[i]), tmp, sizeof(tmp)) != NULL)
		{
			duk_push_string(ctx, tmp);												// [ret][integers][string]
			duk_array_push(ctx, -3);												// [ret][integers]

			duk_push_int(ctx, ((struct sockaddr_in*)&addr[i])->sin_addr.s_addr);	// [ret][integers][value]
			duk_array_push(ctx, -2);												// [ret][integers]
		}
	}
	ILibDuktape_CreateReadonlyProperty_SetEnumerable(ctx, "_integers", 0);			// [ret]
	return(1);
}
duk_ret_t ILibDuktape_Polyfills_getModules(duk_context *ctx)
{
	char *id;
	duk_idx_t top;
	duk_push_heap_stash(ctx);											// [stash]
	duk_get_prop_string(ctx, -1, "ModSearchTable");						// [stash][table]
	duk_enum(ctx, -1, DUK_ENUM_OWN_PROPERTIES_ONLY);					// [stash][table][enum]
	duk_push_array(ctx);												// [stash][table][enum][array]
	top = duk_get_top(ctx);
	while (duk_next(ctx, -2, 0))										// [stash][table][enum][array][key]
	{
		id = (char*)duk_to_string(ctx, -1);
		if (ModSearchTable_Get(ctx, -4, "\xFF_Modules_File", id) > 0)	// [stash][table][enum][array][key][value]
		{	
			duk_pop(ctx);												// [stash][table][enum][array][key]
			duk_array_push(ctx, -2);									// [stash][table][enum][array]
		}
		duk_set_top(ctx, top);
	}
	return(1);
}
void ILibDuktape_Polyfills_Init(duk_context *ctx)
{
	ILibDuktape_ModSearch_AddHandler(ctx, "queue", ILibDuktape_Queue_Push);
	ILibDuktape_ModSearch_AddHandler(ctx, "DynamicBuffer", ILibDuktape_DynamicBuffer_Push);
	ILibDuktape_ModSearch_AddHandler(ctx, "stream", ILibDuktape_Stream_Init);
	ILibDuktape_ModSearch_AddHandler(ctx, "http-headers", ILibDuktape_httpHeaders_PUSH);

#ifndef MICROSTACK_NOTLS
	ILibDuktape_ModSearch_AddHandler(ctx, "pkcs7", ILibDuktape_PKCS7_Push);
#endif

#ifndef MICROSTACK_NOTLS
	ILibDuktape_ModSearch_AddHandler(ctx, "bignum", ILibDuktape_bignum_Push);
	ILibDuktape_ModSearch_AddHandler(ctx, "dataGenerator", ILibDuktape_dataGenerator_Push);
#endif
	ILibDuktape_ModSearch_AddHandler(ctx, "ChainViewer", ILibDuktape_ChainViewer_Push);
	ILibDuktape_ModSearch_AddHandler(ctx, "DescriptorEvents", ILibDuktape_DescriptorEvents_Push);
	ILibDuktape_ModSearch_AddHandler(ctx, "uuid/v4", ILibDuktape_uuidv4_Push);
#if defined(_POSIX) && !defined(__APPLE__) && !defined(_FREEBSD)
	ILibDuktape_ModSearch_AddHandler(ctx, "ioctl", ILibDuktape_ioctl_Push);
#endif


	// Global Polyfills
	duk_push_global_object(ctx);													// [g]
	ILibDuktape_WriteID(ctx, "Global");
	ILibDuktape_Polyfills_Array(ctx);
	ILibDuktape_Polyfills_String(ctx);
	ILibDuktape_Polyfills_Buffer(ctx);
	ILibDuktape_Polyfills_Console(ctx);
	ILibDuktape_Polyfills_byte_ordering(ctx);
	ILibDuktape_Polyfills_timer(ctx);
	ILibDuktape_Polyfills_object(ctx);
	ILibDuktape_Polyfills_function(ctx);
	
	ILibDuktape_CreateInstanceMethod(ctx, "addModuleObject", ILibDuktape_Polyfills_addModuleObject, 2);
	ILibDuktape_CreateInstanceMethod(ctx, "addModule", ILibDuktape_Polyfills_addModule, DUK_VARARGS);
	ILibDuktape_CreateInstanceMethod(ctx, "addCompressedModule", ILibDuktape_Polyfills_addCompressedModule, DUK_VARARGS);
	ILibDuktape_CreateInstanceMethod(ctx, "getModules", ILibDuktape_Polyfills_getModules, 0);
	ILibDuktape_CreateInstanceMethod(ctx, "getJSModule", ILibDuktape_Polyfills_getJSModule, 1);
	ILibDuktape_CreateInstanceMethod(ctx, "getJSModuleDate", ILibDuktape_Polyfills_getJSModuleDate, 1);
	ILibDuktape_CreateInstanceMethod(ctx, "_debugHang", ILibDuktape_Polyfills_debugHang, DUK_VARARGS);
	ILibDuktape_CreateInstanceMethod(ctx, "_debugCrash", ILibDuktape_Polyfills_debugCrash, 0);
	ILibDuktape_CreateInstanceMethod(ctx, "_debugGC", ILibDuktape_Polyfills_debugGC, 0);
	ILibDuktape_CreateInstanceMethod(ctx, "_debug", ILibDuktape_Polyfills_debug, 0);
	ILibDuktape_CreateInstanceMethod(ctx, "getSHA384FileHash", ILibDuktape_Polyfills_filehash, 1);
	ILibDuktape_CreateInstanceMethod(ctx, "_ipv4From", ILibDuktape_Polyfills_ipv4From, 1);
	ILibDuktape_CreateInstanceMethod(ctx, "_isBuffer", ILibDuktape_Polyfills_isBuffer, 1);
	ILibDuktape_CreateInstanceMethod(ctx, "_MSH", ILibDuktape_Polyfills_MSH, 0);
	ILibDuktape_CreateInstanceMethod(ctx, "WeakReference", ILibDuktape_Polyfills_WeakReference, 1);
	ILibDuktape_CreateInstanceMethod(ctx, "_rootObject", ILibDuktape_Polyfills_rootObject, 0);
	ILibDuktape_CreateInstanceMethod(ctx, "_nextObject", ILibDuktape_Polyfills_nextObject, 1);
	ILibDuktape_CreateInstanceMethod(ctx, "_countObjects", ILibDuktape_Polyfills_countObject, 0);
	ILibDuktape_CreateInstanceMethod(ctx, "_hide", ILibDuktape_Polyfills_hide, DUK_VARARGS);
	ILibDuktape_CreateInstanceMethod(ctx, "_altrequire", ILibDuktape_Polyfills_altrequire, DUK_VARARGS);
	ILibDuktape_CreateInstanceMethod(ctx, "resolve", ILibDuktape_Polyfills_resolve, 1);

#if defined(ILIBMEMTRACK) && !defined(ILIBCHAIN_GLOBAL_LOCK)
	ILibDuktape_CreateInstanceMethod(ctx, "_NativeAllocSize", ILibDuktape_Polyfills_NativeAllocSize, 0);
#endif

#ifndef MICROSTACK_NOTLS
	ILibDuktape_CreateInstanceMethod(ctx, "crc32c", ILibDuktape_Polyfills_crc32c, DUK_VARARGS);
	ILibDuktape_CreateInstanceMethod(ctx, "crc32", ILibDuktape_Polyfills_crc32, DUK_VARARGS);
#endif
	ILibDuktape_CreateEventWithGetter(ctx, "global", ILibDuktape_Polyfills_global);
	duk_pop(ctx);																	// ...

	ILibDuktape_Debugger_Init(ctx, 9091);
}

#ifdef __DOXY__
/*!
\brief String 
*/
class String
{
public:
	/*!
	\brief Finds a String within another String
	\param str \<String\> Substring to search for
	\return <Integer> Index of where the string was found. -1 if not found
	*/
	Integer indexOf(str);
	/*!
	\brief Extracts a String from a String.
	\param startIndex <Integer> Starting index to extract
	\param length <Integer> Number of characters to extract
	\return \<String\> extracted String
	*/
	String substr(startIndex, length);
	/*!
	\brief Extracts a String from a String.
	\param startIndex <Integer> Starting index to extract
	\param endIndex <Integer> Ending index to extract
	\return \<String\> extracted String
	*/
	String splice(startIndex, endIndex);
	/*!
	\brief Split String into substrings
	\param str \<String\> Delimiter to split on
	\return Array of Tokens
	*/
	Array<String> split(str);
	/*!
	\brief Determines if a String starts with the given substring
	\param str \<String\> substring 
	\return <boolean> True, if this String starts with the given substring
	*/
	boolean startsWith(str);
};
/*!
\brief Instances of the Buffer class are similar to arrays of integers but correspond to fixed-sized, raw memory allocations.
*/
class Buffer
{
public:
	/*!
	\brief Create a new Buffer instance of the specified number of bytes
	\param size <integer> 
	\return \<Buffer\> new Buffer instance
	*/
	Buffer(size);

	/*!
	\brief Returns the amount of memory allocated in  bytes
	*/
	integer length;
	/*!
	\brief Creates a new Buffer instance from an encoded String
	\param str \<String\> encoded String
	\param encoding \<String\> Encoding. Can be either 'base64' or 'hex'
	\return \<Buffer\> new Buffer instance
	*/
	static Buffer from(str, encoding);
	/*!
	\brief Decodes Buffer to a String
	\param encoding \<String\> Optional. Can be either 'base64' or 'hex'. If not specified, will just encode as an ANSI string
	\param start <integer> Optional. Starting offset. <b>Default:</b> 0
	\param end <integer> Optional. Ending offset (not inclusive) <b>Default:</b> buffer length
	\return \<String\> Encoded String
	*/
	String toString([encoding[, start[, end]]]);
	/*!
	\brief Returns a new Buffer that references the same memory as the original, but offset and cropped by the start and end indices.
	\param start <integer> Where the new Buffer will start. <b>Default:</b> 0
	\param end <integer> Where the new Buffer will end. (Not inclusive) <b>Default:</b> buffer length
	\return \<Buffer\> 
	*/
	Buffer slice([start[, end]]);
};
/*!
\brief Console
*/
class Console
{
public:
	/*!
	\brief Serializes the input parameters to the Console Display
	\param args <any>
	*/
	void log(...args);
};
/*!
\brief Global Timer Methods
*/
class Timers
{
public:
	/*!
	\brief Schedules the "immediate" execution of the callback after I/O events' callbacks. 
	\param callback <func> Function to call at the end of the event loop
	\param args <any> Optional arguments to pass when the callback is called
	\return Immediate for use with clearImmediate().
	*/
	Immediate setImmediate(callback[, ...args]);
	/*!
	\brief Schedules execution of a one-time callback after delay milliseconds. 
	\param callback <func> Function to call when the timeout elapses
	\param args <any> Optional arguments to pass when the callback is called
	\return Timeout for use with clearTimeout().
	*/
	Timeout setTimeout(callback, delay[, ...args]);
	/*!
	\brief Schedules repeated execution of callback every delay milliseconds.
	\param callback <func> Function to call when the timer elapses
	\param args <any> Optional arguments to pass when the callback is called
	\return Timeout for use with clearInterval().
	*/
	Timeout setInterval(callback, delay[, ...args]);

	/*!
	\brief Cancels a Timeout returned by setTimeout()
	\param timeout Timeout
	*/
	void clearTimeout(timeout);
	/*!
	\brief Cancels a Timeout returned by setInterval()
	\param interval Timeout
	*/
	void clearInterval(interval);
	/*!
	\brief Cancels an Immediate returned by setImmediate()
	\param immediate Immediate
	*/
	void clearImmediate(immediate);

	/*!
	\brief Scheduled Timer
	*/
	class Timeout
	{
	public:
	};
	/*!
	\implements Timeout
	\brief Scheduled Immediate
	*/
	class Immediate
	{
	public:
	};
};

/*!
\brief Global methods for byte ordering manipulation
*/
class BytesOrdering
{
public:
	/*!
	\brief Converts 2 bytes from network order to host order
	\param buffer \<Buffer\> bytes to convert
	\param offset <integer> offset to start
	\return <integer> host order value
	*/
	static integer ntohs(buffer, offset);
	/*!
	\brief Converts 4 bytes from network order to host order
	\param buffer \<Buffer\> bytes to convert
	\param offset <integer> offset to start
	\return <integer> host order value
	*/
	static integer ntohl(buffer, offset);
	/*!
	\brief Writes 2 bytes in network order
	\param buffer \<Buffer\> Buffer to write to
	\param offset <integer> offset to start writing
	\param val <integer> host order value to write
	*/
	static void htons(buffer, offset, val);
	/*!
	\brief Writes 4 bytes in network order
	\param buffer \<Buffer\> Buffer to write to
	\param offset <integer> offset to start writing
	\param val <integer> host order value to write
	*/
	static void htonl(buffer, offset, val);
};
#endif
