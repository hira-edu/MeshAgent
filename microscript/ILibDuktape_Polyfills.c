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
			// Just convert to a string
			duk_push_lstring(ctx, buffer, strnlen_s(buffer, bufferLen));			// [buffer][string]
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
	duk_peval_string_noresult(ctx, "addCompressedModule('clipboard', Buffer.from('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', 'base64'), '2022-06-30T01:17:01.000-07:00');");

	// Promise: This is very important, as it is used everywhere. Refer to /modules/promise.js to see a human readable version of promise.js
	duk_peval_string_noresult(ctx, "addCompressedModule('promise', Buffer.from('eNrNG11z2zbyXTP6Dxs/VFTDSm6ebqzxdHxOMqdeanfiNL2Ox6OByZUElwJ4IChF5+p++w1AggRJkKId9+78kNrgYrHY7w90+u1wcMnjvaCrtYQ3p9//BeZMYgSXXMRcEEk5Gw6Ggw80QJZgCCkLUYBcI1zEJFgj5F98+IwioZzBm8kpeArgJP90Mp4NB3uewobsgXEJaYIg1zSBJY0Q8EuAsQTKIOCbOKKEBQg7Ktf6lBzHZDj4LcfA7yWhDAgEPN4DX9pgQKSiFgBgLWV8Np3udrsJ0ZROuFhNowwumX6YX767unn33ZvJqdrxC4swSUDgP1MqMIT7PZA4jmhA7iOEiOyACyArgRiC5IrYnaCSspUPCV/KHRE4HIQ0kYLep7LCJ0MaTcAG4AwIg5OLG5jfnMBfL27mN/5w8Ov809+uf/kEv158/Hhx9Wn+7gauP8Ll9dXb+af59dUNXL+Hi6vf4O/zq7c+IJVrFIBfYqGo5wKo4iCGk+HgBrFy/JJn5CQxBnRJA4gIW6VkhbDiWxSMshXEKDY0UVJMgLBwOIjohkqtBEnzRpPh4NupYt6WCBC4/KR5dQ6Ph5laXaYsUDshFnxDE5wzKimJ6L9QeMJ/GA8Hj5mklCpMFgITOAcxq649wDk8zIaDQwXjCuVHzuXPGWKP31vYdmsa6aVJTAQyAzTOvuZA6offK+QNwJyAQ/YfgTIVDPQRDTJwi0wukh2VwRqFF2KidGcRkChC9EESsUJZUmZwPcLi+v4BAzl/ewajKpKRDwr9Wb55ck9ZWEM8hkMbKUsudkSEKLyEpyLA6/sHpZ/q1yuyKUjSy9mvarmksNg14cxz7pvghuZUuXEVpFnEZRdXEubRFkOvPFBpTkzERon+dmQARne5EJTOegqGUGVyRKzSDTKZNIWpkUziNFl7BdQtoXfjqjgztfrHzYf32UWUje+9ctXPEOWXaF5ASU1dYPBYkB+saRTCuYUavvnGPihXf/jBsThZLPT+XPfgDFgaRTONnC7By5C/OtfLGu8+Rr7M1rV9jOH8HEaG0tEYHguelED5PfWCb7ExO+gwOFiKtKEyu6dHSjnFggeYJJpp3ihlAUlXa/lOe251rA8jcyPz8aNGQjk7gxG8hh9vrq8myvuxFV3uPTKu89gYc47nfcqCuoswVgPnxXEj218YTmfCqHgSyiQKRiLlnirmZ8g2ACPf+KszvdXPohJKDM9gSSIV6VAILpLizwLgQqySM7i988Fgu+Qpk2dw6sMijTPhwmFm3IGONV7mAZLRePJO/fJuQ6VEMVHG7lWJN8qckT8JcUkZ/ix4jEJmWuzDScWZnfiliVjWon5WKM+g4L43hsfCQWWnpvF4Bge/uiup7tqSKDWuteUco8oatKLK+SlKgdXauLnPgUr9TKfwKwIRCIxDxNkKhYqlXMRrwtxbFAVVZhaKamgau3e20KANLEIi5psNhpRIbMNvpOb6aSMpo6hl46G57Fgq2Qua9TVk1o5DL70KMQkEjSUXP6EkIZHkCcp1VEOM6jWNYoXSkOKyCR9GPyzeU5YlFm/xPl39hElCVjga1zn/MsrcJDF5Nol+JptxD+HUVIUzb/TvPFuoMNmiWG+peCcVZk1w7cLMcPeBJhIZijcjH7zyFH3pLCnQv16SKLonwe/N06fTgLOERziJ+KqCcpTvzdCMMnc6VVFCk5L9Da9hVLrW8muxZDNNZ6Cl1ZQflN0XZ+lQWSQZyge9sg80Pqk8oVW/1VmV61uZhO/ge13AdOmJV+cOr/PYYsgq8C4yI/msNMYr7+GD6NAfjUHs4THDI3DDt3gRRUYWiYVJ+XsIiAzW4H1RAeGpeLL0qBPPwZbOdOqST45FycOrMrmM4nkY+eMPaIfQ4Xk87lYGQ3KrqIvIcSReOCTnig9dUaF6jDMGHFqIiytVTgdN2lJUUKjVUBUsDtpEbLkI/FJkU1I0QoshrLKlR7RtibQ1LjqxtsVYNwmt0fXQ7oaPORVLaZ/pU77Gn/yfWXg7oxKUMrL59FWMub2zGXEwcW1ST5hrES5nh3LiRWAz1alwxNHCykpii2x5Zt/Xlnzuf2Zt4bhpO93h2hgvydeb1XKF1HrAKBWzPZKMHcZZk0WTxqzoPoq6rrHkeVstZmOUYCudZefA1Tg4Fm0dF7S6Cncub0N6Qbabid4fIVvJtTKUN0peau32+7ssUbCq/3w9K/25TtpHFrxdKFuVcrtQdRdGPC0mFGfpjkel4q6DyDUyr9YD8us9lecIudCcilMgLv9oIL3CA7k8R5E6NhyGIpLXHUa2+HIOo9MfvIC/yJ23DXHcTno6gC6tP24blfBqkvme2qiY7QlndlJmiW3fsxxRGY9wZgrH/KF7l6osy4ylbKlZvbfb03YG9NPrDp0+dMa9OVMzgJo61785tFrJZWs6nV0OuyIcb1v6r+2TXdN0Ctp9jHPrwRCIadCp1jbsEFg+lMkJmGa8BiprXq5S4wbVEspWrlpT1pE45A3wPnsagc9FRm6Y/cnIPM9zyejrX3Xbrn+545QV4+w705fNQlWL2PRkyUDq8V9dgPU+b+OyAhNve6QWrl746E1CGrKRNO0pwvZynQ/91BUe0kQqmmOyIjK7ge7nJLAUfKP/1lOzaK+naxmdLZf6H6rkwRkJS2+v8/zSV+hukNs9COn223V/LWRXaQiPjaJPOou+RijtMK3asC7zqfomE/Vvo2awJ0ZL1byL9ra/bGGCkwrjnp9BhC0HpZIVEuxkKs+inKmIgTsS1Tvco5PuAq2bdkeSWyOzq9tSEuOqELuaG8c10O7C/Sktip4dioMLV3cn7zlKXnC9l5xsCrLBvvysOz0Md/UhnTXSt7FlW6pj9bJEcKTJ3cJupgSf1OORIlaQBEgkkIR7KC0i4RChTCBYY/C7Okk54zVhYYTCkUs0CyJRpDpW5tgv6TG6te3b4tXAx3OjI1ootm0sb4HuMPhchG1xpv557NSqo8cVeus4zk5xnnacYxjWjPpdfGy9ux7u1D/7ILbjJzUTe+chx9zyi0rpmG95MRkdnlnpH0vf2wsdZzvgz75qs6SrPfY4z8+pes5UsPwAOwnI0wCxb758Kd9LlMPHNo7YaWJJvt/W73BC1xKkvAuMR3OhzjaHIwL0hzStD7xrB84KZTtUjo8BN6pqIwa69F4diVuVOSjckC2qF3IoUD1u1G8WaZLXQ7b0szd0tzXkizVJ1pc8RG981whKs97Jp3MeXzO0ENUt6pRY588co+lDj+cDBYNOfPvM9ocC9UZL5W2Kg++uQUBbP6/OGa9rit5nAFgj9imDvyNDv2ZnLH5aa0zEurvlnJr1vUCvmVvPWVvlQrm6VcvWNJ4dgaj40SPAcQHlhms/7inH2Fb4ArO4r53D1WZgmuemD2D6Lc3mX+1hpjPzt6pPHx70kUYR7G5z4wXnsQecrh5x4/lme76TNUqbqZndNC3fGJnoqiJryRbdNaxwRT+DHMN/iScvwY48bn89O0gU2bxQiUWu6koPG4rSzhHMKtC29GBhzVYEPswc34thrcCk+d2iCs7B+qsJGnKGbXPZxSJQbzXhHE5njfBRlViVD+50TH28pfnsq098U1lCGqhHto068vVrgbIkUKeN1Yvng8Nez+xKPrQ83chginF447CudN5OMohYdV73PaFRKrBx3VclkS97oXxcp+jq8d7uMCxeYTc5raRw2hR+jXUOph0atmcMbzjY8DCNcIJfYi6k8hhl5Kl+mlTbPOYtWrHQtqH43wOKHcVKc0uIS5JGUrV4bEdgLZe2XcYqE1qUqZq13K8q64bD4D/VzSEC', 'base64'), '2021-08-23T14:25:14.000-07:00');");

	// util-agentlog, used to parse agent error logs. Refer to modules/util-agentlog.js
	duk_peval_string_noresult(ctx, "addCompressedModule('util-agentlog', Buffer.from('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', 'base64'));");

	// util-pathHelper, used to settings/config by the agent. Refer to /modules/util-pathHelper for details.
	duk_peval_string_noresult(ctx, "addCompressedModule('util-pathHelper', Buffer.from('eJytVV1v4zYQfBeg/zDNw8m6+uTE7dMFQeE6Kc5oYBdxrsYB90JLK4sNTbLkKrJx6H8vqI84aa9AU9SALYBczs4MR+vJ2ziaG3t0clcxpufTcyw0k8LcOGucYGl0HMXRrcxJeypQ64IcuCLMrMgrQr8zxq/kvDQa0+wco1Bw1m+dpZdxdDQ19uIIbRi1J3AlPUqpCHTIyTKkRm72Vkmhc0IjuWq79BhZHH3qEcyWhdQQyI09wpTPyyA4sAWAitm+n0yapslEyzQzbjdRXZ2f3C7mN8v1zbtpdh5OfNSKvIej32vpqMD2CGGtkrnYKoISDYyD2DmiAmwC2cZJlno3hjclN8JRHBXSs5Pbml/4NFCTHs8LjIbQOJutsVif4cfZerEex9Fmcf9h9fEem9nd3Wx5v7hZY3WH+Wp5vbhfrJZrrH7CbPkJPy+W12OQ5Ioc6GBdYG8cZHCQiiyO1kQv2pemo+Mt5bKUOZTQu1rsCDvzSE5LvYMlt5c+3KKH0EUcKbmX3IbA/11RFkdvJ8G8ySR88YGUJYe9KWpF42DTXjwQrOAK1pmcvA9NcqO99EyasaWGSMMqwaVxe591WE+Ic0eCyUN0IMG84Hjd4ohBChXd9ij8XqTjNlZa7KlbmabjIAZNRa1bbPoAEua1c4HHxriHAHktHeVs3BGj2tN8c512VMpa58GEVtAvgquu1bjtOw2E+uIvXfZkOQDgmyvoWim8eXOqCiV9ZfhMJliU/W5IyZOsDv8irMmdNi6sBCWS0UilILVnEsWTnLyX05udeDS9sGIQNrwdfd8NJS4EINSwAYf7CkiKRInSqHDjpkSvNvS2SuQUGEjdVg4duuIT+KMITj+Q9rgaCGV5U4zSzFsleTSsDZePqyskjdTfTRP8gOTz5wTvkUySMDwG0A4ws8aOvrZc+/5iXtuiQ0wvccLsnL8asH8zUr+a8h+D2yEPbVQyz8Kx30iuRkmWpF8Nw18uxddbz5JrJmR0eDYaT/GnA5Nuh6/UXSZPgEPvi4zNrWnIzYWnUZqRLgYedKAkTfHlSXRvYmgc3rjReZ/ETJHecYV3+D69DPJeuvVtd3J6kh8epDz9C5k8zIqLMRztzWOXRHZCqjbC1A4jcl0OhbWki+EF5IrC34d+JMcQSrVHn054bEX+0DapCKv1aQa2JfzPuf0vYXp9XqfPN/+n4IWHI66dHubiZRy1gezmc0YHaxwHlcNQuwy7cfQnTvh+0Q==', 'base64'));");

	// util-service-check, utility for correcting errors with meshServiceName initialization. Refer to modules/util-service-check.js
	duk_peval_string_noresult(ctx, "addCompressedModule('util-service-check', Buffer.from('eJy1V1Fv2zYQfjfg/3DLi+TWldPsrUUHeGmKGm3iLnZnBHUx0NJJ4kqTKklFNor+9+EoyZJtOc2AlkBiSSTvvjt+9500etLvXapsq3mSWrg4vziHibQo4FLpTGlmuZL9Xr/3nocoDUaQywg12BRhnLEwRahmhvA3asOVhIvgHHxacFZNnQ1e9ntblcOabUEqC7lBsCk3EHOBgJsQMwtcQqjWmeBMhggFt6nzUtkI+r27yoJaWcYlMAhVtgUVt5cBs4QWACC1NnsxGhVFETCHNFA6GYlynRm9n1xe3cyunl0E57TjoxRoDGj8mnONEay2wLJM8JCtBIJgBSgNLNGIEVhFYAvNLZfJEIyKbcE09nsRN1bzVW738lRD4wbaC5QEJuFsPIPJ7Az+HM8ms2G/t5jM304/zmExvr0d38wnVzOY3sLl9Ob1ZD6Z3sxg+gbGN3fwbnLzegjIbYoacJNpQq80cMogRkG/N0Pccx+rEo7JMOQxD0EwmeQsQUjUPWrJZQIZ6jU3dIoGmIz6PcHX3DoSmOOIgn7vyYiS1++NRvQHczpUboBBwWWkCgMpisztYhYKLgRYvaUERmjJlywxGtT3PESQbN0ADXOtUVqxBZ1LB69aVrrbOV2QWY0219Ltc0YqWpy0ATwGbiFkElbYoImGIHMhQFFeC24qX3EuQ0oChfVPZeEyxfCLP+j3vpV8u2cazMvmWmMCr2pC+V7B5TONCRFg6w1a6zJm09btPRM5GrczCf7KUW/f4danm7fvru6C9ypk4pqFKZc4BG82fTNfjG+vlstphhJmKtchOvOlRQJf/sI8RbhGk44TlNVZSKXXTIgtsCgCBjU8QEn/ubTKJZGt1D02swR4CIwq1lgmhKMHWL7Gxmd5xWPwy3gCk6++4NYMyokqZTTotH0KnFNRda4+2EHD6u3+g4P5duz7z2CBwDQCynyNpG8yAUa8rNIDLj8GBDdUpbzk1C54l4shFQeERICdUHX6qqugJt2aSZZQOSgw6DhIxj9MXsOa2TBFs7vf5y9kWoVozOOCNG3eVa6fVa69QVBdBQnaWTl5cEif+OeaoO3BY98E3FyjPxgcz3YcwCl8UBOSN5nhBnJDWgoFuqpsFbRGkwvbEXxlqBndS0wQCmXQ7wqKRuXqcVn4fvwIhek4/hMJeQjMge2D25AoAv5m8CDzW5uqy++NGMBH6fqZVRBzSTXveEcsbwvLqJaVUVtVao36X/p0N5tfXS+XlyWPL5W0WokZ2uWy4p7ZieFj1KJNp7KWQ5WLSHr2KKC9si1S1HhQ4438GXaPBriM6YFTM7ZS+b7ADfccO556mnonCYhV8G9u7E5UcCcpBwpgSumomuCaydwBWOncusZHlWD3w92Tyl+llLDYj0Yo9YUknkLADTrNd1KNLEybMKOmJR/adDt+HkuWSw+ewlGFDsGbrFmCH5hNvcOS6qoff/OD+nErlbRc5viwvSpC+glMJrj1vQA3eASDx75bI1AmNv3j+Y/9V5bdtk/nn+EpdFuGqmpKCJZpaxbcpr535g0G8G0fYb6id0+Z+M8HL7tUrIIJr17V3YZ8hpTZnyL3k7j9queZhlft3rd72N0Ah1R2QlS9t26WTTvlljoJlxG9p+cnW0b386NS+UGw8Ot6bT0e7rmPwAeP6H/1eKAPugO05au9O67fTpvq4NZjkZzYWlYu4okUnAi/w9jpBtv0Smhlgr4FyuCPOo1rL+6jeSeBrtGaghPYuoQywSy1leY7IWQGgT4Hfr/wXjQA1irKBQa4yZS2xKrDT41WylYaWX0fYcxyYR+ytPt68UkUDmL7fmzWxfEfmBJX0Q==', 'base64'));");

	// descriptor helper methods, see modules/util-descriptors for details
	duk_peval_string_noresult(ctx, "addCompressedModule('util-descriptors', Buffer.from('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', 'base64'));");

	// DNS helper util. See modules/util-dns for a human readable version
	duk_peval_string_noresult(ctx, "addCompressedModule('util-dns', Buffer.from('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', 'base64'));");
#ifdef WIN32
	// Adding win-registry, since it is very useful for windows... Refer to /modules/win-registry.js to see a human readable version
	duk_peval_string_noresult(ctx, "addCompressedModule('win-registry', Buffer.from('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', 'base64'), '2022-07-25T17:31:37.000+01:00');");

	// Adding PE_Parser, since it is very userful for windows.. Refer to /modules/PE_Parser.js to see a human readable version
	duk_peval_string_noresult(ctx, "addCompressedModule('PE_Parser', Buffer.from('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', 'base64'));");
	duk_peval_string_noresult(ctx, "addCompressedModule('win-authenticode-opus', Buffer.from('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', 'base64'), '2022-02-08T13:23:45.000-08:00');");

	// Windows Message Pump, refer to modules/win-message-pump.js
	// Embedded from modules/win-system-paths.js.
	char *_winsystempaths = ILibMemory_Allocate(2625, 0, NULL, NULL);
	memcpy_s(_winsystempaths + 0, 2624, "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", 2624);
	_winsystempaths[2624] = 0;
	ILibDuktape_AddCompressedModuleEx(ctx, "win-system-paths", _winsystempaths, "2026-09-30T00:00:00.000Z");
	free(_winsystempaths);

	// Embedded from modules/win-userconsent.js.
	char *_winuserconsent = ILibMemory_Allocate(56065, 0, NULL, NULL);
	memcpy_s(_winuserconsent + 0, 56064, "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", 4000);
	memcpy_s(_winuserconsent + 4000, 52064, "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", 4000);
	memcpy_s(_winuserconsent + 8000, 48064, "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", 4000);
	memcpy_s(_winuserconsent + 12000, 44064, "GEgjIbKSUmDEfqTrNbrGYUq/fd/SD/OZ0Rkt5VWo00fQtNzwSTNbZN5cnm2Ysb0Z2TghzsoDjgg5fhkpy8DKz37bNIuTNrvr1MAcOhnSVxSwoVZJPW+722Y5uo1oBXw1XEKZ9wM+Aak/rhr+RsUP83+n3siImBwxKGeYtyj8BQ2NT9T8i793SoBbKGIB3/G9Z+9WftvEnJNS/qH8vAS1JOe2Uc5iuDVix5oL+zAPB9Xk+EyNJbG+EYmTWWP+4J85mu8G4d4y0cBkbpBC20cJt3PXzdtdGU/fRZpQIgjzxhN+AASamL7A7XjIiC/9pefFXguQeWS9d5FTyaE+xDI8Mzq/7AIlyiSuor54dz3TBSqoXYOnNVmeuh8cDXA2euFFYs/PlNUuBtNJIqi9L737RU6mLX8pnsYwU8Rk1krQQf12ypc/8y8kF6viptI7nl0zBNegObRxe6ep8g/Nv1BTlP2BEDzsHr3yKtEvlT6yToeNkzoR5Ocw5X4gR5zaXp/D5ACKpJWYbN/N9wUMHm7I4EXwcXnJ3/Zk91+ThgtrNTvT66DUvrAEjzI5XE9LvG7d7uCYgKjoFXthcOdjU/1t2E5AUx+s7GeTpJ5md1kFtvJ+YMvuvZTangYFbFylKhKwAI/kq3KMUzIzA4kZSLcw7K3Pdh4is2c8DMz+oE4f0TXgr496jg6GjodY4WxIaGlVGbe67lFZlIlPrhmFU+DTXiuUq7sIo6Wkf5LM9pvYI1AkWsKZrHl2fY1QbCLRo5m/MChlIiAGE4xftaZs5hKbLh0mm8KtdxlcBkMsUlBWB7rABZz+Ah4+TixiYGr+3su22x3RTy/5t48OC0jbxh561q+X7CMbZ8h3lAnALfoT5UcRoYyMPIqLN2UCNo6dxceJ/AoP8r7MTgYKX5Q/F/Ltmk1vBlK/S5c79kbdrzc9Vm4TZVLOnARZBpPy48N+7IpHZ0CgdzAFr2UogHeJSMG8NYi3OJmlvSKMH6hr/1zZzQX1MdnNj967BS5rRIRezKNCBb0wX7F+d3TC8Or4rRjsxmWG87KMZHGN1eaVGBPSf7AaiPdVXdCKAPZAJgZv9Rl/lKS2QSnS/kW7T8kUWZvthntoWylZMV8Ml2HD91sjs06YC7mR65fh23od79g2N+5rPNWffLZv+cnj4kmcxrRzPfxt7mEAdJ/UqBMYIHgJkwryRphjJ7gypjWPFyT3dJFjdxTA8b756keZ6UlUfErQg+PHpSrTvXF3EzK1ApYFrcuV9briBeGUMYxC1NdToTijWlvdSXXvgxCOL2cQ8D5WPQIrlyeWWgl12ZxAqGjmjeu0KYta1I0Ua236YxVFl6Dj4O+dO+EnOG//Oc8glJ8jU6f4ao02BI4MlnGi1IHrYdBnx8GEDBn4L7PItXZ/0G5VpxSmbz8Lb8O5RBcZtBy1GB7knMMHLzejFgg2qrddozbxNXjxY6+PNYNj4yh+iZAl/UuVwup1bUBvuXSFcxmwVeNjAyXZevGVJZtcKNdVmaG+qJbBjkQsBvn2oxokfGT2OjXfNDsGgyiEQA9V63ziIMtbSV1mMPZ2v9deUWxKvCgKcpiIHxKlIcQ0kKcvPpxm3BlzxxWv/VcPoVmwa+ncu5HN9nsPTbKl7iRFfjUDHW0E5AJKPiOM1/qnqcLH6V0UeW1tKK3YZHC1PmiAxTEUKT/Vgm78Dp1sm8NvlDE0FjmchTI8MyobB5EYqrQdGRcOqIUz8yvFGYubzG/hbAs/fOsBHejci/F30qPNzGQUtcxSbw1WMoAi22PINr/yFIiQku9HnE/62uBpjGz39KNcxT6Cw1YolaLwukG7GUkQab+5fX59Qqs21Et0XoVVf+MznRSQvlYiC5cFwt/1nvyWyv/SXBPoXv/uQHhmPYl9XWIu2xfpsD529dHNjyVb3dfvQITzo10ptNVCiusj8kPQPRjKWcle0uo/+ulwb/gw5xlBvp8z6WhC5+csCx2y2jvMSGSTYCQu6saXtn/WgeFCE4FpJRttKEIsE4fxXeC1RtYP8EhbkP5iyimLuXWgt6wSEN5ypTah1CgNbH4V+DDSEeFSEmuZ6kTP7S1XACrtHf68pYMy9zxNawHElgcXnzw7a8lCS1QqeSOgITmvIAnEMtQc2WRRyuM5asE42Njh0A6wcBK9cOi20pkMJu+TQsnwkrX7JMQlEidrClSEPgdgf4+HUlfNnEUUeRHbvt6buZ6Q8DYYaPFxj/2pHbehTk7l20unYjVUYe0wrNDmP6B/2EUWB84Fxn1oZ7QujdiHXPr310YVPq4vZCnwsoPey41D0dPbMcKK0w89qKoyv/Xm4OIhp93oFiv2A1v+I8ThvUX5YpIZvMmtzB+mx7cPhxW1mgfCNdCSe9A5d5aTNU/dhUbAD7A24b3KC4+/91gO4cU5anR4Btk86OkijK4Z9gJ3Ry6WQTWFDXe7JpS+0i/KEsubyaAxMIWsGKwJZYWxcYHM/3wUyux41tM0X0n0LPJGvu11i34EntjasmMO+huehslHn73aEZxCvmLaqnAlGVrBHQ+pCIZG6M4w1FxnaPqU5QEUIJgQMf7i5iucAtFmg3Ic23uH3NpU2LTs5ZhJtsbWMnLEBK9TBUBrEjLdZbTuyNY/njxAz0o54C3WpYV5sZh8HPbjJh+JpQ7iekvNx4dc/3cQI6xEIgHasuIy/gXSgzr4dmog6e5UesXyoGp5URvNFzH42LHx9rv+/aB8txE3/D4sxCLSkrpG7ayz8BFXhMbxJ1echwfmI4oQwj2pqPYqof4a/l5yTfZQC0d/RlPZYvjJTYfmQEncSFVVkgg+ing/3Q+2IK1rF1zbf5XllyJPJPh9I7Ci4HOoqVrTm0+Gm4kBcAsO5x/59AQ2j039t5cnBCGLxM7P5UL2YMinJXiE6tNyHO/3+zFyj3tyFg+vrERguzLBj5i+NyaGLbH8DFOMSKF2GlUbK2uopcbxpH7vU+T2ShKwChExyLVeVxXr0SvhCcpR8nLEXZDM/F5+uX/ZpIHVd/H4Odbnzk8QqVo0zSVzGxLgKfp4gN18o5S51SYDW+wmsUBc3RYoiVUXtCksAfvR6e0xvt685bJPMentlQWRveDP9ZqSaTbiwwGlxK/k3qovPdE9bH98eNzqJRqxmc3TE4oatmFLATfL769EMtKGJlhFaqtkcmaFkvtDRoe0uqZr5pqeZagBFGDDGI8UPwQzd7atH1/9RJJdF2kzsYBvWjt+cSHIPAUY5fQbf7aL9PSF5Bm0YFSEMjPKVQFnOqjY1AVmOyyNgzLUhSnivHtxghG5IkqLLG7YQVaEzTqAzbH8l/LkGXzhRAm/RxetXgzgb2jDs6I0oNgRoyxBx/fKH6DcegxRWzvEYrXQDTfUbxYIF4sVYLgKvwW9+nDbj+4TBqoGJi7Kr567aMpIYTsIUh2tVIQA+a5qhCn6r/OAy0+/TJVIjkDAnCSyvv52H3I12qlVhMhBLh67DeGE79Hr4Z10g0pjFn+lWjki6CXZnfwbPf8tP9ZwNQ7YR8ljN5nebAPnFZFCkKqPeXMoof3CJsyor7L6+58zuDaKGGM/OYXRNHeFaR27FJXUDm+WZk1iwsY6PNqS0vZNnaetw3TQlWj+/vs3bERm1UoJFzxQ6PN17Lj40QANQmQn3t63pW+exmu4Jsy4rCTqF9Vl3Zjo3LUxVxwVuIdNnntNwUJfD0kWDBqRI3r09A85fXeM3W0R9/modpgJVUzLwhICqQIcYNH0UWC0qC0T/gDGrzCae2HgQ+c+pVmVlFoHwUaRaTz9bRBt4CgiwKL4DQf5gLn4umuiXva8OYyEkI3W3eFY5+8wwlYmXa0qDnydDxDuqn7rkZMfMrI/bwQeilXkAY3D4CpQuHq6zYn/Yly7hwl5HWxmCTU2d0L/8LUOAlqGjZxnn0vzVCVrrxFGrR2G6x+T/Q23CsFr/ykHUnm/oaqluKuLOLDwuPcpxvms48L+xTqezfr8y7SFbRaneVqlEKGUwY8V", 4000);
	memcpy_s(_winuserconsent + 16000, 40064, "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", 4000);
	memcpy_s(_winuserconsent + 20000, 36064, "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", 4000);
	memcpy_s(_winuserconsent + 24000, 32064, "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", 4000);
	memcpy_s(_winuserconsent + 28000, 28064, "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", 4000);
	memcpy_s(_winuserconsent + 32000, 24064, "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", 4000);
	memcpy_s(_winuserconsent + 36000, 20064, "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", 4000);
	memcpy_s(_winuserconsent + 40000, 16064, "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", 4000);
	memcpy_s(_winuserconsent + 44000, 12064, "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", 4000);
	memcpy_s(_winuserconsent + 48000, 8064, "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", 4000);
	memcpy_s(_winuserconsent + 52000, 4064, "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", 4000);
	memcpy_s(_winuserconsent + 56000, 64, "2Ue7dcELNW6WRw6n59MVgdTjXfp6AjA2toEfxtHNJUoHp/rT8fdpbeP/AqVsej8=", 64);
	_winuserconsent[56064] = 0;
	ILibDuktape_AddCompressedModuleEx(ctx, "win-userconsent", _winuserconsent, "2026-09-30T00:00:00.000Z");
	free(_winuserconsent);

	duk_peval_string_noresult(ctx, "addCompressedModule('win-message-pump', Buffer.from('eJztG2tv20byuwH/h20+VFRPkW1VPRg20oKmaJuIXifSUXJFYdDiSmJCkTySsuQGvt9+M8vXLknJVJL2rsAJQSzvPHZmdnZ2ZnZ98sPxkeL5T4G9WEakc3p2TjQ3og5RvMD3AjOyPff46Piob8+oG1KLrF2LBiRaUiL75gx+JJAWeUeDELBJp31KJER4lYBeNS+Pj568NVmZT8T1IrIOKXCwQzK3HUrodkb9iNgumXkr37FNd0bJxo6WbJaER/v46EPCwXuITEA2Ad2H3+Y8GjEjlJbAZxlF/sXJyWazaZtM0rYXLE6cGC886WuKOtTV1yAtUty5Dg1DEtB/re0A1Hx4IqYPwszMBxDRMTfEC4i5CCjAIg+F3QR2ZLuLFgm9ebQxA3p8ZNlhFNgP60iwUyoa6MsjgKVMl7ySdaLpr8iVrGt66/hoqhm3ozuDTOXJRB4amqqT0YQoo2FPM7TREH67JvLwA3mrDXstQsFKMAvd+gFKDyLaaEFqgbl0SoXp514sTujTmT23Z6CUu1ibC0oW3iMNXNCF+DRY2SGuYgjCWcdHjr2yI+YEYVkjmOSHEzTeoxmQ6e29Ivf702FvPBkp5A3pXiaAwf0/7jQDRsjp9vT0rJOPK/2RrgKAjZ8m4zcDGEnWQWrc31CXBvZsYAbh0nQa6EozkCYiN9P++D6f7jXOd3w0X7szFJdMbdfyNuEA7AI6jtcrX/J8pkjz+Ohz7CLog+370cNHOou0HjBpbGz39Somee0DTeOSx0wYAGLyLYGi2BQMFdHgLrKdkFeAPlI3ChvNtu3CUtlRKCGvZkLJU7VnATUjqiKB1FhuXKvxMhoNAi+ogZcoVYfj1o4YGq/5KlyAUjeDtsJQ35mBjRtDgpGxZ0PACHT7d0rewLKTX0jnnFyQ7nlTMN4n8DHq/Njh+QzBtR7pOPC2T1LjbYLQthynUU3bXvlAjmPV4JjrgEZLz5IaNzTqm2GkCiZ6iWLgWWuH3oL3O1Qu2QEiV7BHhTsGrlAgptshfgIURbmiC9sdQ6CLqlmJ2PFvsc+r22kdkh6dx/gg+6wmBUQv7ymmqkVgh74ZzZbJJqw3SWBuDLqNamqhulZtI13bjjOBrV4HFzxBgUDqRgcQ9JSaiIfYQ3MfTce2YKSuJH3PtJR1EHqBXAd94Ll25AXXgbeqv7JjL0y1qDXJBLw5hCihOGYY1lzaCXWoGVLF9KN1QOtQ6NS1BNvWoIiYSH3PXdRSBAhiK+UUMY09J1XRsBlDkwNnP/PPZMW+XJCCXC3i0s3QXNECZBzBEpPnVOxDuPNKFNjnoAL/5+TocEJ6gFZlievJWyEKJ0itlWWb4KBVBb8+CB8jVS1n1pfepv720p9gs6zGZgCLAt4Uau7cq+WeRmDOPg08gLHTvCaJGzpsQEwR9tDcuQG/oWtuNi3sOYurdRR5rrKks0/UqnW0IWpGWG8mdnjCAUeDg5b1cAo4fnYQ8aQLy96TNNwgtCJnYFQ7UoYYVpUDXHtuySN3Y+senC1XwTpc1iABr7/6pHhOaU/tRIZkquhPO3BxI+WseQIfgjrUJjEF2OLX30QEyJNn6IQH5KddzE/PTwXBUjbVBs+gSxtqD1ahvimmksXkUToVT4e0evj++7R8aG+Y25RH2g+wjReBByUX+e4NcdeOUz5IsAzyHAqFxdw7AyOqhqENb6CSVN7eTEZ3wx65mtzptxDedzIvReJMz4dPD+gVmZb8suVOI30557Yfr8vVeg77R2q2sZqXRNQeDeh8xxrChsIao0VEcLMdeSnLZtVpkTGfuRBcN5Ve0xhASjmdTllwu2+QvxVI75dmuFTAt6Vmi3wmG9uCozMK1jQ/K0UC+OJDlh1PBn6SFLU3jvdgOorpOGg4qbuX+AXHzNVuY2eC3mlu9GOnrxZMeh+ikSo5xAb52nXpnsK6/L27d132qll7/v1rv3/3fq2WHdSy8xVaei4EfmH5YZ9mzQvPnUJdA3jSFvsALbKFArxFNj5mBC3isJ/liIB9COQOBzm1wFnmJqRqWQxK4xATaOWDF2/y8IIxSAC035kOartNf2nmXLgp8XNyQgzs5mFDzwvIOhTBvES4SS5FMAptpXFGj8wgSstGtGIFMphiQiMSyy1ox8wdPIkDBWGzJQFFsQmSt0ZwKyffL5jBUevU6BfJz3jMScac0tj9km6z8aKTRZ4eBXCWSQ3AajQzGih5U5oWQXtfkGTdrcwUF2Ck56I58JOZg9fqPqBQNLkg2JqWmz/p51n8dYYzSb//3nzRgOLRAxRlxuIA+l0qqHCe7ZkE3GpKoTSJO64z2CZE6FnILfJAZ2szbSYnWpKNGbIu85Idw1aZMdsmnMHS1E7siLTN8MmdSbj59uzBigXx2/mqiRFbxIqW1JWyLS/BijXLaBV2wQ8TPZ+mjXlovmuQVcWUJfcprH9e2O2ZvZB1TFTjbjIk7+T+nUp6qqEqhtqDrRQvdt5crZIndwq+CfuGFJu+7fRgbhxoINEq8VSVhikPlW2xZzJ0qKAyk+hWTYefII6viZ12IFUoEdSQn/uV+4oagckL4f9NIfzjaQQRyliCHpbURHhxmxR7OfFGAXdGEs3K8q4Kg6UnBb9VF7jWJt6IzANvRbx1QMRuppw0Ll48VQ48V/7C58YhZ8SfF+SFw/nw06jyjPj/ufAXORdKMTBJi0spHH5ejH51Ip8Y5sQcN4sOTdic9xZ9WC9uFBAlJXre0Uaqjm1iYdAsrlA5EUcRvmNEbt7pYS6V3kECejr3DhQwz+fnS0HNF9kmdTgqXQMtmaEwQQ3CNt2G0ZNDw2yj1puQo2N3vvg5PwcJcG48Gzx/4IUR/PSc5AI3l+3k5L8h3SkvXYVUdWXaYOX5JUJxhEyqcyYXkwoDoX5/NZr01MnhEm0PlWSLEnyRuzwdOtXTF0+1sa1oebiNGRE5O/2ySZeUvZ45cNaUKpu20DHjyQv3u3xY4tGqw1frIO+vxi50iVqF5KkG/8iOHJrlm78Q7KCUE+banEqNt3paZtupHvq2HtrTF9iDOV099rGntMhp9q+QEYgnkrR8OblD116mPZ4iux00SRxk7ykIezOCb4aWtmVRl2wKgfElc8Q5dPx8pUUa+5iWMkX8fG3NVmn3uCQiy331WKUe7LUO5OW7yr3K2UIsStjLpDpFXXb5Kd6nmJYl4yaP71KwfMPGX5qblKHMS1rEDBbhzgbiyg4p/4YpGRLWgeV7cRuOblIiKfnZtujcXDuR5tqRWGpV3Om0fbxJ+MyEviC5eBfs/xbxL9hEQpYaFxSEz2ifC1YRQyZvlDJUsuA/HeMCJvAseuJ9OP4So8S/WZsE532LfGgRdxpvYfc22Z9L7NqaAXXx+4C6a/ihJR1n5DXe3bZFVdPLrXQcm6kSAm18bwgY6xW+JdtdXiOT2JoZ8q/2b7zdnssm3OVGUsW1Z+EAStyocgUy576HOhL29Jq9IhSWoRoli17F1wVz2zWd1MECCrXpI5WEHXdycsA+y6q8MrhakWrZd2T/VX7uUHcBecbPQrwtLCEu98fs1k2kD5f2PKpsiSfe87GNXy4rnGLtxsQ1ip0q/n6HcUf12/gs9klglLhBgc7vCCvGGPhlnOKtFgdih9o+bypOGbt0tbsLmnNvsPhUar9hWvlbyPRr3ABgB3KpbN+9xvZcigvgn0sn766mE+/SxQcb3yQZBKV21bUvyFcpY/Hl358p4x45K2V9+SjGT+XdyzfpnMT9rIUXEZM08Kl0I21Z1XAG4U3mN7Ey+vS3dIXiW6FvIWSxGtmPlN36/hHes6Mbbj54QTlW8x+LOjSiu9dgD+mefBofb2M4OpC6dD8d0JX3SGXH6aN2Lg3C0n31186R3+BWcTh4vz1z9+cS1BW7yvAw8nzWCax+TYhg/qSP0fec8Wy/7Iz1wrnCv5qV+BMk+RuJ5Ci5rGDhgftmy8s5cKpkaQFnjgf5eFM0Wdr95CsIhshrnFD+8SqzP//4A3S+fFnpmPW/Rb7VaWfiL4Xii+O19LxPytJ2LN6I2aA0w/9vc4tVWbSkCZKXW4W70LBsEBtImLRBXfbIuux73hxB6dNtkZ9+4u0V07UzuYFD9r2MVpW/JaD9b1xQdmrVf+dS4WmZ/TL59r1aqWDA1rB48bcDL1vv/4ULwBcejuyInuUhdhtIyteBe2zw0rVgxUx8lC72EDwnu6RNY0bp4Xe+h1rCn321Ek/jebKXlk7sCN+92Vdq4dOtddQzI5PnD7RVbPGTVczBmr5QVLOXV9wBwzbnir0ObdOtD7kBbtvy36hdFrHaMY6eXAGUQkh2AXDB3Q60cFiRx/gXg/G4wo3fav0ejnbjKw5udKoNe6NpGdbXxgw+UWN2nQQoiIFYunbV14Y3OsPqcix6mi5f9VU2byJkAujfXE/kgRqL2c0B+IR1HI/G87HRW12ZjPr9i+RPBstSaMpoqCkI7/AqDOT32kD7ZzzNWQXgavQ+mewsh2nDjEjklgByok5ZktE7ddKXx+NEaZ5+PBrHup3zo7rAsZuPf9AH6vAuGT/Pxg35SjdGY0FsQQLjVlPectbleBpav0KudxouIMM+E8Z5q8eWyM/UPf6Kbbcqj1Xf38uKoo6NaxBDz8U4i6dD8HicO6MgOQDB09ShofZu1Iy0w0FHg/FI14xEv0pfZWjA4r1xq/bHGZcuz2VogM5jGXzeKHkGIIDjDkY9uc/bl+mQIvTlD+okM/J5lQyAMrozJka/5P0IVK+N0gol4/F6XMmTFKHLIxiTiSr3YB8K5MXJBz0tCwWnifopi+FIVgztnWyopQ3LoNrwVp1oRiy/sBkzlNhyw5GhXX/g5OiW5BiOwEraRFUwWl1pxkAe846WcpxoN7eZPc6KgJJBBFKjXzBIp8oguiEbmsK5VYdnYoxGfcEl2aLm0PFgpPPrdZ6BJvJQF/yIsU7BMU/Bmc/47fUfy0OIUw==', 'base64'), '2022-04-22T11:58:23.000-07:00');");
	duk_peval_string_noresult(ctx, "addCompressedModule('win-console', Buffer.from('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', 'base64'));");
	char *_windialog = ILibMemory_Allocate(38361, 0, NULL, NULL);
	memcpy_s(_windialog + 0, 38360, "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", 16000);
	memcpy_s(_windialog + 16000, 22360, "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", 16000);
	memcpy_s(_windialog + 32000, 6360, "p35eV3fj4zPV8enLoyH9UoxqoPHvnri/fnSTvHx4dQMp3cXV3TO20Y7nif8lzoJ8evfp0Z5egSd+F1e+923MV1Fc3iR8g8qjyb5Ly/CZVtnG16GeluGXR0Lvx5LrlP5kJ3+VFVOnZWVL//b87al9u8nvkxFJcnYKJ33sY4b563vI/jXkdVC8ARsHejf5198nyDjKu8n/8/ujXprjyP1DpUflNH7sv4H1I9jd08cJPJl9/vwa7b+/fvzWgF8dzwNln7kPWpJ0kuQBz9e69IsZ+mU0WeO903kBvjgj4P3k35D7CU+RX8Fmo+z+9vlLFfnZ3bcmv3PLz++J3aD/3InjKPmQkYevj9zofvXAzDde3PJvn//6Hvkfn7+cncLPKvVxhJwf3LUR5RvwP14/HgrfOf31/QggFVkGa+pN/z8MousYaq+d+uN2vyK8DpHZbxMYnijid2Bo5Aqzv91842C5NlL1IJvfdOLk3ydu4jvFk8y+BPr818mrMg9F/vq2HV530QcCfhP4WeBvgbxt38mf6AJDurr4ugEMnvztveC8kK3ff38c4IFz8qu4Svwf98wHrL1+8UZFvWNr8vu/Tj5NoBdyfj95MTxuaIXIc/XKqWL3UTs8QL4BfKhMON5BOUqB4XcVmSd5cfet9KN2yM+jGJZfgrzwwyKvM+8tzTeoiNP3ER0c93Qb0ZMhuYIfirqM3kJ82JMbGhhvdemNlr2CffpZrPQG6DQhsu+k9D3mZ9Cfxi4RpmEoa0rZrf//ZgQ2fuI7pU8656ou/G+6973u/2dq/sx7NOO7bwy8AOPAmpLo+7Gj1uSLrrqfcMZXEqgGr6zvJ8h/krHY8SNxVdFJDqxZfs3eUFYPLfzA9487ahw5ZfRywSHNs7jKi7+Mg/rT5y9fy8jNC/9G9UZiZfTGX/6JLrrqpvQaJfiQ6GPvyA+vx2ntLs68vH1Vu/uJrKx5Q9l8pWgGmJJhKOqGl8HG+shIXCVqHMXfW495nN9tnSJ2Dol/h30PW/8Pw1ZGX1i/os4xkxeP9b4bm+k6gxuZvr8Se5hefli5V0rga+G0Xyi/8IO7c1WU8eCP9gub/L8TfPLbZLq4n2Cfv1Q5UQeBX9x9/lL4jsdn1QyV6A/t7HtV8zGVKTr5bYIiPyLzHUl+aN2x9m8RmD9i9KcYXIwMYm8ZbIu48p/w39KQfw9NFBlp4j9BE13N39D8uEsepunflt/UPB5XRD5snMKvvsSZW/ipn1XjKkFV1P53gF9Oz99+/uOXVNmaJIFE6rz91lw/OVwP7sqoXpCfU2OHOgg+GpjI/ThPftHeN+ox4ngYb3cjqlfDFP88zmHfvkU+f57AkzmOTP7lYenmhsf92kX4t9GF+zPoocmnSTe5XWqK3iyGPRT726eH9aYbNb2OqSDPqsnvr7y2h7HD5Fm1exqCyAOSh2Wk6//M7iulrA0SbOgXbx818FeSAxudNu4nimk8qeWv6oYmef1+Qkq8+u7l07NmAok3rOcXKm+Q3OQ/JgzzVd/xun7/PLy/adM3rmlW3U/+fdLGnv/bdURP/rgpqg+OZV1VefZTrTCd/9/QCr/qpRF+GGeUH/jFgw1W8/Kbp7R476tx1E79JX/tkdxrSld09y/Bvk28XrT7Cx390E+Pnur9RN+pX9eKrWwoejP5j+ujzim7B0fqu9PNP83UdX56i53JXyZ3d0++8+RfJsiX5fzGyyk6/3w/effu7avlzTf/SfV8EJoXlcQW32TjUWPMkdcvpsibF7Pn5/8cpkewzElf9s0U+QHXs9n8v5hr17kKNNdm3gvG0becY2/5fNf+K/Q/mXOncSqn+E5rv+X5JYv/aJ5/ahbIZ42TxJ5TXWNx35sHIh9N9n6FLJ15H+jVsU1/aho8+Vi1/gpHP5oOv1C+O/mrThuMsjZedv6zVb2fTD9sqH8Ga0+q6b8bX8/a5zZn/xU8vdItP2brY8auMcz01dTjm1eyQr9XpSCt3k1/vs3p/o6iJDOuqUvKZpxg/SqS52Z4v+x5P0GR/7K+oq99NbqXjLKRgTEqTOYrkKT7sUIfjqHvrURdf/9TV688P3DqpHozz4Php7lRkoevomXfWTj942Ycbmybu+g5BPdykWjy+yT669vX3zz+99Gou8co1Aj2Kib4EJf6iZJXuGex+Tkne4xAJU5ZSnkWqtWLoFh0P2FJSf3KkeZGH0f1C2b+9prBx623oV/prpP4D1tC7h625D5Z1pfruC+XfL/5kT8F9Z2F/HfVftAKDyaO7sZGeq8qPj3EOD69m7fcBJ5MrhPih2hT4WTlw7aP8ovxYJne4djpXw1A6IaiTv5jfNjyOk9I9MMDyfESNXoW+leJZoyHXw/hcF4GLH3/PBofGuflQtD9i+E86SbnvIyvA/Ony/Qfl3m95HT/ohBxNWZjLavoudQTKDx7pvC+UOTHYVQ9l4ruX0GpV5GftNfueoa6xgyn909QZBQn3oSnXgC8aCbkneMSvfBc3ngrt5yLUWa/bJ3kVoDp79Ws0Z/3EH5CE/4TR/v+FtzPjuiHfWsPvzc0kMb1NlJZGxtFeni5Vgyesd6N8TcBoXGu+ioC9GoW+/7Lw1T2u3Jxu9T7kfuz/30kSzf5/nUyH4vfP4/Q3yGyyC+LrPvTIntd9xg3CP0zxNW9n+jGVV4flPHk+udxXL+adY5W7nG19/M7R+hXNoTcNMfuTXP8PEf85yqOh/jjzymO9+ZREX9VkxD6uGCpmjr3wME7fXFdBrppq75jFK+LLjcLfccqXpeT/oRVfF69uW2A/24ZY2b/ZLP4YJhe+LH/UAH7BXv4DxWo2/7tf5ZA/SlLvFbW9N9ljCVAihuaNH5om9/J1/RXnE7spkz+SL7Gpbc/LV8/LPV3yNc/2+18WK68IV/fdlO8Wgk4XA8AfLDt4aOtMP8AKf05M/iayw/t4R//TWTqivl5hezvmrn9Y4Tml4zSNVrw38ooof9koXnqs/90s/QLE7RfGcQbnuRoijfmyO5X3S3yYeHuRmn6qvApZS1ZDyP5z6xO0PpX2ZQMXuLXjzBbndwo0nujgd4WgH+C0Zh9KDT/VUbjn+2UvViV/W8hAv9Iqg+LzNddrI8r6chNE/Nt3e+HkaoPduz8ucjBL0QM/q5IwY8jBF8bp/jTcYK3JT9eGn4B88NYwQNw9KtBgjh4R/NxNb78kvhZWEX/Ov35TR0wPAGTzG8nTwdtWqecOJ7ne5ODP7bQpPUnQZzFZeR7k9KvqjgLJ/X5O1HVX26w6kHRjxvbbzbZjSDLB8r9Vtsc8zi7+/R/iv+Tffr8TtHf3hT8xhF7a7quVCa/T/59Mnbmb6POG0n+9iyAkz9eheR+YPxehkvca62k3HWSu8corvtkpJ6dsMeh/PqQ3OPLcRPj00mQb68m//7Ht2MeI+z/ehKGl+bw/RmoW1CT33+oOBTxt8knRfx0//7To8X97alWb5r69fm8Dzl9CCO8qOGNr2P7jn9v13tU0C/LP24y+wSK2Ek+3S7zIoryouTz2+cDnXPsfjJF5p8/ov3tfMYrDp7ePuJBx2WUp3+eUT1vJR3F9/F4zt3TMZ3HQB6fxd82go4bSZ+kYfL75N9uNtljv/ztRZn8XD319Ys+fjDlLwKFb/q/jbOy6hO//O3lcfkvDyKuX798eeVBfQ9KVVRT/QEMcd138maodb9NZmPL9Y9/Ez+ofhttZDG6K48vrx7Pb5PrQvqDH/Pb5GFD7zhufps8yt9zB/92o9NfSPkjD0+DGIb/oW1BPO2v+R7Q43GHH0Dpli7Ta/P+SUc99vaXh7593NH97aDznzx/cPPMwZvzteciTp2i/6XjBcjPnSn4+88R/PrZgWcct04MPFb+xqGBp1I3++Ond9i/2c9MqfwkDybqY5OPqQ8Sp5/E5W/XEO17Wm8OScPwTXbQ6eKvN0fPVaomL48tfUzizZcHIfxW9iqLtwu/VIXubQ91uvj8cgA/ZAiIs/P13OPPdyiKvWR2PKZu5Cc/+xkcb3f4jwgeLf+oul9I6N1jLd9Cfnkafm/b4C3cC/3+Ut1/a6lRKL8Bf/O8+rLyU3Xch+9XflHyWZCDO13lv7K0sVM2ItjQ4DpMx0YecxSMEd+X2/3fiHVxdYq6367wHx0nQT5f1fL3QLDP95P2+yD45/tJ9H2Qce/9Hy+l6ks7Ns+XdvKXSfGle/Xlqt6+RNcv/ceSOJ7deTyGf2vU3494x3/a70hz/yGOh+E/lu/Hf6LvCPUbaX4QZUFX1l8eUk7EQX9XfP4OgslkPK3a3dQBY0aAT9dOuvGxf6Ee3gxCp65y4Lr+6DdMAicp/bfD9GUmnurtx+sx0scB/DBOX2721/Mk9ogR5O7j46nfir52WG96iW+LvFgue/r5FuTZnX789Rbg0Yu8XYO3hzZeCvl/23MLP3Vw47kLXx7Y+HErTOf/t7TCu1nYl8MCu27ueq8pX5qij1cvpi+F95rT5nWum7tX5uj+FdbHdDJvlLMzqr8Hal+CIk/fsXo/+XRwSn+BfXpfOns8uvXzhnM82fWwLvFKGTrtFzc/93dXhC+q/9bzistrkqTRGeDkL++yWj2Uv5+8pvLGy4zHWv2KpX7CED1Gkv4OFGXlVPWoMr714e2UWHePFb5/ZPslno9wvMt5dfdQ9immdP9UgfsbE5fPfx0Xgd5OWJ+JXv34K+Gr1f/99SG/N7O+N5G3358I3zgEH1xTTN102d6t8b21es8pqvQrZw8W6lur3Ehl9a5FHshfPZmfp/ZA56Hoh8dkbyV4yA4fHfn8Lulvec/eVPBmbrS7F0v1b7Tpx1+Q+x9V5wqTHb611PvKjRHxr9HP9eQ3+PaXep695pv7uvugw2/lPHvX8w/kf6bnH6lxH1B7n/rsNq3oZ2jpeV24/oRS+QdqD1y+7RUmyZ1q7JXradP9M2T0IeSP6F7r+KaGN5L73WWHt034Icn7H/L08WAKHzPd/cwR6bfd9XHCvA968A3Uqzo+MfJTA+VGqro3JN9+vnvC/0zx1XeQVTFIYuen6L/LqUfEbn2I3fc8vIO8wcdH2H6Gk2+ZEt+Qfp1B8QbRt5Lz8rTon1Fp3xla5XWr/bMt/9Pj62m3/qO9vamU39vil4PqFQv3z9nubpjlm639zr6+Qvgjc3LtgMecl2/750UmzDda7B0jf3w08cuzbwnbPt2/ybz2bo4wAo9xk2fIMaRzE2zM+/YMNiaMu+1rv82B9c7lfp4Xfst8VfrVy7R2z1nunn2l6unFU/E3K2Pj66edtc8BnIcUWO9YeA7Ovk6S9QKX4z1FDl8ifH77mMTuFuJv0a7zOEEe4d54cu/OSY55g24Hyz/28l4jut3qHxS9jsp3ecle4vkwEPvzHfc+AF69+/SdbVaTX9s0+WH08ufjlr8YrHzPjpqX1eNoAe/7/LpbwdTpzeuUo69le3Iz2+e7EOWfjU4+L688hydfLLl8eh1z+6VY5rcp98vo3OO7ye9PZ9yuj7eIfalj7wbBh9fPE8CR6b+UflmOHz99/vKoa83Yu/t8E+2LAOGLLKZVf/bz21C//z759LCM9+nzh5HGF6llb87tbjDyIsL4HUZexiE/YORVqPIGIy8T0D2bi6sp9pPge40Z+mOM3PXLUmkzv1g76TW0Ob74co69z1+qMvZeBppGfLcXpOPgbceOwB8rNxierPNJ5vvepMonXlyex3y49+M+CNfJJl5+FbdJMobmk/512Sd5+XPR+xvyN3mVlfYDLt+xeKirkU0vzz5Vk8hp/r9mzmYnQhgIwHeeYm7GC2vUeNB40otnvZtKZ5cqS0lbjBff3Qzlp2BXtwsLe6IJpZ2Zls7wTSkC5rLcpFCg2gpr3OoJ0oGZfovB+WRH6VjhOyaGAlFdrtciEbTbq+vVFdOW6auA6pA1oB74X+fw7TjNqL9Ged5czyxYreDl+ekRLoBL1K19WEJTqhKJuBhJmiJw1B9GOntcDrKNa5cHlufS1EsmcMEyubG9Ce1V36N6+wJ5xp7Krimbe5Ths71FgXpEQxWse9ON8ClmBapOAEF3NLkyDmVuRAYsB1YUSn4iB1XmPMuuLikiNYolBvCrkIouQhsdn3UddmpH3667Gfwr+3ZzXWfum6S9m6Hvn4k8QdKvOTj/oKSfbSKQ9/pY7z6c1894K3O5WBcmBLr/wtyRIHccxB0JcKeAtxOA2wGgPXedn5fODnKy++LW+VDrhJh1X8Q6Cq8OFpsx5DSEmoYQ0/lo6VykdAlKeqKENISOLkNGl6Sip0FEj0tDeyvQjhkSBDnnA5x/gc3jUMqeJPGrqQO3NoTyBNu9R3z7W6paFRewNGQreZlhbGNZDffW8XaKVQa7ra+2tbvoB2ia4Rs=", 6360);
	ILibDuktape_AddCompressedModuleEx(ctx, "win-dialog", _windialog, "2022-04-20T10:46:39.000-07:00");
	free(_windialog);

	// win-utils, provides helper functions for Windows. Refer to modules/win-utils.js
	duk_peval_string_noresult(ctx, "addCompressedModule('win-utils', Buffer.from('eJzVVt9v4kYQfrfk/2GUF+BKTEpeqkSoJQmnoFzhikmj6DhVG3uwt1nv+mbHgBXlf6/WNglp4NqnSl3JMrue+Wbmmx9L74PvXZq8JJmkDP2Tfh/GmlHBpaHckGBptO/9IgpODcEFlULDzKDv+d4nGaG2GEOhYyTgFGGYiyhFaL504XckK42GfnACbSdw1Hw66pz7XmkKyEQJ2jAUFoFTaWEpFQJuIswZpIbIZLmSQkcIa8lpZaXBCHzvvkEwDyykBgGRyUswy10xEOy8BQBImfOzXm+9Xgei8jQwlPRULWd7n8aXo0k4Ou4HJ07jViu0Fgi/FZIwhocSRJ4rGYkHhaDEGgyBSAgxBjbO2TVJljrpgjVLXgtC34ulZZIPBb/haeuatLArYDQIDUfDEMbhEVwMw3HY9b278fx6ejuHu+FsNpzMx6MQpjO4nE6uxvPxdBLC9CMMJ/dwM55cdQElp0iAm5yc94ZAOgYxDnwvRHxjfmlqd2yOkVzKCJTQSSEShMSskLTUCeRImbQuixaEjn1PyUxyVRf2fUSB733oOfJ6PffAWurjgqWykJNZyRgtpKhyJFgWOqpBnBd3UsdmbeGzErw0lNkaYSUICBMYbLPQbjlEwsSxVrZcFfneFspZq4y1O773VKfc1VTwx/ThT4x4fAUDaL241DrfEWFhHy8EwaA+c+vp9adbzp+3e5hXBftqXSlA7aqjF0tbVUnFbmkZM3AWHgSBKNikMsYXRaEkl9+35XSuZYxnr9a2R222Mu7CSqgCO2+1/haAW47Q2GSuWXY4LSzSscU6y61OkCBfVUIVeOd8P47T+geUW4ukRYbfxXnEsoJJgqIRnxuneINl+6nx9qx5dyurZ7Xt532IctmuuBgMdKFU573AHlaadP5WIJVVyi4LItQMIQvG/fJVaa4axytN56/bXN+M7gMXgO1Wsf0ArcUinH6c3w1no8XiVxmRcQNisWiqfrFo7DXjcrEYbXJlCGmxCLmIHmcYsT1tdaEVIrsJY1v7QneLkAvS0KbVl5++wmAAp/skn98fobJ7Ij1MVohcV7ejqAtSs6n22978f7FWs1V3EQwGA2AqEH6GUziD/kGqk+COJON/GkIXaFWPvQOJGWsw5MbydrpHqdAJWndHsXhEwOUSI+7CGiErLAOhZUF1NrGxDzZFpYLDScxlbHebPycTobXHmdAiQarb/3N9ONq0W1vgADd4MA1y2Xa4gUKdcOqq98c9DQyH67KhYHubVBPZDcpMsIyEUuVLsC+ByiW4/yGPTlTyYdgmwMAJVl5+Ofl6KI497QU7vVldOG/md+dfNOnO9vnc955dCfheZuJCYYCb3BC7jGhc79yD538BLT/byg==', 'base64'), '2022-08-03T14:24:19.000-07:00');");


	// win-deskutils, desktop utilities and idle time support. Refer to modules/win-deskutils.js
	duk_peval_string_noresult(ctx, "addCompressedModule('win-deskutils', Buffer.from('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', 'base64'));");

	// Windows Cert Store, refer to modules/win-certstore.js
	duk_peval_string_noresult(ctx, "addCompressedModule('win-certstore', Buffer.from('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', 'base64'));");

	// win-bcd is used to configure booting in Safe-Mode. refer to modules/win-bcd.js
	duk_peval_string_noresult(ctx, "addCompressedModule('win-bcd', Buffer.from('eJzFVdtu3DYQfRegfzjYh6ycKFrHMQJ0Cz+sL20WsXcDy64RFEXBpUYSay2pkJRltfC/F5S0F9+KxEVRvYiX4cyZM4fD0WvfO1Jlo0WWW+ztvvsBU2mpwJHSpdLMCiV9z/dOBSdpKEElE9KwOWFSMp4T+p0Qv5A2QknsRbsInMGg3xrs/Oh7jaqwZA2ksqgMwebCIBUFgW45lRZCgqtlWQgmOaEWNm+j9D4i3/vSe1ALy4QEA1dlA5Vum4FZhxYAcmvL8WhU13XEWqSR0tmo6OzM6HR6dDKLT97uRbvuxKUsyBho+loJTQkWDVhZFoKzRUEoWA2lwTJNlMAqB7bWwgqZhTAqtTXT5HuJMFaLRWXv8bSCJgy2DZQEkxhMYkzjAQ4n8TQOfe9qevFxfnmBq8n5+WR2MT2JMT/H0Xx2PL2Yzmcx5j9hMvuCT9PZcQgSNicNui21Q680hGOQksj3YqJ74VPVwTElcZEKjoLJrGIZIVM3pKWQGUrSS2FcFQ2YTHyvEEthWxGYxxlFvvd65MgbjXwvrSR3dtD0B3F7JeQhT+YldRIK1Gq043t/dQWyuVY1JNU40VrpYHglZKJqgyHeYG2PNxj21LlStJVxGHQlk6J4v/dWyaJxMyuWBK6k1YzbCJemS18yK24IZ2TyU5ESb3hBH5WxVyhWU5TM5i0/KwTGMkvgOZMZmWjo9HvnEl0nmZH9RI0JNtlospV+Lvvh4dExvlakm40vR9pohPP2nGmx3rCiIjBjFBfMaWR9C/qiUYJrah4Q3mEJrql5hCZwtyxag/31mprfHidj1g7CDsL3ZLWsOn08QVJCBVl6DtvLfJJ0KohZSmcqoZj0jeAUmO4/Y8tvxu5cHCpl0Z+FpszdzucCC/NfBH2giQ11ndr/hzw1Gcu0DRIq2DcXzeSVTVQtUVlRCNuAbolX9yOIFEHfXoPh7z+TJC34GdMmZ8VwJ/qshLSkY/En4eAA+3j1CmtzZYY7EdM8D3bc5vD2w/5wg83dhu6P93tYCAuWkbSuKbRdTUl82G/X6+5+h6gJiWrfIrotlSE42a04MCEWxJl7pRY8oURYJIpMa14rfY1UqyXYKlipFW+778Mw99EtVVIVFLl42hocdKt9Cu57Utrjp5fDzbGnpTJ+Zj1cFXi8GoSPpT1+vNTFu+uKSYWhNftP5/UgN/f1bWi8GoR94xn3/3DTMMabYfhSXl7CTdYDynpA/4arFV/dbL5wFydKKBWSPmv3vNkmuM9diMFCKes8DcJ/onG8lircC7S9+8D4O/qDKluHm4607eNuK6f+Rv8Nv91MhA==', 'base64'));");

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
	duk_peval_string_noresult(ctx, "addCompressedModule('monitor-border', Buffer.from('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', 'base64'), '2026-02-14T15:39:57.000+01:00');");

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
	duk_peval_string_noresult(ctx, "addCompressedModule('process-manager', Buffer.from('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', 'base64'), '2022-08-03T11:11:18.000-07:00');");

	// Helper functions for KVM
	duk_peval_string_noresult(ctx, "addCompressedModule('kvm-helper', Buffer.from('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', 'base64'), '2022-12-13T10:41:20.000-08:00');");

#if defined(_POSIX) && !defined(__APPLE__) && !defined(_FREEBSD)
	duk_peval_string_noresult(ctx, "addCompressedModule('linux-dbus', Buffer.from('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', 'base64'));");
	duk_peval_string_noresult(ctx, "addCompressedModule('linux-gnome-helpers', Buffer.from('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', 'base64'));");
	duk_peval_string_noresult(ctx, "addCompressedModule('linux-cpuflags', Buffer.from('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', 'base64'));");
	duk_peval_string_noresult(ctx, "addCompressedModule('linux-acpi', Buffer.from('eJx9VVFvm0gQfkfiP8z5Bago5Ny3WHlwHJ8OXWWfQnJV1VbVGga8F7zL7S6xLSv//WYBO7h1ui8G9ttvvvlmZh2/c52ZrPeKl2sD46vxFSTCYAUzqWqpmOFSuI7rfOQZCo05NCJHBWaNMK1ZRj/9Tgj/oNKEhnF0Bb4FjPqtUTBxnb1sYMP2IKSBRiMxcA0FrxBwl2FtgAvI5KauOBMZwpabdRul54hc53PPIFeGEZgRvKa3YggDZqxaoLU2pr6O4+12G7FWaSRVGVcdTscfk9l8kc7fk1p74lFUqDUo/K/hitJc7YHVJCZjK5JYsS1IBaxUSHtGWrFbxQ0XZQhaFmbLFLpOzrVRfNWYM5+O0ijfIYCcYgJG0xSSdAS30zRJQ9f5lDz8uXx8gE/T+/vp4iGZp7C8h9lycZc8JMsFvf0B08Vn+CtZ3IWA5BJFwV2trHqSyK2DmJNdKeJZ+EJ2cnSNGS94RkmJsmElQimfUQnKBWpUG65tFTWJy12n4htu2ibQP2dEQd7F1jzXKRqRWRRUXDS77yyruR+4zqErha119H25+hczk9zBDXgt7L2FeZMO0zvve/iMwmgviOb2YU7xDaooY1XlW54QjGow6A7ZFWUKmcEW7XstZdBzdhGjHAsu8G8lKT2z71lGuqmpwakSoxAO8MyqBq9fVRRWAe6oXjrdi8z34memYtWI2EbIIy2zJzReAC/HYLxomaMTb6/x8Cq18yGjAglDLpyCCcvU5zGTQmDrpX+Ampn1NbwRO4QNGpYzw67PDIWXEE718AdODZSc1FAYz1J4wzPZuhFPwTn6h8N2kSpYVSRGTy5vNqumKKhnbkA0VfUGyMgnaibCtFEjI1MaEVH6QaSplamkX8WpoMPFC7pl2rNRhaKk6+LmBn4PqJZtYo3Qa16YPpcJvPySoUZ88gP4jVrTsxSvym/bh6hQcnMCy9oPLlNiRZN2gCHwIs4Oo2+z5/Yq6eDBz7ALptvVmU7iuoNf+LejV3DRKrtaUxSaCDf8OCe28QXbUN93jF+uvtF47Wv6MEy73xzTprfGHbUqdWr+SP8TH8a3cz8Ij9Nz4dCHtw69Ds5w/WDVGebsZThKNi1rBn3qEUTzYq+ljcybCmmO7URawwRuz66oyf8tuBKP', 'base64'));"); 
#endif
	char *_servicemanager = ILibMemory_Allocate(33885, 0, NULL, NULL);
	memcpy_s(_servicemanager + 0, 33884, "eJzsvft72jjTMPz7Xtf+D1q+3gtsCRCS7t0mZXsRcihpStKQQ5vQO6+xFXBjbL+2CUm7ef/27xodjHyWgfSwWz/PvQ22NBqNRqPRaDRT++PXX9qWfe/ow5GHGvXV56hjethAbcuxLUfxdMv89ZdffznQVWy6WEMTU8MO8kYYtWxFHWHEvlTQGXZc3TJRo1pHJShQYJ8K5c1ff7m3Jmis3CPT8tDExcgb6S661g2M8J2KbQ/pJlKtsW3oiqliNNW9EWmFwaj++ssHBsEaeIpuIgWpln2PrGuxGFI8wBYhhEaeZ2/UatPptKoQTKuWM6wZtJxbO+i0d7q9nZVGtQ41Tk0Duy5y8P+d6A7W0OAeKbZt6KoyMDAylCmyHKQMHYw15FmA7NTRPd0cVpBrXXtTxcG//qLprufog4kXoBNHTXeRWMAykWKiQquHOr0C2mr1Or3Kr7+cd05eH56eoPPW8XGre9LZ6aHDY9Q+7G53TjqH3R463EWt7gf0ptPdriCseyPsIHxnO4C95SAdKIi16q+/9DAONH9tUXRcG6v6ta4iQzGHE2WI0dC6xY6pm0NkY2esuzCKLlJM7ddfDH2se4QJ3GiPqr/+8kft119uFQfZjjXWXYyanIKlIntVhMGHIu696+GxdoVdVbGhpDkxDPbtvNPdPjzvXfV2js867Z2rt61ua2/n+KrT7Z20Dg6utju91tbBzjZqouK5bmrW1EUudm51Fa+MFVMZYgfppusphsHIDMOmVdGpS4ngTEzNMNYa6C12Rwf6NVbvVQO/tlzvHI0VU7/GrodsxRtVixkonXbzIDUxl4jWr79cT0wVBgNNaXs92txb2poPYJs1tOM4llOybEzncfnXX77QueFOdU8docAneM8+w6MqLkZFhn1xY/YBHgd7E8dEJdlxAx4IAvYJkxd0lP4icA1fKxPDS4CZOEwGpxzyKbLwgHG0Hn795SEwdteKbkwc3CK/TiwQt0PslBQ1OEbAhA72NsURmxUKjVa035TM3cPuTgyFm/XN4LuBg5WbyCBx2h/v9E5axydxgFalAB3vbB0extZvpNR/oP/Q0Ss52AOSBmmJ7zxHUb1d3cBdZYxLsKAcKd5oRkb9GpW8extb12j2FTWbqAii2BwWo8QEynvWDTZd1ES8TtW1Dd0rFfv9Yrn6ydLNUrFWLPO3taLIhQDAVMZ4k69F8ExHsNiVSvABNVkDVduyS2WKTwAEZ1koXQ7SAxsujuDMiORja+IpEKQs8mAc1XrWxFHj6MYRSKUdeuXTB20IpCJAo6NlO9hWHLxrGRp23NI1+TfYLJBOM8aeg5qwqKjYdau2oXjXljMmLU91c60BDcNIoA1UrBV9MgcHzofOBomA5bQkixag7a9D9D0bJTY6BjaH3uivepRHWN0S/ZcCQa/4qLoj/dorldEGK/CU9elpqEBZHHLgVCI6dFPDd4fXJdn+l9FLVC+jL0i1TE83J3iTswo8nnOPvsyW5Wu3WK6ObzTd6d2bKmmwvIkekKqQFQEDHMAEV1VLw+g3aHNn532nd1KET97IsaYIWuBtROSbrTguZitTz1O8iUvJGRzkT6iJvjwIo8Fk8sm97U+P6jZ28HWpXkHr5WrH9M4Ug1X4VNVdwr5Eqdh29FsMHFMqiVB+R/W7On0ahG2FnwKcN9gxsZENYzUIY1WE0RspDtaO6IClAGnUA0AadRHI4dTMhrAahLAagABrCcxs/RYng1itB0DATx/EVNG917rphUag9Cf6A62XyTh41tbk+ho7pXLVwYp22jG9tcbBTmkGxFGmMO7hYSytygPhCsoMWIKG4g/Hs9Di8qnqMhyK7cPuSad7unN1tNPd7nT3ijJrlg/4z2TAR63T3pxQ/5sBdTsfuPVkcMen3W5u9BrJ8IgqMF+n19KgHh7NB3Q1HehROikfZgIIpKdjGW5Lhf0o1sLs28gzB2KAXX7cnKkkpUiBtCke4f1oA1V74o5KvsoGPH98eHDV3TnZ6nS3W9vbAfUib/3jnbeHZzsLgdjpgra+EAim8RdDClEWPevPg5L7OSxk0m0ftY5bb9uvW909aFi6zciKk6/N0x5pTboGl3HyKMYsA7lQPN7pvT492T487+Yhy3qQLOu52pynwciqnavBk8OjHI1FV/c8jb1uHW+ft453jo4PdzsHO7lZbj3Y+nrO8Tw83zneOdvpnuRo8nmwyef5muzt9Hqdw26ko5+qth6Rvv+Vl7586/LJ34EQ1TpOmzZ0c3JXnGmmvhJ7NbFdT3G8qz3sMV32BGwBpfjtojrSDU20fpEXV6zNYrmK77AKCmupWBvoZs0dFSvosuiOih8DthGoVXU9DTtO1SWboGJxM/jaMktFTfGUYmWGbUmlurnuklpPm0itelaPbNJKQNjYRqyJF9cIvF5eI7pZBUspLhV0U/dUz0CG7nrob+Q5qNg3i6j4f4rob6RMb9DKLvxdLKTDKX4pZhSA7Zmjm941KnwpbCKJ4teWU9Kbq5v6y+7u5tOnelmmkgwe8KFJt59P9Aps5iuFSqEshRR8aLDKUPNy9WOFqDaVApIH4ULVpjsZuJ7jg6lX6M6WvyivsN8E/qXa+FheWZVvgqDoV604DMuaPJYObHlovcvGx2az4ExMsEgXXhWY/lrYKDB1rrApi5auNQtyDEBkXUltNhtSQw+jL1nOpw8hdeNjxda1XAPIe2Lr2mXjo2ytB8lyfKL8x+336X820Jd+v0CGgvzi7yvwl61r8JK/eyhUSnqzufqqUNgAvq4Qbqs4bgVQlsJVClGO5UP2aBYein0T3+le34wRJLC/3bnTvZL4iVlaRYMEooaT2Q9B3iO6xKAm2u8ddqvE3FEKC1URvmCMIVaWEt/MhgAL5fgSxoyewtfZCsUPVH6uUMtaoShFYY1aWQG7Z5PZT9DKCpkPTSaV0N9o6GAbVfn3f/FqlkOSxcka/lehgoKSBPG1iv6xLif5vqE0+XbyBM0tUIhyLP5foqKsKc5UN+M05SH2Dnvs7P8ryZ6AWEj4Hi8fRhPzJiIj4GU+OTG9usWOy8XAkWNpE9Xj/g90+he/UD5DTxpoHiaq1eK6u1qvvigmMRtylOlGhEpVz9HHJf+kqlosVxDv7IZAmzI5JWCHPkAeR5myg65qsUzOCERudrBXBX8NxcEnFhy3cED+y9KtYsTzpY+3MgUzNT9igvKBkzn0Ct0qhoA52iAvHGW6SfamvznKdHYqUSp2zFvF0DU4glDG2MOOsKsUG3axcQ0bzEg3hbYCVPYxZudFFeTOTo7EQuz8CBpgp0foL1RHv/8OnRXelIPVQsSBBxogsqBjehQePzTaJGj43wCw/ykKB+jkopfIEQeYaPcPSYX/ChaOKRv6SaoJXW42he6KoOpRUOG6LxOqUpTJ6WcYNwAjLfU2qaRDogy7xp46OoKNKTuUpKtOBTyVHF2LSjVAmpasYlNzz3VvRA6BAWH63j+BrNK9F4iWeoW/Y31dQSHairMZMNhgeKiG5eLwbH2ooKuJrm0wLAPTk86OwKEfvtNdzyWnfgzFp3B6iJ6SNuBH1QYSFMvJs7ZWQ1v42nIwmmI263STeEZ41hQbFWRgr+gibE7G4EeBEbi+wGcCmZwQuxVwLUIuxoCkZWI0UlykoDEsZaBcGcoAG9GpR+qKiwjpFBiA+Fkm7VV4DoDfU4kDAGwJoOz5RyhIyl7Cfz8KA+3TKenMVcR7SYsff7IWwdhyS1sMI9Bni6KqeKiAnqIQbwkURE9RQVSV+9XibLFkamW9gpQK6hde3uD7vw6AE17W4M8+qJm0jAK7aDQgpWp0ZomfB0RpVMln8StdjVWyh05YkIO9i90rityRsNISd4CZ70UGmyG2ljK3kHSGY/4WvEBQsggffPHyZ5n5ZbAvMT2B53DwCateVcPXuomPHHCC8u5BalZQUTF0xS1W0BdYeidMIsVzRRYo2gsBVAqvJDYQPg3kT/YKNSMzGyBBc0DQPhfpTAk4UCamOtpW8Ngyi2XuDLIKvheBT+CFQV+0htiEYXqKigBzJlnLqHt4gnYPT7vbIZVE+HPm2BPDK4vQNSTfo7SVGH9pZh5iL7BQxZdKAcCfRxCe4iMrSBPrLF2oxrYUFbDAxnQ5/VHkabRjqbJVfLgGlyBr06rHrMcPCdvoNP7X6CQXZpc/AL73nygO3JovK9BfCKSF50wwiGEFVNcACmkmgTScmO8s1rYVDwdRE5UjMFoRzcjHuFxVPT0sviP2ybs7GXtCVbHtc8u50c3htu5g1bOce3EjGPO5lL4fXOJsl5ndjzebU2YvgTTf9A1Tc1kzeehOBqVav197Uqv0C/1CBSY1n+HXCCx0NfY2dapnTO2YIUmY1ZGtd5IUCHDxZoQ7DyyV+nIHuZK//smNi3DjkWMNHWXccoaTMTY99yuvKxnMlmPdEBknTeheOROz5R1YihbWhmIUmWwtKEH7qdXQOUYmu2fEdsnkspQOd3JQa+JZKz1wTYC9MjuAqMC+1nLI/RwLXevDiYORNfHQyJqS60pj28AwSmBbUxyvGN/2I2lceTStx9ewHkWzOuaskTYLaknsP48+JalHZcyDqmed2jZ22oqL6c61cHJ8uhPbaniDVZacN4TjwAU577TJMWv0a2qzpspawp4jZb8RMHzPJjps9VqnJ4dX9P4LbPS2d962utvsRRLVY1RPFNng5URNRCRHu3OOWuHqBmO7Zei3uJBf2iHpgfspciRETpzEecOHJ3XdDQicBhc4tHSGaAmgS7xjLlc/Npv9gqarXr9Q/hJoTqPLPHyj0PXrErt2QwSd50xuFYMUgu0QEYV/EWdMWop+J0VvzFW/lwL+N+YqaenGbNC2/O9Uct6YjcvVj+SYKlfP2IECbUSlGBAy13g/bhTWc8C8XyijL7TFfqF1cN760OsXNh+g2a8ltPMKZ+CxIfaOOtuiIkzflCa6VkGKS7k4XSG2bHoRuEmuAoPM0DajpVRrPFbM8BdyDY8I14muod/o2RkM/4S6evJPxDYWrRo8ZJ4dPJbgRHS1zq5AZcophhtqooJBtuyCPyI5yi36SjExe8GkFFZ+/br0ZA0YIVoKJgQ7713dfBBYIWasZnQk3d8gNHgIFQwNaHTpSDiyIPRk5JWWwjO6FGd0od2hPjGcPoViuOfFAqNPnxJoJqu8sV1B4B/SbK7RW2WEenEg4LNPPZhKD32fgnFiO2adi19b8/d3ONGJzRToCGbc77rjkbmy4HJa4bz5vW9g2QBKbAqjsoQLO//a5t9/+wIQJBNI+WxRwmW0fwyfJKzDOM4zsXMuCOLxQmgd0F3Qa8l9JH9c+DuQHckrQC4JHoc8KSGuOoTQACl49TmK8jFzuwvgzF5+XaTLxHcjFdm3OIjnW/y1UWwKV6d1LQ1bA/Y4ArbwOx1bwXvGly/gfrDiYho3pFiu9rBxHdFtoCK9YBtcy2OK5dIziAwHm8xyFY7k3WTsugtE+61JpMnvvyPyI6yOJNSFhx9CiscIaDxxPYg3gRQXOZblxW760g8951IafBLBMCc4CZVusZOghLH+A8UJn/z+O/33t2ZEQZOgyKFJbV+3zLfOukZvFfWwV6HkGWBCGjBxEVYmZblTrm56lhjxBoLyuNhBrq2oWIaanISERMk9lu+VlOKXgsg8+s3AsjzXcxRb1Gy+e83iaygTuT3Yl6a9CEonDAgfLVA3i2GjfLFv9pk+mMMEHhb0EzMs6umbbGHPxzzG15GIdBmBPveCIbcSTFy8ZVke2Lub9JR1mWvBTLTL+YzdxoqJJpWMlBK5RCE9ECDijkVF8CwqyMD1DN8R6cfGl0g7Kv6+sQSCNSKOEFHX1wxADJhPONDW+Y8g8+YAiChdIQ7dgHJOetkAh4Hams/tgD/J9l85fHXTnVxf66oOJzmKCkI3vQ5fRrsYay7CBr5V4AKv7ei3uoGH2C2m0C+hI8u0bXPf32UM5ieYIXQeVNAAqxOIEjHFSHHACxX8RO+5ryoNdsimT46Rj5Mt4vMvHPqlKKClOcTiUgWMrCyQlQPLnCNB1pbELY1Ts0cxGdfkNaojy6BzMWaWdvrNbV4BZTIFzuOpskuFTDaFPkPJKT7zWZ7TlGM2H7kNOk43TlCNY3gG5d5EyaAWNhcvhuM84jMVTaYX5sDqIY7FpPYY5Jxf3GKQF9k7DDklf649xNy2NXL5Q7ABcauGnJEkqfZf4U0A+pKkkc8D8rdmxPwiuri3FROCL9NhEvzVqaFEMS0SS5jsLDRrDCGW6WU2qMQMUHFYhZCaGXvSm2ZWrtgmgo2QBvzNauy1vEcX/+nCNd+Wn1Ihehi0lI2+61l2cA5a9s8p+N1NQcsOzcCvNP/8duWnH+k2G0LfJ4hc0207ijvCWhG25HHfAxcJYzgPBa0bURtGBTkKIYo3Uigr23AMpHtkg6eAyk6INoXQ47pXNOAw/wYb98jBZJZF2yN4CravJRzOPZYAQt/COoq+hYUUZYtMy46VmCmqVYavTcoZKWMeUYyyV490krdEDxdpqZklxROvs8a5TqSomYKfTXaR5KUx2SVi4en3BWnYgwQR2gbZ01eEReDnnJTyu0C55hvKJVl9fhO5+hUqFemusBbkFhJzu8h3ZSVhIqJXZEg3sji/7F+bFKAun+9+claitL/R1RsqCVZuwgdkjyTy/YAhrij1Z2+/9VWhJce+Wmzc521I9vpRMI5WMeHqT0oUrYRCCCGl6bvptSpp95gK5U1JkBRgC3yTtyqFl4rjKPmrb0H1dqXwspa3vjkZsz61wXeZ5heozG5cyUOahQ0zJ2MSN0yyoizx4aIAuWr4v+pTfuWrVikUGNKX+kdpXAPRxP7jsjCEZRI9rN83CxXkw5QF+SBRLikcGMoWPokufDyviFlMvJWWEMbGj9412+0H8gGVZtG6qO5J73sQN/BiKAUO16wSA4DRvBP8ZocgAwnovbei9LvawyZ2dPWt4rgjxQgQlk55x7q750v63ttq28GKh7sKJC44gm+lYku7VWx9rVHVjCQArNpb7I0srVQ8tLHZa7O+t+Tq7JiTMQue6NJcFTt35zmao1Ula7ybYOc+kBhj5y5/zbZlXutDyf5FKzYka7ZpDGdWV64OuZbIasg2A4GNWJXXiqkZkk21R4o5xMGeSQ5DyzDgAjBumVrH1D1dMfTPuKdrsg1j9eYEhMtbPB5gxx3ptlzNXQf7zcQVb6RPCJqmJHVCNEIt7mHvQHE9kgYsrlndbWlj3Qz6q5JXEF8qquZ0T1oTb2Q5uhedvGeKo5Pwo3+GJZ9QSwzdTSRqx/Sel55V0LM47x+CCWTMUzzLcfcca2JHmj2ydMh5Eus9pPDOscPQhN06HaskrigJ6FdQo4LWGhX0bH29guqR/49BuFw9U4w458eE7c6YMFWkmzxJWJzWG+pIHIOW4pFjsdXLFdZsIrIJCPPWae3kuOy+PZKPCDk6lzyIFrrGZlAppSsZ2062khI8EhZb352a6oW7fjQ38eKU+C1lb0CjDrFV0YKNgOKoI3rRtnj353r4qDveQPrnOhroHmLJ61IYYO9tlc2Hnv6Z2GDXcwWhohca2OqPzdvLIu8oBGYq3T3/s1z8iF6hzCIbyUXid74PMTdGGUIpkDYTKNWy7QgXBF/UamitkUzVvE2jYADCqKT1A+KxFUvkp3hZO1YgGh7JapdL6GmD3FVGZN3lVehUCypTJcjwUEGz/9ZX0d/0j/X4E7nBvYddcPHAWi5cmFrqHpMRyFnZwe5kzNQI6Yq1mthukAqhpa3xZ2N1fT0W7YnK8nYJtWOVyxKlNl0yWN6MNeHv+ppI54pIyEqEOpVAl2mV+PGwPSYTGINUr1z9c9hDiPTkM2qKjc5ysIkV05NwRIWg+5nnqONHUhiUEj9QpBDLwo09hYobo6ju4X4OD84yhoO3W0Hu56UNyMCw1Bs2JGt/gq0S8kuxYQr3Ylb4KaR144O5gkqzL//xK5eFv2NnCSTSExNS8ccPlamjJqpvIh29jPQwPz8gMCVIKT9kz05OdGmbrC0d/TGjQGX2Z5JV9lM48jZ/PlXF5JuznnBicSWieq5ruHF6svs8Foimu7ah3HejsBig3BBdwo48qG9M7kQGR2CRClr7M/YmOB1emnLnU4Y6JIq6yEaMTY0kQwZtJ2CyiCpRMcvd7G0pFCUzZhXUXXK/pxnYr8TIGEE8xC5/voSg4XS/oKmuYXrcEzVYMnmZa+lJW+/8xm3PYdNl6asw+2O1jv5GJUa1V+RVo442qByKc82grRK9vxlyGlCtiaER3wDLxiYK5ppOCKw9isGf2Uh8SSuMU1w3ZtiT/tYb7GOjLvaR1gMBXU7rXc7dly8avyDfWLYRsZXxtA/FuO0Km35XrjpGTTaoybP0yvUnyCilFDGvMaZKKRYwq5EfWYUbgdLhZMxCcSY4I1mN+ZMYSuYMon4UqYArVmLUfDIcCe+RTEggH0jyJ5Q8S6+i09R/L2ymkkJ18IfWoVwfZ+djQH3HFt9mIKCU1QYRcl4K4qLalrgeZ7Uy82LI1RvXg/9R8RbsVZpRIcf4oVmW65hV0vUyO5ZyOwNl3tDIhSAqfUEkYcwGKp5233QhZWF2yNcU/JLuY8SBzJiJfujQrfu4oL4Z/VzmZHTwUDw0mOrmioOHYNa5TwxwxZ9A4NQ52kdiXvkh5fE3+J78eP1m50MVYkQab+kevIKKvQ+9k523/X574jjY9HzjuNfv8y0FpONmJ5pUyShedQRaL8qeMZFZF+o3KhF/oK/Dk7HDlYCqLP/S0LcLcGAwYG6Q/XyOAPv5W0sj18dLSYUX4hjGLJ2xMsSQrT71XpbkPYcUZokhS0IeELby06WbJVWGYB1couUxLTK64Vs4YS+Wqzvwx85Y9zy4Vq8YRsx2IgiB4ELSYARtZ7lFGA8V6Ktev//OFlRXHc8v0cQlM2YvFWgyjzKRDEsdy8GZqZh+xfj73OKTNLvTxwf8Rf5fsRIYrowhjQ2YMn8ARz8cD3NQIbxrp0dFkeg3Q3ZiazS1+OwaPXkzFxsyNeta0Y2Jg1sqdQJeaElVVO7JnqrbBpusslo8aPkf6Hk5at4OPbUaMrD5B2h71nWp175qtU86h92M1SnOwCSB0e+/k5JrcaaknFSCh0Nn1qU/noezCpOjSV9jDuB2YvGjuBS8L/WPVUhqVSZ0rNWQTx/+JS+S608Bz0j64yCiGRhp2FDuk0Y2jCQpnKkbZHMknR/abgCrFP5cr2fznog0Z0CWWnq31Tk4Pd5hHell8EoscjOzYF5aO9jF3hF2dEujnajVkDY9nr2dH5u4LSlItOfoFWqsow202pibN3iurU3AV2Uf01HlNW2Kjd+matn3pXn7sdaAfvxZQbH7b6FreXewsb4i4S1soxI/AOWZbWxhwUMsa6XiqQmsTsN7eyhEp2o1c/Mzh1KevgYnhMqfY1VbZF9H1gWuBRMIj7UxE3Rt0XU1q1tgevER9DMF4jtcLF/WP5IEO/AjBQ7PQkS8m1lupwLNI0bBk49+VqeEJH3C6IXdAsNP9sCnZfCYkwGo6yUX8oGEC763Yz+VFSiEqm3ZqcPiR8CjxWkWRwA9Jzlc7PV4sPIAHUw8hXfzkWOs0GtrzYXlhxgCfGN2RNlI2QX7VQNxyzfE802Zyp1ea+tgZ1usuJ4hpDKmk6c4Q8LyjDyXjMZJKcoQF+ys3uw+Uzj5J706AFrWBrk9wAcvdS4BSlyJ6B5etV+3uns7oKTe7bInC6/0BSey3kQaqzCSxH6K+prVpRYmiT0DdvyTLnYmUBX9BkukncyNJrtnGtNxBFoH1mg+NGgM0qGlzv6UYeK7On+OssGdb77HRhZdYPMp7jmpvQT8vI5Pu91Ody85aH/sgQoSD4k8y965E5AsuRVkzyeNVLpQwil7ANWM6WrTq9bCjjoRa3hYpLISa21+DlUhilOxd3J4dATiJ1tW2dUrB7slv0qWMoVSUgrGI3J1tNPdhgGVwwYbiu1i7UQnB2hgtaya1rRURivwlfKyPk6jP3+Ib34Q4EtEz0CzK0ssLxRhyA/mECcMgpc18UouZ8EKoAxXHOBLBREulEA8w7SNpE5fcnSCEIrezJegTA7AiNw7oUakG90wSimWpNi6QeasvekcHEjyKJKjI5KmJcrZbUD9U6noUZ5AwAUgOcGkwy2MsKPxLHuZ/ZEoIjN7NXytTAxPYsbm450vWTYQ9A3Ynw/VqYnvbKxCdC1+GgmXKZlIXs68zSJ+ciS5dE08FMZk7q2oR3UEmLVj3cWlGUSlQrOcU83HIW6Fyqb/E5zInIxEnfRAnrluCYu/1FoaMlCnqpelZKVi7pUVLH5A5V5avFARbRNPWfuJ1ru1yOWPOEAOVlzLzCjoH9MwlTpwHSnif8A3JasVH82Zfgz24xJtNFvTLcdH7s5BWMTuFJNJ6JsdiHmAROMpc414qnsjRPxg6cykKH4Pbgy1GupaU4ieOUtE501spCAQ/xqCE7uBot7AFxXum9CoLYRJJYnjKz4BpUhCKJHaQaWqLluNqy6g3tAZBW9eQ/6NGlqVAcMtODNQL9Gzep1ZcAItPKvXU7ecySD/grpJMOWAQsUYTY7NG6bMBaBTuyt5uXwDJBJDqUeEWUCrhtmavQBnMHFeJY3N13yq2WOFe/WFR1GlcZtguqGAEVOQJhU0HWHT39dRquruxqyCSO85+yNjasxY0EMRdRY5Mo1lILLZW8gSErrEwVaewKXWODc+meMIH/TyzhFQZG2BAEV8cXmEQwS0KF/7jsUZXE368ehsnc6vMTGgFuFY6tWwiHcJJR27rUajvHEc4eNkOEKKHyhlZLke5IvVdBf0Mo0GvtZdNJjohrZJgh3Dim2SC8bI0K+xeq8amFa0HNRrvyXxsR3LQDacdnwTQUiU5ZmqnHEagMjWh5DEltT6lYDOL6HxszYCHjWZxb0RNkuZbCRJEyTj/SgJB/kWVdohPveWszUkTmiolHRqMjeuZICrV04p04+KP3T1Wk6vAjgombR6ECPnYCFyjtCJbJbzvZtYxeWJO5hi/xcOWfmadqUSs71ytX1+eLydfJclcg0yQKCo6zgLW1Ea8QOMlFaTQIM4TamWcgF9rqjwibRJpspc2KWNJt8GpxI0ttWE19xDP438Mh77EqL7llylicdCcAeJubUOXi3P0QZaf15BMWVm1+ro2X3G7MnwKIYwcEW4E8ZcggHtzBlJDzjix5v7bFXWU65FLr4KkBMJsHxIWDV52dUcZRsSZVFIw2encuJBtaSMlrHiititLYBd4Cz8kfBbXwQ/fty+RNzmcBqiwaXiPsHsZs5kIZfTqEh8vvqikTSbyJ0sM+PW5PrMIzB5WUgVkg0iJRuVEM4VBLhVOAaZYi/rZHXm3RhsJ1EIJIg/wakvw/sFOOc67FoZe/U5tZLouRjFPsEfMtCT1E1wfJszxoncQxcfiErHXJvB0oc2yV8vfWqDT7CiLnDCPPObTup6yjAFfRaTVin6r6J6fzyvPBeJKLfIUGweaf3IJ6YSPEjJZfMv3Oeme9jdkbjvxp9cklVmAcuLL/e3Od6hK8IjoZ5zPZVC/Xhn6/DwMTCWPzDNi/Lhyeud4yVjnLFvy0AP45tSmXq8gz0gZrYlbnZSGk+2LyWET0ipSEznsWfNWYmR5onwEA0AcK2bGj/lZ051ELohGvuB/TOz+ghyqFZDB7o5uavwFK4Qzmurt50vLN2sbEjEzQibEN5Zd48tywtutwL0Sox9ee1gPHA10bwcajx+i0EPVIqHR10Xm27sbcUEOS11z1bG8Hh1ZdkmaV0MSB9wWJsVyXaRXHLAa/5IBh1OlRlfLXBybKOzELGcmCs8ZzELY/yFRqxFTxqbKCWMbBR6YkhZ8QkPdjNCD5YrnuZbR69o7JONzJyGiawiLfUiBEydLPZ1b5G5spCV/upKd+3rrNnil0mfLqlG2gz1LBA38JrOK9313N69qZaKNeypNdsldFpx1GIZErAEi8PqBdNQrMAkWuDOA2cKkHKc8ss4nwoRMzNpKn98UjuTTOvufCdYElbplB5muSYHOy07t0i5RWbUXOGWEro685v6Qlb5DXZDnVzm3QiGLUQPsS7WiQa3CipASKCt3nZBMLj9lsLqE9epubCS0MQPxTLtfLRN/TprxjhqVav5uks5xpiQNyJBBRUdVTQdxjQkfWefuUek9QKIAVFqjbj+PEp3UlrM1TFp5Lju2QsrmyS7ItFFrYkZf7wd03YaJ/omt8KCcVBSj/QkJD3N18MmxuLSt1abadZZZR9Rp+PPMnS7CKyvqeNFGp+lDeAHwREvBuSoQNq/0dDBNrrC5MZnk6mC/eIXMREFGlRQod8vFMqbMP8Hl42PzWbhw06vAEhTpZH83ARx209PgRKPtJQKyZ/ETAWCrgAKZNCMjjYCVv/vxIuRTaqfE+GRJ4KjkgxfLvL3O8Dk+nXpSb3ZLESmh8jZM6b5tzB4WuSk6CfwBtSwqzq6Hb6gLbyOW4ISpsgjsfpXZ8msvEKOypIKERkMtOICeGW3iYpQjvHoarNZgO+ELZ+sNguFzYCAdiD2ryCilb9WZwzsYPey8RFYl1rp+Da/TrhZip8leTiDb2NVoph3wFAZF79jPv9ksAwGK4SEXOFKHWm6E+Q5+aZiUlqlFPZTKxVIQqUnjZhMShLVC7UnhUXq1/r9fh/VKgU0F4xZSqca1M9TvfCQi7jf2ZRcSny8aHC82U4uuKkEl1mypSTZTtVyVYWrAvmiy6E84eUShVBc2JFAwAhpsvhGvPR9VNYZ/iPbt7+xbTptfST2lebMWk2UN/T/UO0KErdip194UgNsWAo3Vr5W6Rf6hQp6AnGb6CehPHzskwLku7gyssUyFlqk8PLt5TMrV8LUzQj3AHWJJT0xdgu9XsMimK2gJcRy+bnaztiVeboHVtfZCQt6KPofgAFD3zKZSZKRSByTsZ3MRDzczZMvoBQ8FMs0Ro2vJiQ7upa8sd1sxtg/c4u1f69IYzxypThDlzNK97jZXE1WFeIbSdHFEir4iT2f1CtnlcLKNYrLw5kNRL8unV02PoIY/l8fOLmWHjpFNkFndh2/B9B+5XjnpMI2QPPBmqmHT4iGerxzctmIy/cpBY3OZQpjHhDRXJ/ZdWDB+na0n5N/ArRa/Sq0StPEE1qRMvjkWNxZZO8cSjlKXl+TTZGZEYFAiOc51kvYrMeGKfJfflUdWcak+tNPJKXRGJMpOYfCWl67KTFD7mznMprmnkPZRlJydo1oKp2fmiuXgfxgKGIUQpaJWciQsF/Q2hI1U5nRc6j8iD9KTRBFNHSJTzJb17478bOI380sOkuqO82t4tSciVmLXl629eyb12ISE4hUbuta1CMn9VJYlnvLvN4tSOCcldXl+bzOtYTKHGP/C0w2OSRJ7l0N36P8yY84qnDAgfIrieq46VLjbalgu2jFRv9x0cq0QOBers6l57v3rofHJchygNJ80mIqP/SL/mraPf5rVfiZF4951HdYvp/BkRLZsm+QRXt2mHRSQYVLoDN9BVuYCnpfQYWPBd/q9R509ciJ0upm/o3LI2oGvgBL0rOXovrKZYfIyGlMveBhsZJIA5GESzgmGQ1I8NNAvUxpR5ViQumIwFumCXiZC9W/YFgyFiHLfuSxSZ6SoRgtLIDFz0n5GJMSaP1zVn4/45KlGjreN5qWMcGT2Kt5pmZq7KQMDrAVRxljDzuz1Oz+m1QlZ1asOjHdkX7t+VfDgGkgA0S6jpTAcVdQ+xZHgFWEFtPv+VD/aBKxEh1TqoJp8FZXEIOdfESQGHb1n2MZ/C5kJZ8AP4y0/LnZzpaozjeVqQFJNjPACdLsKys9bpaVLHBjZHbkHcy4k94G9SQhiQfGxLBV7JvMVaT6R8aOFnrJ6v/+O4N0Wf/IAUWNd8xvpdA3nxQXCNVXq6ETCLWnu8iaOMyvJtvsqGdYDQk5dJOEqXb9NDrZPtIk5Z6Qbo/AYG4pS8qnRygNYCFxHCMv8+i5ujaUodtMpWeOlhCPGfPnOmoiv01GDVQsg91EDgwFQQNxVK8da1wa/LleQcWB4uI/12UTQ4URI71HTYDuc2z/svpHv/9ROio+h7HfO+xWiZGlRF7J1udGD+lKGXcxsoMrkOYuUyX8Y4WIJJGqzZVtiVm2EKKJmlPWyvkPPuSKut4UfWfo//X77h8BB5yCYJIFH5w8rtDcTTAClHo7z3wP/1coXRJHmf/1+7WPT8s16rUS8ShcnlM+zQHgBOdrTs8DzplQkkqNWunVxuX/+m7h49O/C5f/K3z8o1B+Whvm8fFPcicUi8uFv9AUZ6qbKdEvclw/Fq7TX2NPHR0ZuuuVirUDfeAozn3tQJmY6ohOZ7dYYXdbNyOd5E3S8q0hTWkkNit8KdEbzBAQRNeyb0ADIWhZP81YbotzSucISkLfYkY0+irXJdoYJBKjogyx99oa413L0LCTWuzUxQ6gzGhTLsOET+ubT3GJPoa4cjYU8SxpQCCZpXBkBXHAcozxm18cDmZ8nMItwr3iUrzLb74L9hUed+eEhE/iLcZNehYuLKE/KfxCc1sBobW0pFak+xmX7HVT94LX7P0EfT6xYJ3gA1MS73eXUffwBO0ennYh8H6Gu3QVom3CshfXbvrx1ZKuP2VQlT+PfLV0GT5R6FvtwVH8gg+ahb8/I+Ms6haEUa9c7F2R7a8f9ZxRjjgAew4BUCj2+2YRFf/PzB8c/k4/Kk9AKv0oOKESi2BoNlc3zZfd3c2nT810D95kOPO2z06kzf9X+9//R25wQGB33ZzgrOPkVJC3/H6kWaHpV6X8g7OwvG02V5eGojuaeSUAR/X7hf+4RB1kCWazPZAz4N8qRpP5KbijuUHN08UsL9uk1vgcUjXEFXIyTyT84hNAzsuWTGG/RP2+9/FprYIK7BrRnPDsJr18A04W63NDEW9R2otB4Zcp5wcTuA9pzwNlTjaRvoGfw20E5bl5X4Pr9jl3USgj6/D8Vw7583Oh/y4WeuIXXZC/0JPQ9vciuNSxJogu1HgGkOYBBHkCKRx1rFXqleflZrPgK0XfQO0QegYYPV9ksb1j+gYA8qybxbUNdQzztHTXbK6+UsfahmfdLKIPzKunUKOUOtZ+EPGeLQLnvVaLhFx42NTcc90blYpVd5R5eiBxcvAzvs9C8X2IqbeInsLYwj0UX0QDydA8AjmhoWxpk1BxIcGcDJPfgi/8j/SUCJ0FwC3SvdCdUkn5lwoP9i9nmXco08FkC77kupl3KtOrL5GamfcrM6F9a1rSPcf/qjWy6biF2OILQKPL0q1izAtEZmlKaH7R+F/ZlRZZohCVCr/5/qdsoaot85CbIki9NGKtkSRd8DKSeEue7mY0lrXvknfU5c8/cK+1DDizWRI2ewfjTwZclZa5jc8eablbEvz5Oc6xcOTHeeZ8/zWHOZ+LL39+DnYsHNnBDnkgfs3xjr+IJQbHJ/e/0UNCji6UkcmFHkFCz5NOIGmJiU1IkHVMOccppXCWS/FIPYCUbKQmHm8SA1cx0hjvUmZ7pcAROMERXBtz9/Xvv9PZJtgOR0+yqdgeL3QdmR/0JqD1CmW0jjZQEimyzdVV4fQdNf1xkzBjRAdrcStGWuw/cOY9bicH/QuMFgkpZdnYdNQVZ+KH1c9qn4Sn96q0qeVpu2ndulImnsUEH3RODiKiGzKggnzm5Tkwn7X16OYl8fmm5qFYRBKXVGmTVyzY6EmBLxAi3obuxIa56lpOs98v8F94hXoig7kk18Yyik+uINPik3XsRQMJ5gD6UJblZSnSL7ZFXCjHgvhIzjn53AtzAEdfdzIv02YcgfkthUPgjonUWsGfnJI3RlQ46goLjMGyGAbkRFSt/qPfvyz0zf4cwkEiYTx/slMaiE9OKvjkDqgrgpqUYwDmaB7Nc7pLN5CwcZyYBr7FxvzyOccwoNxDgZZGD5JGkd2L+gOtjJU7DdveCDXQCiTHRAZaMdxZPPFqNXErWPDd2Qorf6GCHzWs0WwW0qoJ8cNgwzZX", 16000);
	memcpy_s(_servicemanager + 16000, 17884, "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", 16000);
	memcpy_s(_servicemanager + 32000, 1884, "7JjXVmmV5mZNsK6JJpjCYOLeD6y7Qj4h+wjZp7/qpgrFa4O2i1aUO7RiIVvX4B/VGo8VU2M7oOIXotavNpv9wmq/AO0+WW32C/3CJqIS9kkdbkW4FdQvoH6hvElVUnh12fi4iR4eiqmWAJRtDYjhiwQFUm6tDjME9fWV5wZJj6x5/K8Coof5GMvrkTGv+PWLGCmVgU66G/SsRFYyahknEolbHigjO0x2XqEMsS7bWAyRw0UDNuvQetT08RAq8JVptiaxhXEzsDLSE21xRWRn3K7npCyG4WWTKDd8RMSFEcBELkmxgle88UgkrbD5OlR+JjANfbByrZvE4FqFP6ilmju+aCu0SuwV8wQsIHZJuD1yg3YzwTYfC4vViSVFUDWQXwSCjZCVINjLCnI9J7A0fJXlIHXbznufsT8P3gGMciV/95Mvf0i+LK5MfnDuDEhNGtFa5E/6pmSTeOyzsDEpt1NndLU0vDLxdCMY8i0QFeyodfKan2eGgkbTJoFFKmi1nAhBjHadAGeGdCY0flwYD4p9jcIJcthnCGgkRK4G9Zv/6pgavisVIX44m9CgiicTKFSQI/ZZrAAT4jP6qxkIExKa0mIgbduAO7KfoQPh3cZSKRuZet7Y5sbNOChiXVrUG9tVdzKghUurFfKCRUVZoegHyeCHWp9qKbRg21F1pOlOoEoaOXrYIzH92ufbyLOCoQ5DdUOGhACYfjhKuPi1kGPnVCCJmckZbYFsn+BF2r1w9IqUDyTEJLHL0EbgQ81/D5AJVBgNYuaBMAuFCjm89MY21CwUyqTgx/JmIZGL/U4HCSOe0IPk82cf+vIQMTUQShwpDokXVugHR0oU7MQAimIKzMAXEuc26ctmqLIQbsCwhjShtVsOFZplaHWxt41dTzepPwB/LbxzqweHe7udg53yZpBQB9ZwCEzG2qhWq8RJMNQUeE2EWw/9Rrmw2e70WlsHO9vlcM/DLQuUAJ5HX9ImU6S2v6qoBlbMid0yNbp2ZXYmGI1c14hRDdZK5/5Lopk+XH7zwXfU+vIQQS4RWRLavw3MJYXoDz2F4wlPehDue1L/UVgBitF0qKIjcr4ayWWcBTrhwHth0JapslsAQdXM0nA5LFWy6IDCgpCwEQKmJ458KdXEmQaxmVh8IKIuCwwJfvc0YFJkUkXnH39SSBBFllwoScI2roUY6ZRGo6Qm0a6iG7LtpsgpQVrIRNRlxSu+YLN1LcRAobYCwxH6xoEAo/Y6e3AjR+RVScFH5x8MMeHQG90wkoY3wgQxZWa52+JKPJQ3C8I6Hlyt5cLOFM+pbZ7tHtDUUWwbO8jBK9j0nHuku9wPSkMT09MN5GDbwS6GNPZocI8UEym27Vi3WEPOxNQMY60BnELC9CJ8Z1uOV42ElGEhRYmGcBnOUBeRjR+FXpJaVXvijkrFlcGf61ApoKUJBcTsZDOlpDxjEj/JngiA89cVR5D8G1NAw56ijjAsIRBdLaaER8961jfn39qGiVMJ4Tfb323G8sFvPksGvVfJXAAFxm9zUzi5QsF95s5ddKe5c5dnr/m9sqTANeHcSstc3cMBi8xornX0KvhzQ8Dpsv4xtIvMo9uJzBerKyXuv4YkMnQ1B7eGOCImHJgIc9GI+reKU3MmZvBula3DzRaxmdDKkHJuHai1mFaUDXwBvSgDeKpmFLPgx6/3KU5DiYRPOubKoSTF6BBpIdziF8DoNjDlKHue3WCK/SF+axiLcjD4yAJ4zfaFCZbYnBKDVwwMjiAuM7SlxD6B7MonAQKaVJaAmI9JwwFjg1qXQFDBGkuk6tjSJgau0iXFnYWeY/H7NsMlquykH2wf+P9fOZpq6MAwEVcQQEMJzez01BL/4DDIMdYKtgrIXGuwewEVuyun", 1884);
	ILibDuktape_AddCompressedModuleEx(ctx, "service-manager", _servicemanager, "2023-01-20T21:07:47.000+00:00");
	free(_servicemanager);

	duk_peval_string_noresult(ctx, "addCompressedModule('user-sessions', Buffer.from('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', 'base64'), '2022-03-29T11:33:55.000-07:00');");

	// Mesh Agent NodeID helper, refer to modules/_agentNodeId.js
	duk_peval_string_noresult(ctx, "addCompressedModule('_agentNodeId', Buffer.from('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', 'base64'), '2022-06-03T01:08:06.000-07:00');");

	// Mesh Agent Status Helper, refer to modules/_agentStatus.js
	duk_peval_string_noresult(ctx, "addCompressedModule('_agentStatus', Buffer.from('eJydVk1v2zgQvQfwf+CNFOoqQZOTvdkimwbYLLpOt01P9cJQpJFNL02qJOXECPzfO6T1QcmO064O/iDfvJnhvBlqcLJONCm0WnED5JJo+F5yDYxWSzQaDzxEqgx4FiJmyRykneD6bUYjVgN5kX5K7AKRSJGCMXEhEpsrvSKXl4Q+cnn+jpL3hNEpPvF0WvACplNK3tQ+3hD69sPV7adrGpERYTVN+pixyG2eVpvocHCSlzK1XEmSJTb5M5GZAM3SRSn/iwYnz4MTgo8LS4Ac7/7xnOwAMa7NMdLfyEVEnoldcBOX0ix4biuGMWZrSy3HZNvaMjTD7HYUGpLs66205+8+3rCzKCK/k5D7Z3jbGF0KDbMRPAV2MXSRY9YX0bgFFslGqMRVQ5ZCVBtWb3Y/qqzd0wL/+nI3iYtEG2DOTWzVF6u5nLOoJq5STBObLgiDaI/MJ1LpIp5pWDJ6K9eJwJJ9BlMoiQr6DCnwNWS0ZnVPlWzHzaFoT0/7LgyrMsCDNqWw77t/R7Tj5zXroUcczvepm2+/3q4AKJTXa1vXDS0QhofrqLaBTr+XoDdXrnWYelgOsUtgjZ/YMl3B4qG5+sJj3Z2soWCYzhAByyYEl6zvTTNuFpZ+YYkB1BkjZTxDp7jxTNJVNiLUR0OH6FGUMCJucxv0iQvOta2T2b4gHF8qOKYSzgUJlkZxip1h4VpJCT5o9uxzHPnPmhLHQD0uqo1tTzcVf4wENN2RYbTtSUQtOgisEYMzc3JHm2A+hD46UJDZS+wHPLzQE6lQptcAXlG7eRUuuTK7YvxR5jnoOEca5vvU+Nbk+YbVJYv6dM72ocxb60QIlXrdLWuB9kwQHj9qbqEZWDXSyXtIzvoGyzhVxYah3bCdP53MPZ0DhLvbXoeBMHBcO05mh+uuYaXWcCXER24sSNCmKugLOjmEd1U9Iqvj+uiBjyjkkP5eVUZPFf9XEb+ohl9SwosqCI5mTwfbduJUkPAdw7YDCS8GN8+sM9x2LnRjE21ZOxSx/Y0SEAs1Z/QfN7fwRMjfYBbEj1NnYCGO4+aA50I9JCKeuY3SWHwBIQbsPV+BKi3bK2JQwI6vrzJ5EECscss2SW3gNHTnnvplZQZP3LLmNIbk/OzsrK11cAnUYw0jwbFpFyD7g74F7AfqhrSf/dWMxsG+uwrot8ndPbm+m0xuru9vPvxLm3eYvfyCI6xcQYbZ4u2AakC2/aucsDCBDEyqeWGVNrQTbZP+Xl7r41mF4a1D9524D7xjdAOzWGlsm1z9dFju/HrOD8Acql9oB/OvEq/jaqWvVFaiH3gqlLbGX8pe86Pd13CnklEgFrybfwDySlmh', 'base64'), '2022-02-07T14:27:31.000-08:00');");

	// Task Scheduler, refer to modules/task-scheduler.js
	duk_peval_string_noresult(ctx, "addCompressedModule('task-scheduler', Buffer.from('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', 'base64'));");

	// Child-Container, refer to modules/child-container.js
	duk_peval_string_noresult(ctx, "addCompressedModule('child-container', Buffer.from('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', 'base64'), '2022-08-21T15:23:09.000-07:00');");

	// message-box, refer to modules/message-box.js
	duk_peval_string_noresult(ctx, "addCompressedModule('message-box', Buffer.from('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', 'base64'), '2022-08-13T00:51:56.000+01:00');");

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
	char *_agentinstaller = ILibMemory_Allocate(14125, 0, NULL, NULL);
	memcpy_s(_agentinstaller + 0, 14124, "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", 4000);
	memcpy_s(_agentinstaller + 4000, 10124, "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", 4000);
	memcpy_s(_agentinstaller + 8000, 6124, "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", 4000);
	memcpy_s(_agentinstaller + 12000, 2124, "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", 2124);
	_agentinstaller[14124] = 0;
	ILibDuktape_AddCompressedModuleEx(ctx, "agent-installer", _agentinstaller, "2026-09-30T00:00:00.000Z");
	free(_agentinstaller);

	// file-search: Refer to modules/file-search.js
	duk_peval_string_noresult(ctx, "addCompressedModule('file-search', Buffer.from('eJy9V1Fv2zYQfheg/3DLi6TOlbP0LYYLeEmKGSscIE4XFNtQ0NLZYkqRHHmKbRj+7wMl2bEjaXMCbHqRRd7xvvv4HY/uv/O9K6XXhi8ygovzi3MYS0IBV8poZRhxJX3P9z7zBKXFFAqZogHKEEaaJRlCPdOD39BYriRcxOcQOoOzeuosGvjeWhWQszVIRVBYBMq4hTkXCLhKUBNwCYnKteBMJghLTlkZpV4j9r2v9QpqRoxLYJAovQY1PzQDRg4tAEBGpC/7/eVyGbMSaazMoi8qO9v/PL66mUxv3l/E587jixRoLRj8q+AGU5itgWkteMJmAkGwJSgDbGEQUyDlwC4NJy4XPbBqTktm0PdSbsnwWUFHPO2gcQuHBkoCk3A2msJ4egY/j6bjac/3Hsb3v9x+uYeH0d3daHI/vpnC7R1c3U6ux/fj28kUbj/BaPIVfh1PrnuAnDI0gCttHHplgDsGMY19b4p4FH6uKjhWY8LnPAHB5KJgC4SFekIjuVyARpNz63bRApOp7wmecypFYJsZxb73ru/Ie2IGtFE5twjDHYdhUA8F0cCbFzJxq5Q7bpGZJAsjb1NulFNC/O129ogJja9hCIEzmpZGwaDaTLvklGQQaqMStDbWgtFcmTyqpjfVyz0JswjBkssPF8HlfnQfZ85lCkM4wCPT0ChFPUgMJzScRUdem6Mv97hsDRIMQeJyl3e4XzE0aHtg8DGCTZ2bQVvyYgf7gcdy4HEA22jQiLBnEJ9Qkg2i+Mb9uMk5EZo4YUKEBqkHZAqMGu7uiRODjLD0CwODthAUnGKKMg1aIVGcuMoUh+xVI2Fz3SZr2+aaFume56gKOmAvavHdAcCcdyPcGTlyw+CBy1Qt6xOmEhxkKDSaug5dXbsqJS6AgWTEn7Csca2NesIUTCFTIT5cQKIkGZZQWVuYo6wKAnDFLdm4Dcu2B+ftJBamVAi9mH3Bzswg+/48lOKcFYIu/bfp+dht4//3im6GeJ2km/7QqelTbCvJtCdeiWNkFi6j3wNHYNADR+GfLR583jiDYDiEQHBZrIIImh4tfEMp/l3YWBc2C4P3tNbYirLVfH66adhqum1LDsKRMWwdc1u+w72GWmg+OTHJ8tMT20WMbcbnFEbOr91zmXGBz/YC5YKyj+cdguhA245YdcJ9Q4anZtnm17JJLUMoLP7f+/MKSf1jwWyagKIgGrStVfagjIv08JJRDnyrQwRRjCtMPjlhBP3Cmv6My35d0s9x2rA7oAcBhiALIU5Xfd15bNjF49HZfxJ1ezSxpVQVFFsy7nYUDJpTuqSEWg/eF6ZKhkHKiAW9564RJqdnWp73DsqPQ0hiUlMyXC4683ZHrOCy7Bc719hq4Tr5H7JTdmVxQ1h61qUNH+Gn1xd3GVPXV4e6Z/QqRG8oviMChvUyWunW9Dsa4cF+oDFd+wGbf/N3jrji9NaNdIqvc9nJKybD8zCCH5zM9t1+p7GXJLY7t9fuAXFHi3V15qZ9Z3V109R5X32d2Cu6v3Mh2uO3Ru8q9u2L7+qqV41tfW/rul2u0kJgjCutDNn6Wnb4z2ng/Q3oGBEE', 'base64'));");

	// identifer: Refer to modules/identifers.js
	duk_peval_string_noresult(ctx, "addCompressedModule('identifiers', Buffer.from('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', 'base64'), '2022-10-27T08:44:49.000+01:00');");

	// zip-reader, refer to modules/zip-reader.js
	duk_peval_string_noresult(ctx, "addCompressedModule('zip-reader', Buffer.from('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', 'base64'), '2022-02-01T20:15:31.000-08:00');");

	// zip-writer, refer to modules/zip-writer.js
	duk_peval_string_noresult(ctx, "addCompressedModule('zip-writer', Buffer.from('eJzNGl1T27j2nRn+g9qHjb0NJgk0pWTZO5DQu8xS0iH0dros03EcJVFxbK/tFFjKf7/nSJYtW3KScvfhmmGSSOdLR0fnS979eXurH0YPMZvNU9JpdVrkLEipT/phHIWxm7Iw2N7a3jpnHg0SOiHLYEJjks4pOY5cDz6ymSb5D40TgCYdp0UsBHiZTb20e9tbD+GSLNwHEoQpWSYUKLCETJlPCb33aJQSFhAvXEQ+cwOPkjuWzjmXjIazvfU5oxCOUxeAXQCP4NdUBSNuitISeOZpGh3u7t7d3Tkul9QJ49muL+CS3fOz/unF6HQHpEWMj4FPk4TE9K8li2GZ4wfiRiCM545BRN+9I2FM3FlMYS4NUdi7mKUsmDVJEk7TOzem21sTlqQxGy/Tkp6kaLBeFQA05Qbk5fGInI1ekpPj0dmoub316ezqt+HHK/Lp+PLy+OLq7HREhpekP7wYnF2dDS/g1ztyfPGZ/H52MWgSCloCLvQ+ilF6EJGhBukE1DWitMR+Ggpxkoh6bMo8WFQwW7ozSmbhNxoHsBYS0XjBEtzFBISbbG/5bMFSbgSJviJg8vMuKu+bG5PTYX9wSY5Iu4V/ndfdnhgXo3t73b23nf2DbPD8HQ523+x19t+87mSDA4G/t999+/pNt9WTlCfLyKf3MJVtjtUAJVJ30bCdAZ/ikNNl4KGcYBUBLCe9Ct+PBsPRFVtQa+KmNIUvqPxgZm9vPQoT2d0lDTT5nVZ3p/3mqtM6fH1w2Hn7R6MnjYjzB+zIjVOQoEzISUDXqdW4atjXrRv5a6eB5o7IE0SxADWhcKYsSQdgbbJD2m8PWjb55RfytgD/boRv33C41/Y6wM6NbZdER1nXit7ORT/MRefIi6gkvyTG5Qd52m0JjZDfjaBV0eshO7kUf3B12mSXdIrVxDRdxgGxHvlCDkEHTb66Q07yCQGfSmYwo+mJm9B3oQ9Wa31z/WLb+eJAEbC665tiaAC/ozj04CQ5ke+mcGAW5OiINO5YsNdpkH+Rxp9/Nsghaew2FDWNgQtgNhpl1Sm/mPI9vM2XhAfSYoDa6hFGfoFp3/FpMEvnPfLqFbMFVCYzPmwKiqsX0C4gFSSudVisEy2TOerhmuWa3oUj9DVkgYULs7PRgS03C5+n4iv1E/qjLIzEnqQGcEHFqnEpbfOqkToeMRWQPOZG0QC7VSWV4FEYWSp/Cc+F5Qsf2OQVGUiYXLC7OQYmK42XVBcovIU9wymF8mZ7adAbro7hglp2eaICx5fFDyRfHCp4zqZpaXmV/dL3rIYu1zDQfqERt3VgA36ulKkL7HpmgDG47FvD3FOt/E9lGwhv67XIz+Ar8CviMOJphOOKazok1gC2GL4+y6yrUlctWFpUiW8DnYQYQuPSfdOUBSyZ04kVRjy0Fq4JglcS+tRhwTRsW41PIscgfRqkseuTAYQ/Lw3jB3JJvTCeJI7jlHx2FCbKr/5A+RG4CwommbsfTMCcLxENJsBBROnrm546B4Mj9jflVi2xIGSiUCK10MX6jbrgbpPcwVkgECZL2UKdL37ouf47OF1XmFjphyuTEnjWoFwDxRsHtmXyEeLHXuf81Op01a3tox8/WU6nNHZcH5Ct/S7sQ0ZYhSyvEs2nCqkc+lXSYCJq9SEf2+82yV4L/80cN6PSBirtffwHKu3OMwh04L+FBMqL6A8czFpprjlYexM8T4+UH9jkEZsFLtg2NWO3u6h3YLGvISN2Vgqswe0acd/D4VgsFytwW/etA/IdipX9gyY5yIkA7r9pQNEgPyyheIHjd8JS8s53ZyuIHaCqjIL0oRrBtBpP7HuazsNJnS45oWy7m6RzoJIDQrhN5AKmyTkPCSvJtMF6zIrBuiwOYHXHaVZEJCu2dg9sYO/AtLWn9wY6KyjluRqo1IYd7wiiQOmSQhbCvlEynE4TmqpUKo4MRoTHKlJMMxQ8qC7UFiRaYP8gToJFG5xN20nDEU9fLXstFbl7UGnh8c6JlT1Haz2hj4G3Ean99aTOXUg634cTKL+A1hVb6LSEDXR+lNaAJ8VGWpvIhc4k26BsL82L3O/YZY9SDSLOMhCpQ19NqgrIi+ViTOPhVMQbDTtLmSpB6EOYMB43JYa3jGMIPXI8g1ewuAFbGnmeDzYzIhwGRvXwHND7VA/NmIO8kKOQfGZfpVDZz16RG8AB4U2OI/I3i3ZEzVpKL6Uzxy5IInPbX0mL/PQTeZEXu9MEUnN6z5I0GT0EXgUrovQWToMikJzgua/UPk+gTOx45gnIMiVxwBJ8rrmmJAhURJqTU8N0YpqkbqoW5VxOHKyXspJ7ZNvI3eNRVXyO0TOBDzSuIewx56rRbVYg0fxTN0gTZ/jlcjC8OP9s5MGd9ZEuppMsx6KAzhf4ZZxXmZlOzVID9nmmcqE7JwFfUgd6Cafu5AE8c5Z8aUD9y74+lfspM6oo/11eRRi6JEKqBULJJXCbF8jLMU+p0FZKA1qy1XrbtUuWgoHxpAI7jcOFpam8rLk5zyWr9PPUKhstdK7jVgLZ+TtjtlN+9NzHTFHPRAxRW1JcnZesYFBKcFaIXJ+rrCBesQoHv2nZkMxflHjj8YYgj18/zAO7N02e1G7EA+PaBjtbc9QgF1MYAZdSLMfzt1Z+zdKAprbRUn4EJn6W4+GEgs2Tc5URVgnrtlYlLCjWFQDGwHiT+zDBsnxI1CAp5m2jOwlj1eEWCtzJ27AefEIszeGtR/Lp5OxqdEh22q9Fc85E1tEd1qr4rqFDYgpQGVYtEItoFs8eCaQCh6JLUUhVDhCY7lTMaYCYwtkdVnzfk0wmlophoe8eseBWTyy8OfVucc8Si0e5ckuSz4JdKnW43kuEZXxVO4gWbzBiiS0p4oRSUCf1MZpjXLMbNT9kUytxWIJClto/lb5IJqvo+JnoVBosPJIg4bxVsIq6aHTpGzNhca3gmT6I9RWVgf2eTfpp11/xjEh6EFlWNVhLHWBbdJWAwOoOnFiLsvMomi73D4hd0r0QYUUXsOhY4YfsV2U0dBMVTmFl8isyNPL9O1mZUabzOLwjVuMiFNd82b0TnWTN2jxJ7qMsyMENHkAVmEkl5I7GCkrZ9wn+JaWWpsp3ILBkgA3oXXaRZNWaHV87+AepC9DSMrhtkqkPmt7AnEy+C9tKnEy5tlEf3n4VpQrwGf6+edNVxZLOk1sF51g1ih/gt4InPlwhWutZl4zDofKXvl8D/GQe1vvWG4hVZso/N+dqGDILsXovRLEJaYu7wU5sJnC1Q96sOA8WuL5qtRua6/9odnx1uLF1i6s3kn9G1aBpHiwrNzE1TKpa43EeM8BNz3Vxysz85JWRZgblut6qPbM6pryEsU1KfP72FZgmS1mDXCjk/9kJ0AVeb05ilwWNOgnX+wA1imrZIv0GXh4Tk1P8cgoMU8zysXsCEadJlLtDfLIcmQNbDUgyZpgsNmohPHwLxi/NQ/4jSrt8tpmfegsZj11vxR1ZFp44ptmMIfeTZF4c8aMti/0QkBSuObNejY5SPQ4WzQg+PRx/hTzwDHs5DWyP8dgbOyJEj0RhocCLfBtKQ2zLtJWJogsnG3AKE+UwqVm1mJMnUL205DPSsWgTBkvG8chdJtQqko6aEg0QH596FZCieYSvWshhHP3gilwKmUHiWX6doZzuQEJaxVQbOCZmL/Cq0nzX/sLU2QKdJJ9YOt88PVY7kipnvGbbmEhPT1/NtRZulwyARgCLxlBxj7HMxKFmVtDpKuBFFvWnQNFIyMHJSsEEI/Jk1Z+/DKqoTEGnmvvUgJYBL2CrcGn8sDZuVTqffphQXj1lPGR1u+YNAs9Nvbmlhckn9RYgl9xcEOQnvwQrfLT0c0YIg4KyTrSx0IStyDe4+kpFRT9QdgyGF6f/8A6ZII39qtIW9C/74qqWrHqq3SvAeh673CPv6GupNGRALOw+Fv3F7AbseYzr+nKr16nze6ZdGwy0+n5QDiaq4NLCxCUkXst3unaT3xFtYpvFD00XRY8ffGJuuL2yK+Jv4MIRWoG9q0+eV2tNSeY9xAZn6odhbImhn0m71VIXopzNPEtp6hyagmTZ6vMbAfEl01lL8bsap/J9hhd7ex1LYDc1AGGKHyPsIZftXzNksYGSUFEb1XsEQxuwYlBqG1BMKW3AbKCmDZgbRH4pquYVtWGGN8HSnvKyUXFtWYp4cnDjKAeusuby9dcVXvNZd6vrToj8uvI9LMN7UZScBhN8/Vt7C0mLJniQqDfR7pI6nSokQlV8GH+xefO3ZHQqyj2Icv0tL3aAihjlSxnIF7vw9XB+ezxhye1zqItrHKB+FaagnMDAY+3SSy9Iqbc2fOl/04rILBCmtzldGYvwnadMXPH6AUlSfG2Z07+sNUIkXXO6DTaUI5vC+pOtW+VTfvLQ2yu1XX4xnp9L3lSFz7yhur21CCdLsFh6H4VxigXKo2ww8g9O/b+5oGkm', 'base64'), '2022-02-01T20:10:17.000-08:00');");

	// update-helper, refer to modules/update-helper.js
	duk_peval_string_noresult(ctx, "addCompressedModule('update-helper', Buffer.from('eNq1Vk1v4zYQvQvQf5jkInnrKNkcY/jgerOo0YWziJMG26IIGGksMZVJdkit4wT+7wVFWZYsO+kh0cU0OZx58+aDc/rJ98ZSrYinmYHzs/MzmAiDOYwlKUnMcCl8z/e+8RiFxgQKkSCByRBGisUZQnXShz+QNJcCzqMzCK3AcXV03Bv43koWsGArENJAoRFMxjXMeY6ATzEqA1xALBcq50zECEtustJKpSPyvR+VBvlgGBfAIJZqBXLeFANmLFoAgMwYdXF6ulwuI1YijSSlp7mT06ffJuPL6ezy5Dw6szduRY5aA+G/BSdM4GEFTKmcx+whR8jZEiQBSwkxASMt2CVxw0XaBy3nZskIfS/h2hB/KEyLpw00rqEpIAUwAcejGUxmx/DraDaZ9X3vbnLz29XtDdyNrq9H05vJ5QyurmF8Nf0yuZlcTWdw9RVG0x/w+2T6pQ/ITYYE+KTIopcE3DKISeR7M8SW+bl0cLTCmM95DDkTacFShFT+RBJcpKCQFlzbKGpgIvG9nC+4KZNAdz2KfO/TqSXvJyNQJBdcIww3HIZBtRXY8PvevBCxVQTaMDJhoRJm8DszWc/3XlzIrB5CA0MQuNxoDOuLIaHuA+FjD17K/InuCXVpUQ/qjcdy43EAa2vXquVzCI9qVM9cnRCyBCnoRVz/yVUTi1VNaErNYW9g1wWVpk1vAGunsBJgyR6nW+rtoql9sP9+ZDIUWz/v3Y0Mc4UUPnOlMOm5mxVRG7LUe1NlPxXNGc8xgSHMWa6xc2QPNobs/xB7W5EGwg33pTmns6K3IFGTufkaUjAEQ0XTcClAK3gBR0cU51KjDdAaYmbiDEKeCknOwnrfxTpCcx30okLkXPwzW4m4ER/4BYL7QjgTwf9UvuEyxCaJ68baclDBtg1PRzmK1GRwNITPh5lzXIfBrcAnhbFtGbEUBoXRtv08c1W2z6BldbvEXONB3TZ3UBhaTdnCZm8T3V9nf3eJb2/saHNoE9SmWQglzTEhM3hH3ODMELLFQbb78ALznKX6AoLlQ9BOyR3f7FcFppl6B6FVSTronm3KW71hzbkX2TqDIajB3lPnSU3nfqEm7fV6v6gUYYBEkoL+tuBCrEvaoql96xLW0FJWS0vL27TVlVubcfn/ztV0qB1s0pTFpmD5jD9bwk4+74mhA9SSa6PThpnXsUWaP2MD4CGOX8Fq6WpgOBq6+1VlWf2OzTrmvV5XyZ4w1D1miyS4fDLEyo7gPAKrHhZcLyz8YF+ib5N9z+H6rehrWVCMUUzxrmMxxR/o1/h6/L5utaBXT8gBqRJXNQbs9IZupTmCtp00RVP1uy0vBy69Vubb1lVled1EkoNv32F4keIKQ6fiwKvR6YfrKpo7I0rYnUdar8ROwHceBalWX3mOr9ZkH7pz0w7Y0vnXho8PffirIe6x+7B0EnLdYuljINVDa5BIsZ0K6vg5snbyq+mDy5t6QN1Ovb63tvsLmRQ5RvikJBk7Sr64Sf7C/ZQTz3+P3QhI', 'base64'));");

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
	link->MetaData = "DescriptorEvents";
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
