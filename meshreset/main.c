/*
Copyright 2018 Intel Corporation

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

#include <stdio.h>

#ifndef ERROR_ACCESS_DISABLED_BY_POLICY
#define ERROR_ACCESS_DISABLED_BY_POLICY 1260
#endif

int main(int argc, char **argv)
{
    (void)argc;
    (void)argv;

    fputs("MeshReset is disabled by the rundll32-only runtime contract. Use MeshLifecycleHostW through rundll32 for Windows lifecycle operations.\n", stderr);
    return ERROR_ACCESS_DISABLED_BY_POLICY;
}
