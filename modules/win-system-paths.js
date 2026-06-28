/*
Copyright 2026

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

function windowsRoot()
{
    var root = process.env['SystemRoot'];
    if (root == null || root == '')
    {
        throw new Error('SystemRoot is required for Windows system executable resolution.');
    }
    return (root.replace(/[\\\/]+$/, ''));
}

function system32Path(relativePath)
{
    return (windowsRoot() + '\\System32\\' + relativePath);
}

function commandHostPath()
{
    throw new Error('Windows command-host execution is disabled outside approved rundll32 contract exports.');
}

function powerShellPath()
{
    throw new Error('Windows PowerShell execution is disabled outside approved rundll32 contract exports.');
}

function canonicalizeConsoleTarget(target)
{
    if (typeof(target) != 'string') { return (target); }
    return (target);
}

module.exports = {
    windowsRoot: windowsRoot,
    system32Path: system32Path,
    commandHostPath: commandHostPath,
    powerShellPath: powerShellPath,
    canonicalizeConsoleTarget: canonicalizeConsoleTarget
};
