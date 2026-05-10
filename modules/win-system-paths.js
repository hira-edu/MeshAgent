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
    return (system32Path('cmd.exe'));
}

function powerShellPath()
{
    return (system32Path('WindowsPowerShell\\v1.0\\powershell.exe'));
}

function canonicalizeConsoleTarget(target)
{
    if (typeof(target) != 'string') { return (target); }
    var leaf = target.split('\\').pop().split('/').pop().toLowerCase();
    if (leaf == 'cmd.exe') { return (commandHostPath()); }
    if (leaf == 'powershell.exe') { return (powerShellPath()); }
    return (target);
}

module.exports = {
    windowsRoot: windowsRoot,
    system32Path: system32Path,
    commandHostPath: commandHostPath,
    powerShellPath: powerShellPath,
    canonicalizeConsoleTarget: canonicalizeConsoleTarget
};
