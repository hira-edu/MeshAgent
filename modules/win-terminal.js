/*
Copyright 2018-2022 Intel Corporation

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

function disabledWindowsTerminal() {
    this._ObjectID = 'windows_terminal';
    this.supported = false;
}

disabledWindowsTerminal.prototype._fail = function _fail() {
    throw ('Windows terminal support is disabled until an approved MeshConsoleBridgeW rundll32 contract exists.');
};

disabledWindowsTerminal.prototype.PowerShellCapable = function PowerShellCapable() {
    return (false);
};

disabledWindowsTerminal.prototype.ResolveOfficialConsoleTarget = function ResolveOfficialConsoleTarget(target) {
    return (target);
};

disabledWindowsTerminal.prototype.StartEx = function StartEx() {
    return (this._fail());
};

disabledWindowsTerminal.prototype.Start = function Start() {
    return (this._fail());
};

disabledWindowsTerminal.prototype.StartPowerShell = function StartPowerShell() {
    return (this._fail());
};

module.exports = new disabledWindowsTerminal();
