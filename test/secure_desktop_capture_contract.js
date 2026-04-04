const fs = require('fs');
const path = require('path');

function assert(condition, message) {
    if (!condition) {
        throw new Error(message);
    }
}

function main() {
    const kvmPath = path.resolve('meshcore', 'KVM', 'Windows', 'kvm.c');
    const inputPath = path.resolve('meshcore', 'KVM', 'Windows', 'input.c');
    const inputHeaderPath = path.resolve('meshcore', 'KVM', 'Windows', 'input.h');
    const kvmSource = fs.readFileSync(kvmPath, 'utf8');
    const inputSource = fs.readFileSync(inputPath, 'utf8');
    const inputHeader = fs.readFileSync(inputHeaderPath, 'utf8');

    const report = {
        kvmPath,
        inputPath,
        inputHeaderPath,
        checks: {
            exposesDesktopSwitchConsumer: inputHeader.includes('int KVM_ConsumeDesktopSwitchEvent();'),
            hooksDesktopSwitchEvent: inputSource.includes('EVENT_SYSTEM_DESKTOPSWITCH') && inputSource.includes('DESKTOP_HOOK'),
            tracksDesktopSwitchNotifications: inputSource.includes('KVM_DESKTOP_SWITCH_EVENT') && inputSource.includes('InterlockedExchange(&KVM_DESKTOP_SWITCH_EVENT, 1)'),
            consumesDesktopSwitchNotifications: kvmSource.includes('KVM_ConsumeDesktopSwitchEvent()'),
            explicitlyTargetsWinlogonDesktop: kvmSource.includes('OpenDesktopW(L"Winlogon"'),
            logsDesktopSwitchTransitions: kvmSource.includes('desktop switch old=%s new=%s explicitWinlogon=%d event=%d'),
            refreshesResolutionOnDesktopChange: kvmSource.includes('kvm_server_SetResolution(writeHandler, reserved);') && kvmSource.includes('kvm_send_display_list(writeHandler, reserved);'),
            noLongerShutdownsOnAnyDesktopNameChange: !kvmSource.includes('DESKTOP NAME CHANGE DETECTED, triggering shutdown')
        }
    };

    for (const [name, passed] of Object.entries(report.checks)) {
        assert(passed, `${name} failed`);
    }

    process.stdout.write(JSON.stringify(report, null, 2) + '\n');
}

main();
