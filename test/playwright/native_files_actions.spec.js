const path = require('path');
const { test, expect } = require('playwright/test');

test('Files buttons send literal native requests and display agent outcomes', async ({ page }) => {
    await page.setContent('<div id="p13rightOfButtons"></div><input type="checkbox" name="fd" value="0" file="3" checked>');
    await page.evaluate(() => {
        window.requests = [];
        window.p13filetree = { dir: [{ n: "O'Brien & Ω 😀.exe" }] };
        window.p13filetreelocation = ['C:', 'owned files'];
        window.filesNode = window.currentNode = { _id: 'owned-node', agent: { id: 4 } };
        window.GetNodeRights = () => 131080;
        window.isWindowsNode = () => true;
        window.files = { State: 3, m: { ProcessData: () => { } }, sendText: (request) => window.requests.push(request) };
        window.meshserver = { send: () => { throw new Error('Files execution must not use runcommands'); } };
    });
    page.on('dialog', dialog => dialog.accept());
    await page.addScriptTag({ path: path.resolve(__dirname, '../../../MeshCentral/public/scripts/custom.js') });
    await page.locator('#mc-files-run-user').click();
    await page.locator('#mc-files-run-privileged').click();
    const requests = await page.evaluate(() => window.requests);
    expect(requests).toHaveLength(2);
    expect(requests[0]).toMatchObject({ action: 'execute', path: "C:\\owned files\\O'Brien & Ω 😀.exe", privileged: false });
    expect(requests[1].privileged).toBe(true);
    expect(requests[0].reqid).not.toBe(requests[1].reqid);
    await page.evaluate(() => window.files.m.ProcessData(JSON.stringify({ action: 'fileaction', reqid: window.requests[1].reqid, operation: 'execute', ok: false, error: 740 })));
    await expect(page.locator('#mc-files-exec-status')).toHaveText('Native execute failed: 740');
    await page.evaluate(() => window.files.m.ProcessData(JSON.stringify({ action: 'fileaction', operation: 'execute', ok: true, pid: 1234 })));
    await expect(page.locator('#mc-files-exec-status')).toContainText('PID 1234');
    await page.evaluate(() => { window.files.State = 0; });
    await expect(page.locator('#mc-files-run-user')).toBeDisabled();
    await page.evaluate(() => { window.files.State = 3; window.GetNodeRights = () => 8; });
    await expect(page.locator('#mc-files-run-user')).toBeHidden();
});
