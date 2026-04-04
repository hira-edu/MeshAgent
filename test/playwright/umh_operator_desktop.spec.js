const path = require('path');
const { pathToFileURL } = require('url');
const { test, expect } = require('playwright/test');
const contract = require('../lib/umh_operator_contract');

function fixtureUrl(surface) {
    const filePath = path.resolve(__dirname, 'fixtures', 'umh_operator_panel.html');
    return `${pathToFileURL(filePath).toString()}?surface=${surface}`;
}

async function readJsonPre(page, testId) {
    const text = await page.getByTestId(testId).innerText();
    return JSON.parse(text);
}

test('desktop surface builds canonical injectTargetSet dispatch', async ({ page }) => {
    const input = {
        pids: '9101,9102',
        runId: 'run-desktop-9100',
        targetTag: 'screen-midterm',
        methodKey: 'remote-thread'
    };

    await page.goto(fixtureUrl('desktop'));
    await expect(page.getByTestId('surface-label')).toContainText('desktop');

    await page.getByTestId('desktop-op-injectTargetSet').click();
    await page.getByTestId('field-pids').fill(input.pids);
    await page.getByTestId('field-runId').fill(input.runId);
    await page.getByTestId('field-targetTag').fill(input.targetTag);
    await page.getByTestId('field-methodKey').fill(input.methodKey);
    await page.getByTestId('dispatch-plan').click();

    await expect(page.getByTestId('console-command')).toHaveText(contract.buildConsoleCommand('injectTargetSet', input));
    await expect(page.getByTestId('control-request')).toContainText('"op": "injectTargetSet"');
    expect(await readJsonPre(page, 'control-request')).toEqual(contract.buildRawJson('injectTargetSet', input));
    expect(await readJsonPre(page, 'dispatch-record')).toMatchObject({
        surface: 'desktop',
        operationId: 'injectTargetSet',
        consoleCommand: contract.buildConsoleCommand('injectTargetSet', input),
        controlRequest: contract.buildRawJson('injectTargetSet', input)
    });
});

test('desktop surface renders retained uiSnapshot output', async ({ page }) => {
    await page.goto(fixtureUrl('desktop'));
    await page.getByTestId('desktop-op-uiSnapshot').click();
    await page.getByTestId('field-pid').fill('4242');
    await page.getByTestId('sample-response').click();
    await page.getByTestId('render-response').click();

    await expect(page.getByTestId('rendered-result')).toContainText('umhctl uiSnapshot');
    await expect(page.getByTestId('rendered-result')).toContainText('"requested_pid": 4242');
    await expect(page.getByTestId('rendered-result')).toContainText('"flow_contract"');
});
