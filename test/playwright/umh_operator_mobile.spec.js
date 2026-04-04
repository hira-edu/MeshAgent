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

test('mobile surface preserves ipcBypass semantics', async ({ page }) => {
    const input = { action: 'enable', target: 'adapter-mobile', domain: 'screen' };

    await page.goto(fixtureUrl('mobile'));
    await expect(page.getByTestId('surface-label')).toContainText('mobile');

    await page.getByTestId('mobile-operation-select').selectOption('ipcBypass');
    await page.getByTestId('field-action').selectOption(input.action);
    await page.getByTestId('field-target').fill(input.target);
    await page.getByTestId('field-domain').selectOption(input.domain);
    await page.getByTestId('dispatch-plan').click();

    await expect(page.getByTestId('console-command')).toHaveText(contract.buildConsoleCommand('ipcBypass', input));
    expect(await readJsonPre(page, 'control-request')).toEqual(contract.buildRawJson('ipcBypass', input));
    expect(await readJsonPre(page, 'dispatch-record')).toMatchObject({
        surface: 'mobile',
        operationId: 'ipcBypass',
        consoleCommand: contract.buildConsoleCommand('ipcBypass', input),
        controlRequest: contract.buildRawJson('ipcBypass', input)
    });
});

test('mobile surface renders retained control-json output', async ({ page }) => {
    await page.goto(fixtureUrl('mobile'));
    await page.getByTestId('mobile-operation-select').selectOption('examsoftBypass');
    await page.getByTestId('field-action').selectOption('secure-enter');
    await page.getByTestId('sample-response').click();
    await page.getByTestId('render-response').click();

    await expect(page.getByTestId('rendered-result')).toContainText('umhctl response');
    await expect(page.getByTestId('rendered-result')).toContainText('"action": "secure-enter"');
    await expect(page.getByTestId('rendered-result')).toContainText('"state": "entered"');
});
