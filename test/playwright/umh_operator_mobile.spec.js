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

test('mobile surface omits retired hookControl', async ({ page }) => {
    await page.goto(fixtureUrl('mobile'));
    await expect(page.getByTestId('surface-label')).toContainText('mobile');
    await expect(page.getByTestId('mobile-operation-select').locator('option[value="hookControl"]')).toHaveCount(0);
    expect(contract.getOperation('hookControl')).toBeNull();
});

test('mobile surface renders retained control-json output', async ({ page }) => {
    await page.goto(fixtureUrl('mobile'));
    await page.getByTestId('mobile-operation-select').selectOption('safetyState');
    await page.getByTestId('dispatch-plan').click();

    await expect(page.getByTestId('console-command')).toHaveText(contract.buildConsoleCommand('safetyState', {}));
    expect(await readJsonPre(page, 'control-request')).toEqual(contract.buildRawJson('safetyState', {}));
    await page.getByTestId('sample-response').click();
    await page.getByTestId('render-response').click();

    await expect(page.getByTestId('rendered-result')).toContainText('umhctl response');
    await expect(page.getByTestId('rendered-result')).toContainText('"destructive_controls_supported": false');
});
