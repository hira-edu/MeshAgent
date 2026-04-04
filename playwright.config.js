const path = require('path');

module.exports = {
    testDir: path.join(__dirname, 'test', 'playwright'),
    timeout: 60000,
    retries: 0,
    use: {
        browserName: 'chromium',
        headless: true,
        viewport: { width: 1440, height: 1080 },
        screenshot: 'only-on-failure',
        trace: 'retain-on-failure'
    },
    outputDir: process.env.UMH_PLAYWRIGHT_OUTPUT_DIR || path.join(__dirname, 'test', 'playwright', 'artifacts'),
    reporter: [
        ['list'],
        ['json', { outputFile: process.env.UMH_PLAYWRIGHT_JSON || path.join(__dirname, 'test', 'playwright', 'artifacts', 'playwright-results.json') }]
    ]
};
