import { test, expect } from '@playwright/test';

test('trigger scan and view results', async ({ page }) => {
  await page.goto('/scans');
  await expect(page.getByRole('heading', { name: 'Scans', exact: true })).toBeVisible();

  await page.getByPlaceholder('Target path (e.g. . or ./packages/api)').fill('ts/test/fixtures');
  await page.getByRole('button', { name: 'Start Scan' }).click();

  await expect(page.getByRole('link', { name: /completed/i }).first()).toBeVisible({
    timeout: 120_000,
  });

  await page.getByRole('link', { name: /completed/i }).first().click();
  await expect(page.getByRole('heading', { name: /Scan: ts\/test\/fixtures/ })).toBeVisible();
  await expect(page.getByRole('heading', { name: /Threats \(\d+\)/ })).toBeVisible();
});
