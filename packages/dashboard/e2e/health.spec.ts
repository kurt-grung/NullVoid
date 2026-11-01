import { test, expect } from '@playwright/test';

test('shows API connected on load', async ({ page }) => {
  await page.goto('/');
  await expect(page.getByRole('link', { name: 'NullVoid' })).toBeVisible();
  await expect(page.getByText('Connected')).toBeVisible({ timeout: 15_000 });
});
