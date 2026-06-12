import { test, expect } from "@playwright/test";

test("dashboard shell renders navigation", async ({ page }) => {
  await page.goto("/");
  await expect(page.getByRole("heading", { name: "SSHMap Dashboard" })).toBeVisible();
  await expect(page.getByRole("link", { name: "Dashboard" })).toBeVisible();
  await expect(page.getByRole("link", { name: "Graph" })).toBeVisible();
  await expect(page.getByRole("link", { name: "Tools" })).toBeVisible();
});
