import { render, screen } from "@testing-library/react";
import { createMemoryRouter, RouterProvider } from "react-router-dom";
import { describe, expect, it } from "vitest";
import { Layout } from "./components/Layout";

describe("Layout", () => {
  it("renders dashboard navigation shell", () => {
    const router = createMemoryRouter(
      [
        {
          path: "/",
          element: <Layout summaryLine="1 hosts" error={null} />,
          children: [{ index: true, element: <p>Home</p> }],
        },
      ],
      { initialEntries: ["/"] },
    );

    render(<RouterProvider router={router} />);

    expect(screen.getByRole("heading", { name: "SSHMap Dashboard" })).toBeTruthy();
    expect(screen.getByRole("link", { name: "Dashboard" })).toBeTruthy();
    expect(screen.getByRole("link", { name: "Graph" })).toBeTruthy();
    expect(screen.getByRole("link", { name: "Tools" })).toBeTruthy();
  });
});
