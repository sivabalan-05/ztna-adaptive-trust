import { useCallback, useEffect, useState } from "react";

export type Theme = "dark" | "light";

/** localStorage key. index.html reads the same key before first paint. */
const STORAGE_KEY = "ztna-theme";
const CHANGE_EVENT = "ztna-theme-change";
const BROWSER_CHROME: Record<Theme, string> = { dark: "#070a11", light: "#f3f5f9" };

/** Dark is the default; only an explicit "light" choice switches it. */
function readStored(): Theme {
  try {
    return localStorage.getItem(STORAGE_KEY) === "light" ? "light" : "dark";
  } catch {
    return "dark";
  }
}

function currentTheme(): Theme {
  return document.documentElement.dataset.theme === "light" ? "light" : readStored();
}

function applyTheme(theme: Theme) {
  const root = document.documentElement;
  const reduceMotion = window.matchMedia("(prefers-reduced-motion: reduce)").matches;
  if (!reduceMotion) {
    // Fade colours across the switch instead of snapping.
    root.classList.add("theme-switching");
    window.setTimeout(() => root.classList.remove("theme-switching"), 350);
  }
  root.dataset.theme = theme;
  document
    .querySelector('meta[name="theme-color"]')
    ?.setAttribute("content", BROWSER_CHROME[theme]);
  try {
    localStorage.setItem(STORAGE_KEY, theme);
  } catch {
    // Storage can be blocked (private windows); the choice then lasts for this visit only.
  }
  window.dispatchEvent(new Event(CHANGE_EVENT));
}

/** The active theme and a function to flip it. Every toggle on screen stays in sync. */
export function useTheme() {
  const [theme, setTheme] = useState<Theme>(currentTheme);

  useEffect(() => {
    const sync = () => setTheme(currentTheme());
    window.addEventListener(CHANGE_EVENT, sync);
    return () => window.removeEventListener(CHANGE_EVENT, sync);
  }, []);

  const toggle = useCallback(() => {
    applyTheme(currentTheme() === "dark" ? "light" : "dark");
  }, []);

  return { theme, toggle };
}
