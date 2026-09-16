"use strict";

// Extracts a dominant-color palette from an image (via ImageMagick) and
// turns it into a full Omarchy colors.toml — the "pull the colors out of a
// picture and build a theme from it" feature. No public URL required: this
// operates on a local file path already saved on the machine (same
// allowed-roots sandbox as every other file-path tool), then the resulting
// background image is copied (not re-downloaded) straight into the new
// theme's backgrounds/ folder.
//
// Framework-agnostic like notes.js/files.js — `resolveImagePath` and
// `extractImageColors` accept the host's own `resolveInputPath`/`isAllowed`
// filesystem-sandboxing helpers via an opts object instead of assuming any
// particular project's conventions (see tools-agent/lib/paths.js in Lain
// for a reference implementation).

const fs = require("node:fs");
const path = require("node:path");
const { execFileSync } = require("node:child_process");

const HISTOGRAM_LINE_RE = /(\d+):\s*\((\d+),(\d+),(\d+)\)\s*#([0-9A-Fa-f]{6})/g;

// opts: { resolveInputPath, isAllowed } — both required, host-supplied.
function resolveImagePath(inputPath, { resolveInputPath, isAllowed } = {}) {
  if (typeof resolveInputPath !== "function" || typeof isAllowed !== "function") {
    throw new Error(
      "imageColors: resolveImagePath() requires opts.resolveInputPath and opts.isAllowed"
    );
  }
  const resolved = resolveInputPath(inputPath);
  if (!fs.existsSync(resolved)) {
    throw new Error(`File not found: ${inputPath}`);
  }
  if (!isAllowed(resolved)) {
    throw new Error(`Path is outside the allowed roots: ${inputPath}`);
  }
  const stat = fs.statSync(resolved);
  if (!stat.isFile()) {
    throw new Error(`Not a file: ${inputPath}`);
  }
  return resolved;
}

// Returns the dominant colors in an image, sorted by pixel count (most to
// least common). `count` caps how many distinct colors ImageMagick quantizes
// down to before histogramming — 12-16 gives a good spread for theming
// without drowning in near-duplicate shades. opts: { resolveInputPath, isAllowed }.
function extractImageColors(inputPath, { count = 12, resolveInputPath, isAllowed } = {}) {
  const resolved = resolveImagePath(inputPath, { resolveInputPath, isAllowed });
  const n = Math.max(4, Math.min(32, Number(count) || 12));
  let out;
  try {
    out = execFileSync(
      "magick",
      [
        resolved,
        "-background", "white",
        "-alpha", "remove",
        "-resize", "200x200",
        "-colors", String(n),
        "+dither",
        "-depth", "8",
        "-format", "%c",
        "histogram:info:-",
      ],
      { encoding: "utf8", timeout: 15000 }
    );
  } catch (err) {
    throw new Error(
      (err.stderr || "").toString().trim() || "Failed to read image (is it a valid image file? ImageMagick required)."
    );
  }

  const colors = [];
  let m;
  HISTOGRAM_LINE_RE.lastIndex = 0;
  while ((m = HISTOGRAM_LINE_RE.exec(out))) {
    colors.push({
      hex: `#${m[5].toUpperCase()}`,
      r: Number(m[2]),
      g: Number(m[3]),
      b: Number(m[4]),
      count: Number(m[1]),
    });
  }
  colors.sort((a, b) => b.count - a.count);
  return { path: resolved, palette: colors };
}

// --- color-math helpers -----------------------------------------------

function luminance({ r, g, b }) {
  // Perceived brightness (ITU-R BT.601), 0 (black) - 255 (white).
  return 0.299 * r + 0.587 * g + 0.114 * b;
}

// WCAG relative luminance / contrast ratio — used to make sure the 8 named
// colors (and the accent) are actually readable against whichever
// background got picked, not just "close in hue" to a palette color that
// might be nearly as pale/dark as the background itself.
function srgbToLinear(c) {
  const n = c / 255;
  return n <= 0.04045 ? n / 12.92 : Math.pow((n + 0.055) / 1.055, 2.4);
}

function relativeLuminance({ r, g, b }) {
  return 0.2126 * srgbToLinear(r) + 0.7152 * srgbToLinear(g) + 0.0722 * srgbToLinear(b);
}

function contrastRatio(hexA, hexB) {
  const a = relativeLuminance(hexToRgb(hexA)) + 0.05;
  const b = relativeLuminance(hexToRgb(hexB)) + 0.05;
  return a > b ? a / b : b / a;
}

// Nudges a color's HSL lightness away from the background (darker in a
// light-mode theme, lighter in a dark-mode one) until it clears
// `targetRatio` against it, preserving hue/saturation as much as possible.
// Caps out at l=0.08/0.92 so it can't wrap into pure black/white and lose
// the color's identity entirely.
function nudgeForContrast(hex, bgHex, mode, targetRatio) {
  let { h, s } = rgbToHsl(hexToRgb(hex));
  let { l } = rgbToHsl(hexToRgb(hex));
  s = Math.max(s, 0.35);
  let candidate = hex;
  let steps = 0;
  while (contrastRatio(candidate, bgHex) < targetRatio && steps < 20) {
    l = mode === "dark" ? Math.min(0.92, l + 0.04) : Math.max(0.08, l - 0.04);
    candidate = hslToHex(h, s, l);
    steps++;
    if (l <= 0.08 || l >= 0.92) break;
  }
  return candidate;
}

function rgbToHsl({ r, g, b }) {
  const rn = r / 255, gn = g / 255, bn = b / 255;
  const max = Math.max(rn, gn, bn), min = Math.min(rn, gn, bn);
  const l = (max + min) / 2;
  if (max === min) return { h: 0, s: 0, l };
  const d = max - min;
  const s = l > 0.5 ? d / (2 - max - min) : d / (max + min);
  let h;
  switch (max) {
    case rn: h = (gn - bn) / d + (gn < bn ? 6 : 0); break;
    case gn: h = (bn - rn) / d + 2; break;
    default: h = (rn - gn) / d + 4;
  }
  return { h: h * 60, s, l };
}

function hslToHex(h, s, l) {
  h = ((h % 360) + 360) % 360;
  const c = (1 - Math.abs(2 * l - 1)) * s;
  const x = c * (1 - Math.abs(((h / 60) % 2) - 1));
  const m = l - c / 2;
  let r, g, b;
  if (h < 60) [r, g, b] = [c, x, 0];
  else if (h < 120) [r, g, b] = [x, c, 0];
  else if (h < 180) [r, g, b] = [0, c, x];
  else if (h < 240) [r, g, b] = [0, x, c];
  else if (h < 300) [r, g, b] = [x, 0, c];
  else [r, g, b] = [c, 0, x];
  return rgbToHex({ r: (r + m) * 255, g: (g + m) * 255, b: (b + m) * 255 });
}

function hexToRgb(hex) {
  const v = hex.replace("#", "");
  return { r: parseInt(v.slice(0, 2), 16), g: parseInt(v.slice(2, 4), 16), b: parseInt(v.slice(4, 6), 16) };
}

function rgbToHex({ r, g, b }) {
  const c = (n) => Math.max(0, Math.min(255, Math.round(n))).toString(16).padStart(2, "0");
  return `#${c(r)}${c(g)}${c(b)}`.toUpperCase();
}

function mix(hexA, hexB, amount) {
  // amount 0 = all A, 1 = all B
  const a = hexToRgb(hexA), b = hexToRgb(hexB);
  return rgbToHex({
    r: a.r + (b.r - a.r) * amount,
    g: a.g + (b.g - a.g) * amount,
    b: a.b + (b.b - a.b) * amount,
  });
}

function lighten(hex, amount) {
  return mix(hex, "#FFFFFF", amount);
}

function darken(hex, amount) {
  return mix(hex, "#000000", amount);
}

// Hue buckets (in degrees) used to slot palette colors into the 8 named
// ANSI-ish roles Omarchy's colors.toml expects.
const HUE_BUCKETS = [
  { name: "red", hue: 0 },
  { name: "orange", hue: 30 },
  { name: "yellow", hue: 55 },
  { name: "green", hue: 120 },
  { name: "cyan", hue: 185 },
  { name: "blue", hue: 225 },
  { name: "magenta", hue: 295 },
  { name: "brown", hue: 20 },
];

function hueDistance(a, b) {
  const d = Math.abs(a - b) % 360;
  return d > 180 ? 360 - d : d;
}

// Builds a full Omarchy colors.toml color set from an extracted palette.
// Heuristics (not literal — there's no single "correct" answer, this aims
// for something usable and true to the image's actual palette):
//   - mode/background/foreground: the most common color decides the mode
//     (dark image -> dark theme); background = darkest of the top colors in
//     dark mode (lightest in light mode), foreground the opposite extreme.
//   - accent: the most saturated non-background/foreground color among the
//     most common ones (a wallpaper's "signature" color).
//   - red/orange/yellow/green/cyan/blue/magenta/brown: nearest hue match
//     from the palette (falling back to a hue-rotated synthetic color if
//     the image doesn't contain one), each with a lighter "bright_" variant.
function generateThemeColors(palette) {
  if (!palette || palette.length === 0) {
    throw new Error("No colors extracted from image.");
  }
  // Ignore near-grayscale/very rare colors when picking the accent — an
  // almost-black or almost-white "dominant" pixel is usually a border or
  // background wash, not the picture's signature color.
  const withHsl = palette.map((c) => ({ ...c, hsl: rgbToHsl(c) }));
  const top = withHsl.slice(0, Math.min(withHsl.length, 10));

  const avgLuminance =
    palette.reduce((sum, c) => sum + luminance(c) * c.count, 0) /
    palette.reduce((sum, c) => sum + c.count, 0);
  const mode = avgLuminance < 128 ? "dark" : "light";
  const isDark = mode === "dark";

  const sortedByLuminance = [...top].sort((a, b) => luminance(a) - luminance(b));
  const darkest = sortedByLuminance[0];
  const lightest = sortedByLuminance[sortedByLuminance.length - 1];
  const background = mode === "dark" ? darkest : lightest;
  let foregroundHex = (mode === "dark" ? lightest : darkest).hex;
  // The image's own extremes are usually plenty of contrast, but guard
  // against a low-contrast source image (e.g. a flat, evenly-lit photo)
  // leaving body text hard to read against the background.
  foregroundHex = nudgeForContrast(foregroundHex, background.hex, mode, 7);

  const accentCandidates = top
    .filter((c) => c.hex !== background.hex && c.hex !== foregroundHex && c.hsl.s > 0.25)
    .sort((a, b) => b.hsl.s - a.hsl.s || b.count - a.count);
  const accentBase = (accentCandidates[0] || top[Math.floor(top.length / 2)]).hex;
  const accent = nudgeForContrast(accentBase, background.hex, mode, 3);

  const namedColors = {};
  const excluded = new Set([background.hex, foregroundHex]);
  for (const bucket of HUE_BUCKETS) {
    const saturated = withHsl.filter((c) => c.hsl.s > 0.2 && !excluded.has(c.hex));
    const pool = saturated.length ? saturated : withHsl.filter((c) => !excluded.has(c.hex));
    const best = (pool.length ? pool : withHsl).reduce((closest, c) => {
      const dist = hueDistance(c.hsl.h, bucket.hue);
      return !closest || dist < closest.dist ? { c, dist } : closest;
    }, null);
    // Only trust a real palette match if it's reasonably close in hue;
    // otherwise synthesize a color at the target hue, tinted with the
    // theme's own saturation so it stays coherent with the rest.
    const accentHsl = rgbToHsl(hexToRgb(accent));
    const candidate =
      best && best.dist < 35 ? best.c.hex : hslToHex(bucket.hue, Math.max(0.4, accentHsl.s), 0.5);
    // Whatever we picked, make sure it's actually legible as text/an icon
    // color against the chosen background — a pale palette match on a pale
    // background (or vice versa) is exactly what produces a "washed out,
    // low contrast" theme.
    namedColors[bucket.name] = nudgeForContrast(candidate, background.hex, mode, 4.5);
  }

  // "bright_" ANSI variants should read as more emphasized, not less — nudge
  // further in the same safe direction (lighter in dark mode, darker in
  // light mode) rather than always lightening, which would drag a
  // light-mode color like light_yellow right back toward the background.
  const brighten = (hex) => nudgeForContrast(hex, background.hex, mode, 6.5);

  return {
    mode,
    accent,
    selection: isDark ? lighten(background.hex, 0.15) : darken(background.hex, 0.1),
    muted: nudgeForContrast(
      isDark ? lighten(background.hex, 0.25) : darken(background.hex, 0.2),
      background.hex,
      mode,
      3
    ),
    background: background.hex,
    dark_background: darken(background.hex, isDark ? 0.35 : 0.6),
    darker_background: darken(background.hex, isDark ? 0.55 : 0.75),
    lighter_background: lighten(background.hex, isDark ? 0.2 : 0.08),
    foreground: foregroundHex,
    dark_foreground: nudgeForContrast(
      isDark ? darken(foregroundHex, 0.55) : lighten(foregroundHex, 0.3),
      background.hex,
      mode,
      3
    ),
    light_foreground: nudgeForContrast(
      isDark ? darken(foregroundHex, 0.2) : lighten(foregroundHex, 0.1),
      background.hex,
      mode,
      4.5
    ),
    bright_foreground: isDark ? lighten(foregroundHex, 0.1) : "#000000",
    red: namedColors.red,
    yellow: namedColors.yellow,
    orange: namedColors.orange,
    green: namedColors.green,
    cyan: namedColors.cyan,
    blue: namedColors.blue,
    magenta: namedColors.magenta,
    brown: namedColors.brown,
    bright_red: brighten(namedColors.red),
    bright_yellow: brighten(namedColors.yellow),
    bright_green: brighten(namedColors.green),
    bright_cyan: brighten(namedColors.cyan),
    bright_blue: brighten(namedColors.blue),
    bright_magenta: brighten(namedColors.magenta),
  };
}

const TOML_KEY_ORDER = [
  "mode",
  "",
  "accent",
  "selection",
  "muted",
  "",
  "background",
  "dark_background",
  "darker_background",
  "lighter_background",
  "",
  "foreground",
  "dark_foreground",
  "light_foreground",
  "bright_foreground",
  "",
  "red",
  "yellow",
  "orange",
  "green",
  "cyan",
  "blue",
  "magenta",
  "brown",
  "",
  "bright_red",
  "bright_yellow",
  "bright_green",
  "bright_cyan",
  "bright_blue",
  "bright_magenta",
];

function toColorsToml(colors) {
  const lines = TOML_KEY_ORDER.map((key) => {
    if (key === "") return "";
    if (key === "mode") return `mode = "${colors.mode}"`;
    return `${key} = "${colors[key]}"`;
  });
  return lines.join("\n") + "\n";
}

// One-shot: extract a palette from a local image, turn it into a full
// colors.toml, and hand back everything omarchyCreateTheme needs (including
// the resolved local image path to use as the theme's background, so the
// same file the palette came from is reused rather than re-fetched).
// opts: { resolveInputPath, isAllowed } — see extractImageColors.
function themeFromImage(inputPath, { count = 12, resolveInputPath, isAllowed } = {}) {
  const { path: resolved, palette } = extractImageColors(inputPath, {
    count,
    resolveInputPath,
    isAllowed,
  });
  const colors = generateThemeColors(palette);
  const colorsToml = toColorsToml(colors);
  return { imagePath: resolved, palette, colors, colorsToml };
}

module.exports = {
  extractImageColors,
  generateThemeColors,
  toColorsToml,
  themeFromImage,
  resolveImagePath,
};
