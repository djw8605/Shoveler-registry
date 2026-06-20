/** @type {import('tailwindcss').Config} */
module.exports = {
  // Scan templates so unused utility classes are purged from the build.
  content: ["./portal/templates/**/*.html"],
  theme: {
    extend: {
      fontFamily: {
        sans: [
          "system-ui",
          "-apple-system",
          "Segoe UI",
          "Roboto",
          "Helvetica Neue",
          "Arial",
          "sans-serif",
        ],
        mono: ["ui-monospace", "SFMono-Regular", "Menlo", "Consolas", "monospace"],
      },
    },
  },
  plugins: [require("@tailwindcss/forms")],
};
