import tsParser from "@typescript-eslint/parser";
import tsPlugin from "@typescript-eslint/eslint-plugin";

export default [
  {
    ignores: ["node_modules/**", "dist/**", "coverage/**", "test-vectors/**"],
  },
  {
    files: ["src/**/*.ts", "scripts/**/*.ts"],
    languageOptions: {
      parser: tsParser,
      parserOptions: { ecmaVersion: 2023, sourceType: "module" },
    },
    plugins: { "@typescript-eslint": tsPlugin },
    rules: {
      "no-undef": "off",
      "no-unused-vars": "off",
      "@typescript-eslint/no-unused-vars": [
        "error",
        { argsIgnorePattern: "^_", varsIgnorePattern: "^_" },
      ],
      "no-implicit-coercion": ["error", { string: true, number: true }],
      "no-restricted-syntax": [
        "error",
        {
          selector:
            "IfStatement > MemberExpression[property.name=/^(token|key|hint|note|did|id|from|to|hash|signature|nonce|timestamp|expiresAt|validFrom|validUntil|revokedAt)$/]",
          message:
            "Truthy check on a string-shaped field can be bypassed by empty string. Use `x.field !== undefined` plus explicit length check, OR add eslint-disable-next-line with reason.",
        },
      ],
      "no-misleading-character-class": "error",
      "no-empty-pattern": "error",
    },
  },
  {
    files: ["test/**/*.ts"],
    languageOptions: {
      parser: tsParser,
      parserOptions: { ecmaVersion: 2023, sourceType: "module" },
    },
    plugins: { "@typescript-eslint": tsPlugin },
    rules: {
      "no-undef": "off",
      "no-unused-vars": "off",
      "@typescript-eslint/no-unused-vars": "off",
      "no-misleading-character-class": "error",
      "no-empty-pattern": "error",
    },
  },
];
