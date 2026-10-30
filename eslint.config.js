import tseslint from 'typescript-eslint';


/**
 * Flat config. The rules below are the ones that encode project invariants —
 * generic style is left to the formatter and to review.
 */
export default tseslint.config(
  {
    ignores: [
      '**/dist/**', '**/node_modules/**', '**/coverage/**',
      'apps/web/dist/**', 'scripts/**', 'eslint.config.js',
    ],
  },
  ...tseslint.configs.recommended,
  {
    files: ['**/*.ts', '**/*.tsx'],
    languageOptions: {
      parserOptions: { projectService: false },
    },
    rules: {
      // `any` erases exactly the guarantees this codebase relies on.
      '@typescript-eslint/no-explicit-any': 'warn',
      '@typescript-eslint/no-unused-vars': [
        'error',
        { argsIgnorePattern: '^_', varsIgnorePattern: '^_' },
      ],
      '@typescript-eslint/consistent-type-imports': [
        'error',
        { prefer: 'type-imports', fixStyle: 'inline-type-imports' },
      ],

      'no-restricted-syntax': [
        'error',
        {
          // The entire E2EE model collapses under XSS, so the primary DOM-XSS
          // sink is banned outright rather than reviewed case by case.
          selector: 'JSXAttribute[name.name="dangerouslySetInnerHTML"]',
          message:
            'dangerouslySetInnerHTML is banned: an XSS here would reach the ' +
            'user’s encryption keys. Render text, or sanitize server-side.',
        },
        {
          // JavaScript-evaluation sinks, not query operators.
          selector: "Literal[value=/^\\$(where|function|accumulator)$/]",
          message:
            '$where, $function and $accumulator execute JavaScript in the ' +
            'database. Build the query from literals instead.',
        },
        {
          // Storing a bearer token or key material in web storage would make
          // one XSS a permanent compromise.
          selector:
            'MemberExpression[object.name=/^(localStorage|sessionStorage)$/][property.name="setItem"] ' +
            '> Literal[value=/token|secret|key|password/i]',
          message:
            'Never persist credentials or key material in web storage. Access ' +
            'tokens live in a closure; private keys are non-extractable ' +
            'CryptoKey handles in IndexedDB.',
        },
      ],

      eqeqeq: ['error', 'always', { null: 'ignore' }],
      'no-console': ['warn', { allow: ['warn', 'error'] }],
      'prefer-const': 'error',
      'no-var': 'error',
    },
  },
  {
    // Tests exercise malformed and hostile input on purpose.
    files: ['**/*.test.ts', '**/*.test.tsx', '**/__tests__/**', '**/testing.ts'],
    rules: {
      '@typescript-eslint/no-explicit-any': 'off',
      'no-restricted-syntax': 'off',
    },
  },
);