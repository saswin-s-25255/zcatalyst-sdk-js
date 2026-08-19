/**
 * Jest Configuration for @zcatalyst/auth package
 */

const base = require('../../config/jest.config.base.browser');

module.exports = {
  ...base,
  displayName: '@zcatalyst/auth',
  rootDir: '.',
  setupFilesAfterEnv: ['<rootDir>/tests/setup.ts'],
  transform: {
    '^.+\\.(ts|tsx)$': ['ts-jest', {
      isolatedModules: true,
      diagnostics: false,
      tsconfig: {
        esModuleInterop: true,
        allowSyntheticDefaultImports: true,
        jsx: 'react'
      }
    }]
  },
  moduleNameMapper: {
    "^@zcatalyst/utils$": "<rootDir>/../../packages/utils/src",
    "^@zcatalyst/auth-admin$": "<rootDir>/../../packages/auth-admin/src",
    "^@zcatalyst/auth-client$": "<rootDir>/../../packages/auth-client/src",
    "^@zcatalyst/transport$": "<rootDir>/../../packages/transport/src/__mocks__"
  }
};
