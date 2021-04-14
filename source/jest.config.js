module.exports = {
  roots: ['<rootDir>/test','<rootDir>/playbooks/CIS/test','<rootDir>/playbooks/AFSBP/test'],
  testMatch: ['**/*.test.ts'],
  transform: {
    '^.+\\.tsx?$': 'ts-jest'
  }
};
