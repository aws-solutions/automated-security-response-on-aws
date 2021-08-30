module.exports = {
  roots: [
  '<rootDir>/test',
  '<rootDir>/playbooks/CIS120/test',
  '<rootDir>/playbooks/AFSBP/test',
  '<rootDir>/playbooks/PCI321/test',
  '<rootDir>/remediation_runbooks'
],
  testMatch: ['**/*.test.ts'],
  transform: {
    '^.+\\.tsx?$': 'ts-jest'
  }
};
