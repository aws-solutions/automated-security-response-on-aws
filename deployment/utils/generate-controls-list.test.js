// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

jest.mock('fs', () => ({
  ...jest.requireActual('fs'),
  writeFileSync: jest.fn(),
  mkdirSync: jest.fn(),
  existsSync: jest.fn()
}));

jest.mock('path', () => ({
  ...jest.requireActual('path'),
  join: jest.fn(),
  dirname: jest.fn()
}));

jest.mock('process', () => ({
  ...jest.requireActual('process'),
  exit: jest.fn(),
}));

const fs = require('fs');
const path = require('path');

const actualFs = jest.requireActual('fs');
const actualPath = jest.requireActual('path');

// Get the actual file content
const scRemediationsPath = actualPath.join(__dirname, '../../source/playbooks/SC/lib/sc_remediations.ts');
const actualFileContent = actualFs.readFileSync(scRemediationsPath, 'utf8');

// Count the actual number of controls in the file
const controlRegex = /\{\s*control:\s*'([^']+)/g;
let match;
const expectedControls = [];
while ((match = controlRegex.exec(actualFileContent)) !== null) {
  expectedControls.push(match[1]);
}

describe('generate-controls-list', () => {
  const originalConsoleError = console.error;
  const originalConsoleLog = console.log;
  

  
  beforeEach(() => {
    jest.resetAllMocks();
    
    console.error = jest.fn();
    console.log = jest.fn();
    
    path.join.mockImplementation((dir, relativePath) => {
      if (relativePath && relativePath.includes('sc_remediations.ts')) {
        return scRemediationsPath;
      }
      return '/mock/path/output.json';
    });
    
    path.dirname.mockReturnValue('/mock/path');
    
    fs.existsSync.mockReturnValue(true);
    fs.writeFileSync = jest.fn();
    fs.mkdirSync = jest.fn();
  });
  
  afterEach(() => {
    console.error = originalConsoleError;
    console.log = originalConsoleLog;
    
    jest.resetModules();
  });
  
  test('should extract controls and write to output file', () => {
    const originalArgv = process.argv;
    process.argv = ['node', 'generate-controls-list.js', 'v1.0.0'];
    
    require('./generate-controls-list');

    expect(fs.writeFileSync).toHaveBeenCalled();
    
    const writeCall = fs.writeFileSync.mock.calls[0];
    expect(writeCall[0]).toBe('/mock/path/output.json');
    
    const writtenData = JSON.parse(writeCall[1]);
    expect(writtenData.solutionVersion).toBe('v1.0.0');
    expect(Array.isArray(writtenData.supportedControls)).toBe(true);
    expect(writtenData.supportedControls.length).toBe(expectedControls.length);
    expect(writtenData.supportedControls.sort()).toEqual(expectedControls.sort());
    
    expect(console.log).toHaveBeenCalledWith(
      expect.stringContaining(`Generated controls list with ${writtenData.supportedControls.length} controls at`)
    );
    
    process.argv = originalArgv;
  });
});