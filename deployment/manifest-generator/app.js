// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

'use strict';

const fs = require('fs');
const path = require('path');
const args = require('minimist')(process.argv.slice(2));

// List all files in a directory and subdirectories recursively
let listChildrenRecursively = function(file) {
  if (!fs.statSync(file).isDirectory())
    return [file];

  let children = fs.readdirSync(file);
  return children.flatMap(child => listChildrenRecursively(path.join(file, child)));
};

function validateArgs(argumentList) {
  if (!argumentList.hasOwnProperty('target')) {
    console.log(
      '--target parameter missing. This should be the target directory containing content for the manifest.'
    );
    process.exit(1);
  }

  if (!argumentList.hasOwnProperty('output')) {
    console.log(
      '--ouput parameter missing. This should be the out directory where the manifest file will be generated.'
    );
    process.exit(1);
  }
}

function generateManifestFile(sourceDir) {
  console.log(
    `Generating a manifest file ${args.output} for directory ${sourceDir}`
  );

  const filelist = listChildrenRecursively(sourceDir);

  return {
    files: filelist.map(it => it.replace(`${sourceDir}/`, ''))
  };
}

validateArgs(args);

const webUiDir = args.target;
const _manifest = generateManifestFile(webUiDir);

fs.writeFileSync(args.output, JSON.stringify(_manifest, null, 4));
console.log(`Manifest file ${args.output} generated.`);
