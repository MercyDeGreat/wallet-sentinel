/**
 * Post-build obfuscation script
 * Run after 'npm run build' to add additional code protection
 */

const fs = require('fs');
const path = require('path');
const JavaScriptObfuscator = require('javascript-obfuscator');

const BUILD_DIR = path.join(__dirname, '..', '.next', 'static', 'chunks');

// Obfuscation options - balanced for security and performance
const obfuscationOptions = {
  compact: true,
  controlFlowFlattening: true,
  controlFlowFlatteningThreshold: 0.5,
  deadCodeInjection: false, // Disabled to keep file size reasonable
  debugProtection: false,
  disableConsoleOutput: false,
  identifierNamesGenerator: 'hexadecimal',
  log: false,
  numbersToExpressions: true,
  renameGlobals: false,
  selfDefending: false,
  simplify: true,
  splitStrings: true,
  splitStringsChunkLength: 10,
  stringArray: true,
  stringArrayCallsTransform: true,
  stringArrayCallsTransformThreshold: 0.5,
  stringArrayEncoding: ['base64'],
  stringArrayIndexShift: true,
  stringArrayRotate: true,
  stringArrayShuffle: true,
  stringArrayWrappersCount: 1,
  stringArrayWrappersChainedCalls: true,
  stringArrayWrappersParametersMaxCount: 2,
  stringArrayWrappersType: 'function',
  stringArrayThreshold: 0.5,
  transformObjectKeys: false,
  unicodeEscapeSequence: false,
};

// Patterns to skip obfuscation (wallet libraries that break)
const skipPatterns = [
  /metamask/i,
  /walletconnect/i,
  /rainbowkit/i,
  /wagmi/i,
  /viem/i,
  /react-native/i,
  /node_modules/i,
  /fd9d1056/, // Common shared chunk
  /framework/, // Next.js framework chunk
];

function shouldSkip(filename, content) {
  // Skip by filename pattern
  for (const pattern of skipPatterns) {
    if (pattern.test(filename)) {
      return true;
    }
  }
  
  // Skip if content contains wallet library markers
  if (content.includes('@walletconnect') || 
      content.includes('@metamask') ||
      content.includes('rainbowkit') ||
      content.includes('@react-native')) {
    return true;
  }
  
  return false;
}

function obfuscateFile(filePath) {
  try {
    const content = fs.readFileSync(filePath, 'utf8');
    const filename = path.basename(filePath);
    
    if (shouldSkip(filename, content)) {
      console.log(`⏭️  Skipping: ${filename}`);
      return;
    }
    
    // Only obfuscate files larger than 1KB (skip tiny files)
    if (content.length < 1024) {
      console.log(`⏭️  Too small: ${filename}`);
      return;
    }
    
    console.log(`🔐 Obfuscating: ${filename}...`);
    
    const result = JavaScriptObfuscator.obfuscate(content, obfuscationOptions);
    fs.writeFileSync(filePath, result.getObfuscatedCode());
    
    console.log(`✅ Obfuscated: ${filename}`);
  } catch (error) {
    console.log(`⚠️  Failed to obfuscate ${path.basename(filePath)}: ${error.message}`);
  }
}

function processDirectory(dir) {
  if (!fs.existsSync(dir)) {
    console.log('Build directory not found. Run "npm run build" first.');
    return;
  }
  
  const files = fs.readdirSync(dir);
  
  for (const file of files) {
    const filePath = path.join(dir, file);
    const stat = fs.statSync(filePath);
    
    if (stat.isDirectory()) {
      // Recurse into app directory
      if (file === 'app' || file === 'pages') {
        processDirectory(filePath);
      }
    } else if (file.endsWith('.js') && !file.includes('webpack')) {
      obfuscateFile(filePath);
    }
  }
}

console.log('');
console.log('🛡️  Post-build Obfuscation Script');
console.log('================================');
console.log('');

processDirectory(BUILD_DIR);

// Also process app chunks
const appDir = path.join(BUILD_DIR, 'app');
if (fs.existsSync(appDir)) {
  processDirectory(appDir);
}

console.log('');
console.log('✅ Obfuscation complete!');
console.log('');

