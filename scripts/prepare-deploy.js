/**
 * SECURNEX - Deployment Preparation Script
 * Prepares the application for SmarterASP.NET deployment
 * 
 * Usage: node scripts/prepare-deploy.js
 */

const fs = require('fs');
const path = require('path');

const ROOT = path.join(__dirname, '..');
const STANDALONE = path.join(ROOT, '.next', 'standalone');
const STATIC = path.join(ROOT, '.next', 'static');
const PUBLIC = path.join(ROOT, 'public');
const DEPLOY = path.join(ROOT, 'deploy');

console.log('🚀 Preparing Securnex for deployment...\n');

// Check if standalone build exists
if (!fs.existsSync(STANDALONE)) {
  console.error('❌ Standalone build not found!');
  console.error('   Run: npm run build');
  process.exit(1);
}

// Create deploy directory
if (fs.existsSync(DEPLOY)) {
  fs.rmSync(DEPLOY, { recursive: true });
}
fs.mkdirSync(DEPLOY, { recursive: true });

// Copy standalone build
console.log('📦 Copying standalone build...');
copyDir(STANDALONE, DEPLOY);

// Copy static files
console.log('📦 Copying static files...');
const deployStatic = path.join(DEPLOY, '.next', 'static');
fs.mkdirSync(deployStatic, { recursive: true });
copyDir(STATIC, deployStatic);

// Copy public folder
if (fs.existsSync(PUBLIC)) {
  console.log('📦 Copying public folder...');
  const deployPublic = path.join(DEPLOY, 'public');
  fs.mkdirSync(deployPublic, { recursive: true });
  copyDir(PUBLIC, deployPublic);
}

// Copy web.config
console.log('📦 Copying web.config...');
fs.copyFileSync(
  path.join(ROOT, 'web.config'),
  path.join(DEPLOY, 'web.config')
);

console.log('\n✅ Deployment package ready in /deploy folder!');
console.log('\n📋 Upload the contents of the /deploy folder to SmarterASP.NET');
console.log('   Make sure Node.js is enabled in your hosting panel.\n');

// Helper function to copy directory recursively
function copyDir(src, dest) {
  if (!fs.existsSync(dest)) {
    fs.mkdirSync(dest, { recursive: true });
  }
  
  const entries = fs.readdirSync(src, { withFileTypes: true });
  
  for (const entry of entries) {
    const srcPath = path.join(src, entry.name);
    const destPath = path.join(dest, entry.name);
    
    if (entry.isDirectory()) {
      copyDir(srcPath, destPath);
    } else {
      fs.copyFileSync(srcPath, destPath);
    }
  }
}






