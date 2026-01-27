/**
 * Hexo generator to build the GitBook sidebar navigation JSON.
 *
 * IMPORTANT:
 * - Hexo only loads generators from:
 *   - <root>/scripts/
 *   - <theme>/scripts/
 * - Files under <theme>/source/js are served to the browser and are NOT executed by Hexo.
 *
 * Output: public/js/gitbook-nav.json
 */

const fs = require('fs');
const path = require('path');

hexo.extend.generator.register('gitbook-nav', function () {
  const sourceDir = hexo.source_dir;
  const notesDir = path.join(sourceDir, 'cheatsheets');

  function formatName(name, depth = 0) {
    // Remove file extension
    name = name.replace(/\.(md|txt)$/i, '');

    // Keep number prefixes for depth > 0, remove for root level
    if (depth === 0) {
      name = name.replace(/^\d+-/, '');
    }

    // Replace underscores and dashes (except in number prefixes) with spaces
    name = name.replace(/(?<=\d-)[-_]/g, ' ').replace(/(?<!\d)[-_]/g, ' ');

    // Capitalize words
    return name
      .split(' ')
      .map((word) => word.charAt(0).toUpperCase() + word.slice(1).toLowerCase())
      .join(' ');
  }

  function getIcon(name, isDir, depth = 0) {
    // No icons for root-level folders
    if (isDir && depth === 0) {
      return null;
    }
    if (isDir) return 'fa-folder';
    return 'fa-file-text-o';
  }

  function scanDirectory(dirPath, basePath = '', depth = 0) {
    if (depth > 4) return [];
    if (!fs.existsSync(dirPath)) return [];

    const items = fs.readdirSync(dirPath);
    const structure = [];

    // Sort: at root (depth 0), put files first (so Recon sits near Home), then dirs.
    // Below root, keep the usual dir-first ordering.
    const sorted = items.sort((a, b) => {
      const aPath = path.join(dirPath, a);
      const bPath = path.join(dirPath, b);
      const aIsDir = fs.statSync(aPath).isDirectory();
      const bIsDir = fs.statSync(bPath).isDirectory();

      if (depth === 0) {
        // root: files before dirs
        if (aIsDir !== bIsDir) return aIsDir ? 1 : -1;
      } else {
        // below root: dirs before files
        if (aIsDir !== bIsDir) return aIsDir ? -1 : 1;
      }
      return a.localeCompare(b);
    });

    for (const item of sorted) {
      // Skip hidden files and non-relevant items
      if (
        item.startsWith('.') ||
        item === 'ss' ||
        item === 'images' ||
        item === 'index.md' ||
        item === 'wizard.png'
      ) {
        continue;
      }

      const fullPath = path.join(dirPath, item);
      const relativePath = basePath ? `${basePath}/${item}` : item;
      const stat = fs.statSync(fullPath);

      if (stat.isDirectory()) {
        const children = scanDirectory(fullPath, relativePath, depth + 1);
        if (children.length > 0) {
          structure.push({
            name: formatName(item, depth),
            path: relativePath,
            type: 'dir',
            icon: getIcon(item, true, depth),
            isOpen: formatName(item, depth).toLowerCase().includes('internal'),
            children,
          });
        }
      } else if (item.endsWith('.md') || item.endsWith('.txt')) {
        // Read content for search
        let content = fs.readFileSync(fullPath, 'utf8');
        // Strip markdown for search index
        content = content.replace(/```[\s\S]*?```/g, ' '); // code blocks
        content = content.replace(/\[([^\]]+)\]\([^\)]+\)/g, '$1'); // links
        content = content.replace(/#+\s+(.*)/g, '$1'); // headers
        content = content.replace(/[^\w\s]/g, ' '); // most special chars
        const searchContent = content.replace(/\s+/g, ' ').trim().slice(0, 5000);

        structure.push({
          name: formatName(item, depth),
          path: relativePath,
          type: 'file',
          icon: getIcon(item, false, depth),
          content: searchContent,
        });
      }
    }

    return structure;
  }

  const navStructure = scanDirectory(notesDir, 'cheatsheets');

  return {
    path: 'js/gitbook-nav.json',
    data: JSON.stringify(navStructure, null, 2),
  };
});

