/**
 * GitBook-style documentation viewer
 * Fetches content dynamically from GitHub repository
 */

const GitBook = {
    // Configuration - now uses local files
    config: {
        basePath: 'cheatsheets/cheatsheets-notes',
        navJsonPath: '/js/gitbook-nav.json'
    },

    // State
    state: {
        currentPath: null,
        navStructure: [],
        flattenedNav: [],
        currentIndex: -1,
        searchData: []
    },

    // DOM Elements
    elements: {},

    /**
     * Initialize the GitBook viewer
     */
    async init() {
        this.cacheElements();
        // Cache initial content (Welcome Screen) for Home navigation
        if (this.elements.contentBody) {
            this.initialContent = this.elements.contentBody.innerHTML;
        }
        
        // Initial responsive state
        if (window.innerWidth <= 768) {
            this.elements.sidebar?.classList.add('collapsed');
            this.elements.sidebar?.classList.remove('open');
        }

        this.bindEvents();
        await this.loadNavigation();
        this.initThemeToggle();
        this.initSidebarResize();
        this.checkUrlHash();
    },

    cacheElements() {
        this.elements = {
            sidebar: document.getElementById('gitbook-sidebar'),
            sidebarNav: document.getElementById('sidebar-nav'),
            sidebarToggle: document.getElementById('sidebar-toggle'),
            mobileMenuBtn: document.getElementById('mobile-menu-btn'),
            mainContainer: document.getElementById('gitbook-content'),
            contentBody: document.getElementById('content-body'),
            breadcrumb: document.getElementById('breadcrumb'),
            prevBtn: document.getElementById('prev-btn'),
            nextBtn: document.getElementById('next-btn'),
            searchInput: document.getElementById('docs-search'),
            quickLinksGrid: document.getElementById('quick-links-grid'),
            tocNav: document.getElementById('toc-nav'),
            contentToc: document.getElementById('content-toc'),
            sidebarResizer: document.getElementById('sidebar-resizer'),
            themeToggle: document.getElementById('gitbook-theme-toggle'),
            sidebarOpenBtn: document.getElementById('sidebar-open-btn'),
            contentHeader: document.querySelector('.content-header')
        };
    },
    /**
     * Bind event listeners
     */
    bindEvents() {
        // Sidebar toggle
        this.elements.sidebarToggle?.addEventListener('click', () => this.toggleSidebar());
        this.elements.mobileMenuBtn?.addEventListener('click', () => {
            // Toggle logic
            if (this.elements.sidebar?.classList.contains('open')) {
                this.toggleSidebar();
            } else {
                this.openSidebar();
            }
        });

        // Use event delegation for sidebar open button to ensure it works even if DOM changes or timing issues
        document.addEventListener('click', (e) => {
            if (e.target.closest('#sidebar-open-btn')) {
                this.openSidebar();
            }
        });

        // Search
        this.elements.searchInput?.addEventListener('input', (e) => this.handleSearch(e.target.value));

        // Navigation buttons
        this.elements.prevBtn?.addEventListener('click', () => this.navigatePrev());
        this.elements.nextBtn?.addEventListener('click', () => this.navigateNext());

        // Hash change
        window.addEventListener('hashchange', () => this.checkUrlHash());

        // Close sidebar on content click (mobile)
        this.elements.contentBody?.addEventListener('click', () => {
            if (window.innerWidth <= 768) {
                this.elements.sidebar?.classList.remove('open');
            }
        });
    },

    /**
     * Toggle sidebar visibility (close it)
     */
    toggleSidebar() {
        this.elements.sidebar?.classList.add('collapsed');
        this.elements.sidebar?.classList.remove('open');
    },

    /**
     * Open sidebar
     */
    openSidebar() {
        this.elements.sidebar?.classList.remove('collapsed');
        this.elements.sidebar?.classList.add('open');
    },

    /**
     * Load navigation structure from local JSON
     */
    async loadNavigation() {
        try {
            const response = await fetch(this.config.navJsonPath);
            if (!response.ok) throw new Error(`HTTP ${response.status}`);

            const structure = await response.json();
            // Prepend Home link
            structure.unshift({
                type: 'file',
                name: 'Home',
                path: 'cheatsheets/index.md', // Adjust this to your actual home markdown path if different
                icon: 'fa-home'
            });
            this.state.navStructure = structure;
            this.renderNavigation(structure);
            this.flattenNavigation(structure);
            this.renderQuickLinks(structure);
        } catch (error) {
            console.error('Failed to load navigation:', error);
            this.elements.sidebarNav.innerHTML = `
        <div class="error-message">
          <i class="fa fa-exclamation-triangle"></i>
          <p>Failed to load navigation</p>
          <p style="font-size: 11px; color: #666;">Run: hexo generate</p>
          <button onclick="GitBook.loadNavigation()">Retry</button>
        </div>
      `;
        }
    },



    /**
     * Format item name for display
     */
    formatName(name) {
        // Remove file extension
        name = name.replace(/\.(md|txt)$/i, '');
        // Remove number prefixes like "01-", "02-"
        name = name.replace(/^\d+-/, '');
        // Replace underscores and dashes with spaces
        name = name.replace(/[-_]/g, ' ');
        // Capitalize words
        return name.split(' ').map(word =>
            word.charAt(0).toUpperCase() + word.slice(1).toLowerCase()
        ).join(' ');
    },

    /**
     * Get icon for item
     */
    getIcon(name, type) {
        if (type === 'dir') {
            return 'fa-folder';
        }
        return 'fa-file-text-o';
    },

    /**
     * Render navigation tree
     */
    renderNavigation(structure, container = null) {
        if (!container) {
            container = this.elements.sidebarNav;
            container.innerHTML = '';
        }

        const ul = document.createElement('ul');
        ul.className = 'nav-list';

        for (const item of structure) {
            const li = document.createElement('li');
            li.className = `nav-item ${item.type}`;

            if (item.type === 'dir') {
                const iconHtml = item.icon ? `<i class="fa ${item.icon}"></i>` : '';
                li.innerHTML = `
          <div class="nav-folder" data-path="${item.path}">
            <i class="fa fa-chevron-right folder-arrow ${item.isOpen ? 'open' : ''}"></i>
            ${iconHtml}
            <span>${item.name}</span>
          </div>
        `;

                if (item.children && item.children.length > 0) {
                    const childContainer = document.createElement('div');
                    childContainer.className = `nav-children ${item.isOpen ? 'open' : ''}`;
                    this.renderNavigation(item.children, childContainer);
                    li.appendChild(childContainer);
                }

                // Toggle folder
                li.querySelector('.nav-folder').addEventListener('click', (e) => {
                    const arrow = li.querySelector('.folder-arrow');
                    const children = li.querySelector('.nav-children');
                    arrow?.classList.toggle('open');
                    children?.classList.toggle('open');
                });
            } else {
                const iconHtml = item.icon ? `<i class="fa ${item.icon}"></i>` : '';
                li.innerHTML = `
          <a class="nav-link" href="#${encodeURIComponent(item.path)}" data-path="${item.path}">
            ${iconHtml}
            <span>${item.name}</span>
          </a>
        `;

                li.querySelector('.nav-link').addEventListener('click', (e) => {
                    e.preventDefault();
                    this.loadContent(item.path);
                    window.location.hash = encodeURIComponent(item.path);

                    // Close sidebar on mobile
                    if (window.innerWidth <= 768) {
                        this.elements.sidebar?.classList.remove('open');
                    }
                });

                // Add to search data
                this.state.searchData.push({
                    name: item.name,
                    path: item.path,
                    content: item.content || ''
                });
            }

            ul.appendChild(li);
        }

        container.appendChild(ul);
    },

    /**
     * Flatten navigation for prev/next
     */
    flattenNavigation(structure, result = []) {
        for (const item of structure) {
            if (item.type === 'file') {
                result.push(item);
            } else if (item.children) {
                this.flattenNavigation(item.children, result);
            }
        }
        this.state.flattenedNav = result;
        return result;
    },

    /**
     * Render quick links on home
     */
    renderQuickLinks(structure) {
        if (!this.elements.quickLinksGrid) return;

        const topLevelFolders = structure.filter(item => item.type === 'dir');

        this.elements.quickLinksGrid.innerHTML = topLevelFolders.map(folder => `
      <div class="quick-link-card" data-path="${folder.path}">
        <i class="fa ${folder.icon}"></i>
        <h4>${folder.name}</h4>
        <span class="item-count">${folder.children?.length || 0} items</span>
      </div>
    `).join('');

        // Add click handlers
        this.elements.quickLinksGrid.querySelectorAll('.quick-link-card').forEach(card => {
            card.addEventListener('click', () => {
                const path = card.dataset.path;
                // Find first file in this folder
                const folder = structure.find(f => f.path === path);
                if (folder?.children) {
                    const firstFile = this.findFirstFile(folder.children);
                    if (firstFile) {
                        this.loadContent(firstFile.path);
                        window.location.hash = encodeURIComponent(firstFile.path);
                    }
                }
            });
        });
    },

    /**
     * Find first file in structure
     */
    findFirstFile(structure) {
        for (const item of structure) {
            if (item.type === 'file') return item;
            if (item.children) {
                const file = this.findFirstFile(item.children);
                if (file) return file;
            }
        }
        return null;
    },

    /**
     * Check URL hash and load content
     */
    checkUrlHash() {
        const hash = window.location.hash.slice(1);
        if (hash) {
            const path = decodeURIComponent(hash);
            this.loadContent(path);
        }
    },

    /**
     * Load content from local files
     */
    async loadContent(path) {
        this.state.currentPath = path;

        // Handle Home Page separately (restore initial content)
        if (path === 'cheatsheets/index.md') {
            if (this.initialContent) {
                this.elements.contentBody.innerHTML = this.initialContent;
                this.updateBreadcrumb(path);

                // Re-initialize dynamic elements like Quick Links
                const quickLinksGrid = this.elements.contentBody.querySelector('#quick-links-grid');
                if (quickLinksGrid) {
                    this.elements.quickLinksGrid = quickLinksGrid;
                    this.renderQuickLinks(this.state.navStructure);
                }

                // Scroll to top
                if (this.elements.mainContainer) {
                    this.elements.mainContainer.scrollTop = 0;
                }
                return;
            }
        }

        // Show loading
        this.elements.contentBody.innerHTML = `
      <div class="loading-spinner">
        <i class="fa fa-spinner fa-spin"></i>
        <span>Loading content...</span>
      </div>
    `;

        try {
            // Convert path to URL - the markdown files are in source folder
            const url = `/${path}`;
            const response = await fetch(url);

            if (!response.ok) throw new Error(`HTTP ${response.status}`);

            const content = await response.text();
            this.renderContent(content, path);
            this.updateBreadcrumb(path);
            this.updateNavButtons(path);
            this.highlightActiveNav(path);

        } catch (error) {
            console.error('Failed to load content:', error);
            this.elements.contentBody.innerHTML = `
        <div class="error-message">
          <i class="fa fa-exclamation-triangle"></i>
          <h2>Failed to load content</h2>
          <p>${error.message}</p>
          <button onclick="GitBook.loadContent('${path}')">Retry</button>
        </div>
      `;
        }
    },

    /**
     * Render markdown content
     */
    renderContent(content, path) {
        // Configure marked
        marked.setOptions({
            highlight: function (code, lang) {
                if (Prism.languages[lang]) {
                    return Prism.highlight(code, Prism.languages[lang], lang);
                }
                return code;
            },
            breaks: true,
            gfm: true
        });

        // Pre-process content to handle Obsidian-style images
        // ![[image.png]] -> ![image.png](/ss/image.png)
        const processedContent = content.replace(/!\[\[(.*?)\]\]/g, (match, filename) => {
            const cleanFilename = filename.trim();
            // encode spaces for URL
            const url = '/ss/' + encodeURIComponent(cleanFilename);
            return `![${cleanFilename}](${url})`;
        });

        // Parse markdown
        const html = marked.parse(processedContent);

        // Get file name for title
        const fileName = path.split('/').pop().replace(/\.(md|txt)$/i, '');
        const title = this.formatName(fileName);

        this.elements.contentBody.innerHTML = `
      <div class="content-wrapper">
        <div class="content-header-info">
          <h1>${title}</h1>
          <div class="content-meta">
            <a href="https://github.com/${this.config.owner}/${this.config.repo}/blob/${this.config.branch}/${path}" 
               target="_blank" rel="noopener" class="edit-link">
              <i class="fa fa-github"></i> View on GitHub
            </a>
          </div>
        </div>
        <div class="markdown-body">
          ${html}
        </div>
      </div>
    `;

        // Scroll to top
        if (this.elements.mainContainer) {
            this.elements.mainContainer.scrollTop = 0;
        } else {
            this.elements.contentBody.scrollTop = 0;
        }

        // Re-apply Prism highlighting
        Prism.highlightAllUnder(this.elements.contentBody);

        // Make tables responsive
        this.elements.contentBody.querySelectorAll('table').forEach(table => {
            const wrapper = document.createElement('div');
            wrapper.className = 'table-wrapper';
            table.parentNode.insertBefore(wrapper, table);
            wrapper.appendChild(table);
        });

        // Create TOC
        this.generateTOC();

        // Add copy buttons to code blocks
        this.addCopyButtons();

        // Check for Quick Links Grid in the new content (Home Page)
        const quickLinksGrid = this.elements.contentBody.querySelector('#quick-links-grid');
        if (quickLinksGrid) {
            // Re-assign reference and render
            this.elements.quickLinksGrid = quickLinksGrid;
            this.renderQuickLinks(this.state.navStructure);
        }
    },

    /**
     * Add copy buttons to code blocks
     */
    addCopyButtons() {
        this.elements.contentBody.querySelectorAll('pre').forEach(pre => {
            // Create wrapper
            const wrapper = document.createElement('div');
            wrapper.className = 'code-wrapper';

            // Insert wrapper before pre
            pre.parentNode.insertBefore(wrapper, pre);

            // Move pre into wrapper
            wrapper.appendChild(pre);

            const button = document.createElement('button');
            button.className = 'copy-btn';
            button.innerHTML = '<i class="fa fa-copy"></i>';
            button.title = 'Copy code';

            button.addEventListener('click', async () => {
                const code = pre.querySelector('code')?.textContent || pre.textContent;
                try {
                    await navigator.clipboard.writeText(code);
                    button.innerHTML = '<i class="fa fa-check"></i>';
                    button.classList.add('copied');
                    setTimeout(() => {
                        button.innerHTML = '<i class="fa fa-copy"></i>';
                        button.classList.remove('copied');
                    }, 2000);
                } catch (err) {
                    console.error('Failed to copy:', err);
                }
            });

            wrapper.appendChild(button);
        });
    },


    /**
     * Update breadcrumb (Interactive)
     */
    updateBreadcrumb(path) {
        const parts = path.split('/');
        const baseParts = this.config.basePath.split('/').length;
        const relevantParts = parts.slice(baseParts);

        let html = '<a href="/cheatsheets/" class="breadcrumb-link" data-path="cheatsheets/index.md">Home</a>';

        // Remove click logic for intermediate folders to avoid 404s
        relevantParts.forEach((part, index) => {
            const name = this.formatName(part);
            const isLast = index === relevantParts.length - 1;

            if (isLast) {
                html += ` <i class="fa fa-chevron-right"></i> <span class="breadcrumb-current">${name}</span>`;
            } else {
                // Render as text only, not link
                html += ` <i class="fa fa-chevron-right"></i> <span class="breadcrumb-text">${name}</span>`;
            }
        });

        this.elements.breadcrumb.innerHTML = html;

        // Add click handlers ONLY for Home link logic
        this.elements.breadcrumb.querySelectorAll('.breadcrumb-link').forEach(link => {
            link.addEventListener('click', (e) => {
                e.preventDefault();
                const path = link.dataset.path;
                if (path === 'cheatsheets/index.md') {
                    // Special handling for home if needed, or just load it
                    this.loadContent(path);
                    window.location.hash = ''; // Clear hash for home or set to #
                }
            });
        });
    },


    /**
     * Update navigation buttons
     */
    updateNavButtons(path) {
        const index = this.state.flattenedNav.findIndex(item => item.path === path);
        this.state.currentIndex = index;

        const prevItem = this.state.flattenedNav[index - 1];
        const nextItem = this.state.flattenedNav[index + 1];

        if (prevItem) {
            this.elements.prevBtn.disabled = false;
            this.elements.prevBtn.querySelector('span').textContent = prevItem.name;
        } else {
            this.elements.prevBtn.disabled = true;
            this.elements.prevBtn.querySelector('span').textContent = 'Previous';
        }

        if (nextItem) {
            this.elements.nextBtn.disabled = false;
            this.elements.nextBtn.querySelector('span').textContent = nextItem.name;
        } else {
            this.elements.nextBtn.disabled = true;
            this.elements.nextBtn.querySelector('span').textContent = 'Next';
        }
    },

    /**
     * Navigate to previous document
     */
    navigatePrev() {
        const prevItem = this.state.flattenedNav[this.state.currentIndex - 1];
        if (prevItem) {
            this.loadContent(prevItem.path);
            window.location.hash = encodeURIComponent(prevItem.path);
        }
    },

    /**
     * Navigate to next document
     */
    navigateNext() {
        const nextItem = this.state.flattenedNav[this.state.currentIndex + 1];
        if (nextItem) {
            this.loadContent(nextItem.path);
            window.location.hash = encodeURIComponent(nextItem.path);
        }
    },

    /**
     * Highlight active nav item
     */
    highlightActiveNav(path) {
        // Remove all active classes
        this.elements.sidebarNav.querySelectorAll('.nav-link').forEach(link => {
            link.classList.remove('active');
        });

        // Add active class to current
        const activeLink = this.elements.sidebarNav.querySelector(`[data-path="${path}"]`);
        if (activeLink) {
            activeLink.classList.add('active');

            // Expand parent folders
            let parent = activeLink.closest('.nav-children');
            while (parent) {
                parent.classList.add('open');
                const arrow = parent.previousElementSibling?.querySelector('.folder-arrow');
                if (arrow) arrow.classList.add('open');
                parent = parent.parentElement?.closest('.nav-children');
            }
        }
    },

    /**
     * Handle search
     */
    handleSearch(query) {
        const searchResults = this.elements.sidebarNav.querySelector('.search-results');

        if (!query.trim()) {
            // Remove any existing search results and show normal nav
            if (searchResults) searchResults.remove();
            this.elements.sidebarNav.querySelector('.nav-list')?.classList.remove('hidden');
            return;
        }

        // Filter results
        // Filter results (search name and content)
        const lowerQuery = query.toLowerCase();
        const results = this.state.searchData.filter(item =>
            item.name.toLowerCase().includes(lowerQuery) ||
            (item.content && item.content.toLowerCase().includes(lowerQuery))
        );

        // Hide normal nav
        this.elements.sidebarNav.querySelector('.nav-list')?.classList.add('hidden');

        // Show/create search results
        let resultsContainer = searchResults;
        if (!resultsContainer) {
            resultsContainer = document.createElement('div');
            resultsContainer.className = 'search-results';
            this.elements.sidebarNav.appendChild(resultsContainer);
        }

        if (results.length === 0) {
            resultsContainer.innerHTML = `
        <div class="no-results">
          <i class="fa fa-search"></i>
          <p>No results found</p>
        </div>
      `;
        } else {
            resultsContainer.innerHTML = `
        <ul class="nav-list">
          ${results.map(item => `
            <li class="nav-item file">
              <a class="nav-link" href="#${encodeURIComponent(item.path)}" data-path="${item.path}">
                <i class="fa fa-file-text-o"></i>
                <span>${item.name}</span>
              </a>
            </li>
          `).join('')}
        </ul>
      `;

            // Add click handlers
            resultsContainer.querySelectorAll('.nav-link').forEach(link => {
                link.addEventListener('click', (e) => {
                    e.preventDefault();
                    const path = link.dataset.path;
                    this.loadContent(path);
                    window.location.hash = encodeURIComponent(path);
                    this.elements.searchInput.value = '';
                    this.handleSearch('');

                    if (window.innerWidth <= 768) {
                        this.elements.sidebar?.classList.remove('open');
                    }
                });
            });
        }
    },
    /**
     * Initialize theme toggle
     */
    initThemeToggle() {
        // Global theme toggle handled in theme-toggle.js
    },

    /**
     * Initialize sidebar resizing
     */
    initSidebarResize() {
        const sidebar = this.elements.sidebar;
        const resizer = this.elements.sidebarResizer;
        // const content = document.querySelector('.gitbook-content');

        if (!sidebar || !resizer) return;

        let isResizing = false;
        let startX;
        let startWidth;

        resizer.addEventListener('mousedown', (e) => {
            isResizing = true;
            startX = e.clientX;
            startWidth = sidebar.getBoundingClientRect().width;
            sidebar.classList.add('resizing');
            document.body.style.cursor = 'col-resize';
        });

        document.addEventListener('mousemove', (e) => {
            if (!isResizing) return;

            const diff = e.clientX - startX;
            const newWidth = Math.min(Math.max(startWidth + diff, 200), 800);

            sidebar.style.width = `${newWidth}px`;
            // In flexbox layout, we don't need to set margin-left on content
            // if (content) content.style.marginLeft = `${newWidth}px`;
        });

        document.addEventListener('mouseup', () => {
            if (isResizing) {
                isResizing = false;
                sidebar.classList.remove('resizing');
                document.body.style.cursor = '';
            }
        });
    },

    /**
     * Generate Table of Contents
     */
    generateTOC() {
        const headers = this.elements.contentBody.querySelectorAll('h2, h3');
        const tocNav = this.elements.tocNav;
        const tocContainer = this.elements.contentToc;

        if (!headers.length) {
            tocContainer.classList.remove('has-toc');
            tocContainer.style.display = 'none';
            return;
        }

        tocNav.innerHTML = '';
        tocContainer.classList.add('has-toc');
        tocContainer.style.display = 'block';

        headers.forEach((header, index) => {
            // Create ID if missing
            if (!header.id) {
                header.id = 'heading-' + index;
            }

            const link = document.createElement('a');
            link.className = `toc-link toc-${header.tagName.toLowerCase()}`;
            link.href = '#' + header.id;
            link.textContent = header.textContent;

            link.addEventListener('click', (e) => {
                e.preventDefault();
                header.scrollIntoView({ behavior: 'smooth' });
                // Update active state
                tocNav.querySelectorAll('.toc-link').forEach(l => l.classList.remove('active'));
                link.classList.add('active');
            });

            tocNav.appendChild(link);
        });

        // Scroll spy - highlight current section
        this.initScrollSpy(headers, tocNav);
    },

    /**
     * Initialize scroll spy for TOC highlighting
     */
    initScrollSpy(headers, tocNav) {
        const observerOptions = {
            root: null,
            rootMargin: '-100px 0px -66%',
            threshold: 0
        };

        const observer = new IntersectionObserver((entries) => {
            entries.forEach(entry => {
                if (entry.isIntersecting) {
                    const id = entry.target.id;
                    tocNav.querySelectorAll('.toc-link').forEach(link => {
                        link.classList.remove('active');
                        if (link.getAttribute('href') === '#' + id) {
                            link.classList.add('active');
                        }
                    });
                }
            });
        }, observerOptions);

        headers.forEach(header => observer.observe(header));
    }
};

// Initialize on DOM ready
document.addEventListener('DOMContentLoaded', () => GitBook.init());
