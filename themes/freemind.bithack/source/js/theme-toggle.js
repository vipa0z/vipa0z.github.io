// Theme Toggle Script
(function () {
    'use strict';

    function initThemeSwitcher() {
        // Elements
        // We might have multiple buttons (e.g. mobile vs desktop, or gitbook vs normal)
        // usage: class="theme-toggle-btn"
        const toggles = document.querySelectorAll('.theme-toggle-btn');

        // Load preference
        const savedTheme = localStorage.getItem('theme-preference') || 'dark';

        // Apply initial state
        if (savedTheme === 'light') {
            document.body.classList.add('light-theme');
            updateIcons(true);
        } else {
            document.body.classList.remove('light-theme');
            updateIcons(false);
        }

        // Add event listeners
        toggles.forEach(btn => {
            btn.addEventListener('click', function (e) {
                e.preventDefault();
                const isLight = document.body.classList.toggle('light-theme');
                localStorage.setItem('theme-preference', isLight ? 'light' : 'dark');
                updateIcons(isLight);
            });
        });

        function updateIcons(isLight) {
            toggles.forEach(btn => {
                // Assuming FontAwesome icons
                // If the button has an icon inside, swap it
                const icon = btn.querySelector('i');
                if (icon) {
                    if (isLight) {
                        icon.classList.remove('fa-moon-o');
                        icon.classList.add('fa-sun-o');
                    } else {
                        icon.classList.remove('fa-sun-o');
                        icon.classList.add('fa-moon-o');
                    }
                }

                // If button has text content that says "Dark" or "Light", swap it
                // This is a simple heuristic, adjust if you have specific text requirements
                if (btn.textContent.trim() === 'Dark' || btn.textContent.trim() === 'Light' || btn.textContent.trim() === '🌙 Dark' || btn.textContent.trim() === '☀️ Light') {
                    btn.textContent = isLight ? '☀️ Light' : '🌙 Dark';
                }
            });
        }
    }

    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', initThemeSwitcher);
    } else {
        initThemeSwitcher();
    }
})();

