// Settings and profile while the site is in maintenance.
//
// Nothing of the tree is written then, and ssod refuses every change
// (see MAINTENANCE_COMMANDS in sso1.py). The page is shown all the
// same, with every button and field disabled, so the user sees what is
// there and is not led to press what cannot work.
//
// The cards are built and rebuilt by settings.js and profile.js after
// the page has loaded, and they enable buttons again when a request
// ends. So what is added or enabled later is disabled as well, for as
// long as the page is open.
//
// What is marked data-maintenance-free is left alone: the sessions,
// which are not stored in the tree.
(function () {
    'use strict';

    const CONTROLS = 'button, input, select, textarea';

    function isFree(el) {
        return el.closest('[data-maintenance-free]') !== null;
    }

    function lockControl(el) {
        if (isFree(el)) {
            return;
        }
        // Only when it is not: setting it would be seen by the
        // observer below again.
        if (!el.disabled) {
            el.disabled = true;
        }
    }

    function lockAll(root) {
        if (root.matches && root.matches(CONTROLS)) {
            lockControl(root);
        }
        if (root.querySelectorAll) {
            root.querySelectorAll(CONTROLS).forEach(lockControl);
        }
    }

    document.querySelectorAll('.maintenance-locked').forEach(function (wrapper) {
        lockAll(wrapper);
        const observer = new MutationObserver(function (mutations) {
            mutations.forEach(function (mutation) {
                if (mutation.type === 'attributes') {
                    lockAll(mutation.target);
                    return;
                }
                mutation.addedNodes.forEach(function (node) {
                    if (node.nodeType === Node.ELEMENT_NODE) {
                        lockAll(node);
                    }
                });
            });
        });
        observer.observe(wrapper, {
            subtree: true,
            childList: true,
            attributes: true,
            attributeFilter: ['disabled'],
        });
    });
})();
