// extension/content-auth.js
(function() {
  function syncAuth() {
    const token = localStorage.getItem('dovtek_token');
    const userStr = localStorage.getItem('dovtek_user');
    
    // Tag the body to let the website know the extension is active and listening
    if (!document.body.hasAttribute('data-shieldiq-extension-installed')) {
      document.body.setAttribute('data-shieldiq-extension-installed', 'true');
    }

    // Check if protection is enabled in extension storage
    chrome.storage.sync.get(["protectionEnabled"], (settings) => {
      if (settings.protectionEnabled) {
        document.body.setAttribute('data-shieldiq-extension-active', 'true');
      } else {
        document.body.removeAttribute('data-shieldiq-extension-active');
      }
    });

    if (token && userStr) {
      try {
        const user = JSON.parse(userStr);
        // Only synchronize if the user has a subscription plan
        if (user.plan === 'plus' || user.plan === 'enterprise') {
          chrome.storage.sync.get(["authToken", "apiBase"], (settings) => {
            let needsUpdate = false;
            const updates = {};

            if (settings.authToken !== token) {
              updates.authToken = token;
              needsUpdate = true;
            }

            // Sync API base automatically with current dashboard URL origin (handles local & Render URLs)
            const currentOrigin = window.location.origin;
            if (settings.apiBase !== currentOrigin) {
              updates.apiBase = currentOrigin;
              needsUpdate = true;
            }

            if (needsUpdate) {
              chrome.storage.sync.set(updates, () => {
                console.log("ShieldIQ Extension: Authentication successfully synchronized from webpage.");
              });
            }
          });
        } else {
          // If user downgraded/cancelled their subscription, clear token and disable protection
          chrome.storage.sync.get(["authToken", "protectionEnabled"], (settings) => {
            const updates = {};
            let needsUpdate = false;
            if (settings.authToken) {
              updates.authToken = "";
              needsUpdate = true;
            }
            if (settings.protectionEnabled) {
              updates.protectionEnabled = false;
              needsUpdate = true;
            }
            if (needsUpdate) {
              chrome.storage.sync.set(updates, () => {
                console.log("ShieldIQ Extension: Subscription inactive. Extension disabled.");
              });
            }
          });
        }
      } catch (e) {
        console.error("ShieldIQ Extension auth sync error:", e);
      }
    } else {
      // User is logged out on the webpage, sync logout to the extension
      chrome.storage.sync.get(["authToken", "protectionEnabled"], (settings) => {
        const updates = {};
        let needsUpdate = false;
        if (settings.authToken) {
          updates.authToken = "";
          needsUpdate = true;
        }
        if (settings.protectionEnabled) {
          updates.protectionEnabled = false;
          needsUpdate = true;
        }
        if (needsUpdate) {
          chrome.storage.sync.set(updates, () => {
            console.log("ShieldIQ Extension: Logged out automatically (synced from webpage).");
          });
        }
      });
    }
  }

  // Listen for activation commands from the webpage
  window.addEventListener('shieldiq_activate_protection', () => {
    chrome.storage.sync.set({ protectionEnabled: true }, () => {
      console.log("ShieldIQ Extension: Protection activated by user.");
      document.body.setAttribute('data-shieldiq-extension-active', 'true');
      window.dispatchEvent(new CustomEvent('shieldiq_activation_synced', { detail: { active: true } }));
    });
  });

  window.addEventListener('shieldiq_deactivate_protection', () => {
    chrome.storage.sync.set({ protectionEnabled: false }, () => {
      console.log("ShieldIQ Extension: Protection deactivated by user.");
      document.body.removeAttribute('data-shieldiq-extension-active');
      window.dispatchEvent(new CustomEvent('shieldiq_activation_synced', { detail: { active: false } }));
    });
  });

  // Initial sync on script load
  syncAuth();

  // Watch for any changes to localStorage (like logins/logouts or upgrades)
  setInterval(syncAuth, 1000);
})();
