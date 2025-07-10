// This file ensures React is loaded in the global scope before any other code runs
import React from 'react';

// Make React available globally
if (typeof window !== 'undefined') {
  window.React = React;
}

// Export React for ES modules
export default React;
