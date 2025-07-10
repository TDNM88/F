// This file ensures React is available globally
import React from 'react';

if (typeof window !== 'undefined') {
  window.React = window.React || React;
}

export default React;
