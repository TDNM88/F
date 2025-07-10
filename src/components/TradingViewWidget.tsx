'use client';

import React, { useEffect, useRef, memo } from 'react';

interface TradingViewWidgetProps {
  symbol?: string;
  interval?: string;
  containerId?: string;
}

const TradingViewWidget: React.FC<TradingViewWidgetProps> = ({
  symbol = 'NASDAQ:AAPL',
  interval = 'D',
  containerId = 'tradingview-widget',
}) => {
  const containerRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    if (!containerRef.current) return;

    // Clear previous widget
    containerRef.current.innerHTML = '';

    const script = document.createElement('script');
    script.src = 'https://s3.tradingview.com/external-embedding/embed-widget-symbol-overview.js';
    script.type = 'text/javascript';
    script.async = true;
    script.innerHTML = JSON.stringify({
      symbols: [[symbol.split(':')[1] || symbol, `${symbol}|${interval}`]],
      chartType: 'area',
      colorTheme: 'dark',
      autosize: true,
      locale: 'en',
    });

    containerRef.current.appendChild(script);

    return () => {
      if (containerRef.current) containerRef.current.innerHTML = '';
    };
  }, [symbol, interval]);

  return <div id={containerId} ref={containerRef} className="w-full h-full" />;
};

TradingViewWidget.displayName = 'TradingViewWidget';

export default memo(TradingViewWidget);