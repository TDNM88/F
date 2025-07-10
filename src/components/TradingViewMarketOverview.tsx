import React, { useEffect, useRef } from 'react';

/**
 * TradingView Market Overview widget embedding.
 * Shows tabs (Indices, Forex, Futures, Bonds) with icons as in TradingView sample.
 * Auto-sizes to fill parent container width.
 */
const TradingViewMarketOverview: React.FC = () => {
  const containerRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    if (!containerRef.current) return;

    // clear previous script if any
    containerRef.current.innerHTML = '';

    const script = document.createElement('script');
    script.src = 'https://s3.tradingview.com/external-embedding/embed-widget-market-overview.js';
    script.type = 'text/javascript';
    script.async = true;
    script.innerHTML = JSON.stringify({
      colorTheme: 'light',
      dateRange: '1Y',
      showChart: true,
      locale: 'vi_VN',
      width: '100%',
      height: '500',
      largeChartUrl: '',
      isTransparent: false,
      showSymbolLogo: true,
      plotLineColorGrowing: 'rgba(41, 98, 255, 1)',
      plotLineColorFalling: 'rgba(41, 98, 255, 1)',
      gridLineColor: 'rgba(240, 243, 250, 0)',
      scaleFontColor: 'rgba(106, 109, 120, 1)',
      belowLineFillColorGrowing: 'rgba(41, 98, 255, 0.12)',
      belowLineFillColorFalling: 'rgba(41, 98, 255, 0.12)',
      belowLineFillColorGrowingBottom: 'rgba(41, 98, 255, 0)',
      belowLineFillColorFallingBottom: 'rgba(41, 98, 255, 0)',
      symbolActiveColor: 'rgba(41, 98, 255, 0.12)',
      tabs: [
        {
          title: 'Indices',
          symbols: [
            { s: 'FOREXCOM:SPXUSD', d: 'SPXUSD' },
            { s: 'FOREXCOM:NSXUSD', d: 'NSXUSD' },
            { s: 'FOREXCOM:DJI', d: 'DJI' },
            { s: 'INDEX:NKY', d: 'NKY' },
            { s: 'INDEX:DEU40', d: 'DEU40' },
            { s: 'FOREXCOM:UKXGBP', d: 'UKXGBP' }
          ]
        },
        { title: 'Forex', symbols: [] },
        { title: 'Futures', symbols: [] },
        { title: 'Bonds', symbols: [] }
      ]
    });

    containerRef.current.appendChild(script);

    return () => {
      if (containerRef.current) containerRef.current.innerHTML = '';
    };
  }, []);

  return <div ref={containerRef} className="w-full h-full" />;
};

export default TradingViewMarketOverview;
