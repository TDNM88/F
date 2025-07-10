import { useEffect, useRef } from 'react';

interface TradingViewAdvancedChartProps {
  symbol?: string; // e.g. "TVC:GOLD"
  interval?: string; // e.g. "15" for 15 minutes
  theme?: 'light' | 'dark';
  height?: number | string;
  interactive?: boolean; // if false, disable user interaction
  style?: number; // 1 = Candles, 3 = Line, etc.
}

// Embeds TradingView Advanced Chart widget using external script
// Docs: https://www.tradingview.com/widget/advanced-chart/
export default function TradingViewAdvancedChart({
  symbol = 'TVC:GOLD',
  interval = '15',
  theme = 'dark',
  height = '100%',
  style = 1,
  interactive = true,
}: TradingViewAdvancedChartProps) {
  const containerRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    if (!containerRef.current) return;

    // Clear previous widget (Hot reload)
    containerRef.current.innerHTML = '';

    const script = document.createElement('script');
    script.src = 'https://s3.tradingview.com/external-embedding/embed-widget-advanced-chart.js';
    script.type = 'text/javascript';
    script.async = true;

    script.innerHTML = JSON.stringify({
      autosize: true,
      theme,
      interval,
      symbol,
      timezone: 'Etc/UTC',
      allow_symbol_change: false,
      hide_side_toolbar: interactive ? false : true,
      hide_volume: false,
      hide_legend: false,
      locale: 'en',
      disabled_features: interactive ? [] : [
        "header_widget",
        "header_symbol_search",
        "header_compare",
        "header_indicators",
        "header_settings",
        "header_fullscreen_button",
        "header_chart_type",
        "header_interval_dialog_button",
        "header_undo_redo",
        "header_screenshot",
        "timeframes_toolbar",
        "left_toolbar",
        "edit_buttons_in_legend",
        "use_localstorage_for_settings",
        "chart_zoom",
        "chart_pan",
        "mousewheel_zoom",
      ],
      style,
      withdateranges: false,
      hide_top_toolbar: false,
    });

    containerRef.current.appendChild(script);

    if (!interactive && containerRef.current) {
      // Disable all pointer events to prevent any interaction (zoom, pan, etc.)
      containerRef.current.style.pointerEvents = 'none';
    }

    return () => {
      if (containerRef.current) containerRef.current.innerHTML = '';
    };
  }, [symbol, interval, theme, interactive, style]);

  return (
    <div className="relative tradingview-widget-container w-full" style={{ height }} ref={containerRef}>
      <div className="tradingview-widget-container__widget" style={{ height }} />
      {!interactive && (
        <div
          className="absolute inset-0 z-10 select-none touch-none"
          style={{ pointerEvents: 'auto' }}
          onWheelCapture={(e) => e.preventDefault()}
          onTouchMove={(e) => e.preventDefault()}
          onMouseDown={(e) => e.preventDefault()}
        />
      )}
    </div>
  );
}