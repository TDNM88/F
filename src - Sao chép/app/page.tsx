"use client"

import { useRouter } from "next/navigation";
import { Button } from "@/components/ui/button";
import { motion } from "framer-motion";
import { useEffect, useState } from "react";
import Header from "@/components/Header";
import TradingViewTickerTape from "@/components/TradingViewTickerTape";
import Footer from "@/components/Footer";

// Market ticker data
const marketData = [
  { symbol: "US 500 Cash CFD", value: "27,472.5", change: "-7.00 (-0.13%)", color: "text-red-500" },
  { symbol: "EUR to USD", value: "1.0743", change: "-0.01 (-0.49%)", color: "text-red-500" },
  { symbol: "Gold", value: "3,384.44", change: "-0.36 (-0.01%)", color: "text-red-500" },
  { symbol: "Oil", value: "66.15", change: "-0.63 (-0.94%)", color: "text-red-500" },
  { symbol: "S&P 500 Index", value: "5,797", change: "", color: "text-gray-600" },
];

// Animation variants
const container = {
  hidden: { opacity: 0 },
  show: {
    opacity: 1,
    transition: {
      staggerChildren: 0.1,
      delayChildren: 0.3,
    },
  },
};

const item = {
  hidden: { opacity: 0, y: 20 },
  show: { opacity: 1, y: 0, transition: { duration: 0.5 } },
};

// Market ticker component
function MarketTicker() {
  return (
    <div style={{
      backgroundColor: '#ffffff',
      borderBottom: '1px solid #f0f0f0',
      padding: '8px 0'
    }}>
      <div style={{
        maxWidth: '1200px',
        margin: '0 auto',
        padding: '0 16px'
      }}>
        <div style={{
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'space-between',
          overflowX: 'auto',
          whiteSpace: 'nowrap',
          gap: '16px'
        }}>
          {marketData.map((item, index) => (
            <div key={index} style={{
              display: 'flex',
              flexDirection: 'column',
              padding: '0 8px'
            }}>
              <div style={{fontSize: '12px', color: 'rgba(0, 0, 0, 0.45)'}}>{item.symbol}</div>
              <div style={{fontWeight: 'bold'}}>{item.value}</div>
              <div style={{fontSize: '12px', color: item.color}}>{item.change}</div>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}

// Chart tabs component with improved responsiveness
function ChartTabs() {
  // Hook for tracking active tabs could be added here
  // const [chartType, setChartType] = useState('line');
  // const [timeRange, setTimeRange] = useState('1Y');

  // Common button styles for DRY code
  const chartTypeStyle = (isActive: boolean) => ({
    padding: '6px 8px',
    backgroundColor: isActive ? '#1677ff' : '#f0f0f0',
    color: isActive ? 'white' : 'rgba(0, 0, 0, 0.65)',
    borderRadius: '2px',
    cursor: 'pointer',
    fontSize: 'clamp(11px, 2.5vw, 14px)',
    fontWeight: isActive ? 500 : 400,
    transition: 'all 0.2s ease',
    textAlign: 'center' as const,
    minWidth: '70px',
  });

  const timeRangeStyle = (isActive: boolean) => ({
    padding: '4px 6px',
    backgroundColor: isActive ? '#1677ff' : '#f0f0f0',
    color: isActive ? 'white' : 'rgba(0, 0, 0, 0.65)',
    borderRadius: '2px',
    cursor: 'pointer',
    fontSize: 'clamp(10px, 2vw, 12px)',
    fontWeight: isActive ? 500 : 400,
    transition: 'all 0.2s ease',
    textAlign: 'center' as const,
    minWidth: '32px',
  });

  return (
    <div className="flex flex-col w-full px-1 sm:px-0" style={{ marginBottom: '24px' }}>
      <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between space-y-3 sm:space-y-0 mb-3">
        {/* Chart type selection */}
        <div className="grid grid-cols-3 sm:flex sm:flex-wrap gap-2 w-full sm:w-auto">
          <div style={chartTypeStyle(true)}>Line</div>
          <div style={chartTypeStyle(false)}>Candlestick</div>
          <div style={chartTypeStyle(false)}>OHLC</div>
        </div>
        
        {/* Time range selection */}
        <div className="grid grid-cols-4 sm:flex sm:flex-wrap gap-2 w-full sm:w-auto">
          <div style={timeRangeStyle(false)}>1D</div>
          <div style={timeRangeStyle(false)}>1W</div>
          <div style={timeRangeStyle(false)}>1M</div>
          <div style={timeRangeStyle(true)}>1Y</div>
        </div>
      </div>
      
      {/* Chart container with responsive height */}
      <div 
        className="w-full rounded-md overflow-hidden" 
        style={{ 
          height: 'clamp(220px, 40vh, 400px)', 
          backgroundColor: '#f5f5f5', 
          marginBottom: '16px' 
        }}
      >
        {/* Chart placeholder - would be replaced with actual chart */}
        <div className="flex items-center justify-center h-full text-gray-400">
          <span>Biểu đồ tại đây</span>
        </div>
      </div>
    </div>
  );
}

export default function Landing() {
  const router = useRouter();
  const [isVisible, setIsVisible] = useState(false);

  useEffect(() => {
    setIsVisible(true);
    return () => setIsVisible(false);
  }, []);

  return (
    <div style={{
      fontFamily: '"-apple-system", "BlinkMacSystemFont", "Segoe UI", "Roboto", "Helvetica Neue", "Arial", "sans-serif"',
      color: 'rgba(0, 0, 0, 0.88)',
      fontSize: '14px',
      lineHeight: 1.5714285714285714
    }}>
      <Header />

      {/* Market ticker */}
      <TradingViewTickerTape />

      {/* Main content */}
      <motion.div
        className="container mx-auto px-4 py-6"
        variants={container}
        initial="hidden"
        animate={isVisible ? "show" : "hidden"}
      >
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-3 sm:gap-4 lg:gap-6" style={{ marginBottom: '16px' }}>
          <div className="mb-6 bg-cover bg-center bg-no-repeat rounded-lg w-full" style={{
            backgroundImage: "url(/slide1.jpg)",
            boxShadow: '0 2px 8px rgba(0, 0, 0, 0.15)',
            minHeight: '280px',
            height: 'clamp(280px, 40vh, 400px)'
          }}></div>
          <div style={{ padding: '16px' }}>
            <h2 style={{
              fontSize: 'clamp(16px, 4vw, 20px)',
              fontWeight: 600,
              marginBottom: '12px',
              color: 'rgba(0, 0, 0, 0.85)'
            }}>LONDON HSC</h2>
            <p style={{
              fontSize: '14px',
              color: 'rgba(0, 0, 0, 0.65)',
              lineHeight: '1.5715',
              margin: 0
            }}>
              Sàn giao dịch chứng khoán London (HSC) là sàn giao dịch chứng khoán chính ở Vương quốc Anh và lớn nhất ở
              châu Âu. Thành lập chính thức từ năm 1773, các sàn giao dịch khu vực được sáp nhập vào năm 1973 để hình
              thành nên Sàn giao dịch chứng khoán Vương quốc Anh và Ireland, sau đó đổi tên thành Sàn giao dịch chứng
              khoán London (HSC).
            </p>
          </div>
          <div style={{ marginBottom: '24px' }}>
            <iframe
              width="100%"
              height="200"
              src="https://www.youtube.com/embed/xnCF64dVscM"
              title="London HSC Trading Platform"
              frameBorder="0"
              allow="accelerometer; autoplay; clipboard-write; encrypted-media; gyroscope; picture-in-picture"
              allowFullScreen
              style={{
                borderRadius: '8px',
                boxShadow: '0 2px 8px rgba(0, 0, 0, 0.15)',
                border: '1px solid #f0f0f0'
              }}
            />
          </div>
        </div>
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-3 sm:gap-4 lg:gap-6" style={{ marginBottom: '16px' }}>
        <div style={{ padding: '16px' }}>
            <h2 style={{
              fontSize: 'clamp(16px, 4vw, 20px)',
              fontWeight: 600,
              marginBottom: '12px',
              color: 'rgba(0, 0, 0, 0.85)',
              lineHeight: '1.4'
            }}>Sàn giao dịch chứng khoán London HSC chào đón Thống đốc Samuel Garcia từ Nuevo León, Mexico</h2>
            <p style={{
              fontSize: '14px',
              color: 'rgba(0, 0, 0, 0.65)',
              lineHeight: '1.5715',
              margin: 0
            }}>
              Sàn giao dịch chứng khoán London HSC rất hân hạnh được chào đón Thống đốc Samuel García và đoàn đại biểu danh dự của ông từ Tiểu bang Nuevo León, Mexico. Chuyến thăm này đánh dấu một cột mốc quan trọng trong việc củng cố mối quan hệ kinh tế giữa Vương quốc Anh và một trong những khu vực năng động và có tư duy tiến bộ nhất của Mỹ Latinh.
            </p>
          </div>
          <div style={{ padding: '16px' }}>
            <h2 style={{
              fontSize: '20px',
              fontWeight: 600,
              marginBottom: '12px',
              color: 'rgba(0, 0, 0, 0.85)'
            }}>Nội dung về sàn giao dịch chứng khoán London HSC</h2>
            <p style={{
              fontSize: '14px',
              color: 'rgba(0, 0, 0, 0.65)',
              lineHeight: '1.5715',
              margin: 0
            }}>
              HSC là sàn giao dịch chứng khoán quốc tế nhất với hàng ngàn công ty từ hơn 60 quốc gia và là nguồn hàng đầu của tính thanh khoản thị trường vốn, giá chuẩn và dữ liệu thị trường ở châu Âu. Có các quan hệ đối tác với các sàn giao dịch quốc tế ở châu Á và châu Phi, SSI dự định loại bỏ các rào cản về chi phí và các qui định khỏi thị trường vốn trên toàn thế giới.
            </p>
          </div>
          {/* FTSE widget */}
      <div style={{
        backgroundColor: '#ffffff',
        border: '1px solid #f0f0f0',
        borderRadius: '8px',
        padding: '16px',
        boxShadow: '0 2px 8px rgba(0, 0, 0, 0.08)'
      }}>
        <div style={{
          display: 'flex',
          alignItems: 'center',
          gap: '12px',
          marginBottom: '12px'
        }}>
          <div style={{
            width: '32px',
            height: '32px',
            backgroundColor: '#117dbb',
            borderRadius: '50%',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'center'
          }}>
            <span style={{ color: '#ffffff', fontSize: '12px', fontWeight: 'bold' }}>UK</span>
          </div>
          <div>
            <div style={{ fontWeight: 'bold', color: 'rgba(0, 0, 0, 0.85)' }}>FTSE 100</div>
            <div style={{ fontSize: '12px', color: 'rgba(0, 0, 0, 0.45)' }}>UK 100 • Indices</div>
          </div>
        </div>
        <div style={{ fontSize: '24px', fontWeight: 'bold', color: 'rgba(0, 0, 0, 0.85)' }}>
          8,786.3<span style={{ fontSize: '14px', color: 'rgba(0, 0, 0, 0.45)', marginLeft: '4px' }}>GBP</span>
        </div>
        <div style={{ color: '#ff4d4f', fontSize: '14px', fontWeight: 500 }}>-7.50 (-0.09%)</div>

        <div style={{
          marginTop: '16px',
          display: 'grid',
          gridTemplateColumns: 'repeat(2, 1fr)',
          gap: '8px',
          fontSize: '12px'
        }} className="sm:grid-cols-4">
          <div>
            <div style={{ color: 'rgba(0, 0, 0, 0.45)' }}>Open</div>
            <div style={{ fontWeight: 500 }}>8,794.2</div>
          </div>
          <div>
            <div style={{ color: 'rgba(0, 0, 0, 0.45)' }}>Close</div>
            <div style={{ fontWeight: 500 }}>8,786.5</div>
          </div>
          <div>
            <div style={{ color: 'rgba(0, 0, 0, 0.45)' }}>High</div>
            <div style={{ fontWeight: 500 }}>8,800.2</div>
          </div>
          <div>
            <div style={{ color: 'rgba(0, 0, 0, 0.45)' }}>Low</div>
            <div style={{ fontWeight: 500 }}>8,786.3</div>
          </div>
        </div>
      </div>
    </div>
  </motion.div>

    <div className="w-full overflow-x-hidden">
        <div className="mx-auto" style={{userSelect: 'none', boxSizing: 'border-box', display: 'block', width: '100%', maxWidth: '1028px'}}>
          <div className="relative pb-[calc(100%*0.7)]">
            <iframe 
              scrolling="no" 
              allowFullScreen={true}
              frameBorder={0}
              src="https://www.tradingview-widget.com/embed-widget/market-overview/#%7B%22width%22%3A400%2C%22height%22%3A650%2C%22isTransparent%22%3Afalse%2C%22dateRange%22%3A%2212M%22%2C%22showSymbolLogo%22%3Atrue%2C%22utm_source%22%3A%22london-ssi.com%22%2C%22utm_medium%22%3A%22widget%22%2C%22utm_campaign%22%3A%22market-overview%22%2C%22page-uri%22%3A%22london-ssi.com%2F%22%7D" 
              title="market overview TradingView widget" 
              lang="en" 
              style={{userSelect: 'none', position: 'absolute', top: 0, left: 0, width: '100%', height: '100%', minHeight: '450px'}}>
            </iframe>
          </div>
        </div>    
    </div>

    {/* WisdomTree section */}
    <div style={{
      backgroundImage: 'linear-gradient(to right, #003366, #4b0082)',
      padding: '32px 0 48px'
    }}>
      <div className="container mx-auto px-4">
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4 md:gap-6 lg:gap-8 items-center">
            <div className="order-2 md:order-1">
              <div className="rounded-lg overflow-hidden shadow-lg w-full h-auto" style={{ minHeight: '200px' }}>
                <img
                  src="/wisdomtree-banner.png"
                  alt="WisdomTree Partnership Banner"
                  className="w-full h-full object-cover"
                  style={{ minHeight: '200px' }}
                />
              </div>
            </div>
            <div className="text-white space-y-4 order-1 md:order-2 mb-4 md:mb-0">
              <h2 className="text-2xl md:text-3xl font-bold leading-tight">
                Sở giao dịch chứng khoán London HSC và nền tảng WisdomTree ở châu Âu
              </h2>
              <p className="text-sm leading-relaxed opacity-90">
                Quỹ hoán đổi danh mục (ETF) và nhà phát hành sản phẩm giao dịch trao đổi (ETP) toàn cầu, WisdomTree, đã
                kỷ niệm một thập kỷ kinh doanh ở châu Âu tại Sở giao dịch chứng khoán London hôm nay.
              </p>
              <p className="text-sm leading-relaxed opacity-90">
                WisdomTree gia nhập thị trường châu Âu vào năm 2014, dựa trên một chiến dịch thành công ở Mỹ, nơi hoạt
                động kinh doanh ETF của nó được thành lập vào năm 2006.
              </p>
              <Button className="bg-white text-blue-900 hover:bg-gray-100 font-semibold">Tìm hiểu thêm</Button>
            </div>
          </div>
          </div>
        </div>
        
        {/* Ho Chi Minh Stock Exchange section */}
        <div style={{
      backgroundColor: '#f9f0ff',
      padding: '32px 0 48px'
    }}>
      <div className="container mx-auto px-4">
          <div className="grid grid-cols-1 md:grid-cols-2 gap-6 md:gap-8 lg:gap-12 items-center">
            <div className="space-y-6">
              <h2 className="text-xl sm:text-2xl md:text-3xl font-bold text-purple-900 leading-tight">
                Sở Giao dịch Chứng khoán Thành phố Hồ Chí Minh - Công Ty Cổ Phần Chứng Khoán TP. HCM
              </h2>
              <div className="space-y-4 text-gray-700 leading-relaxed">
                <p>
                  Theo Quyết định số 599/2007/QD-TTg của Thủ tướng Chính phủ năm 2007, Trung tâm Giao dịch Chứng khoán
                  TP.HCM được chuyển đổi thành Sở Giao dịch Chứng khoán TP.HCM, với vốn điều lệ ban đầu là 1.000 tỷ
                  đồng.
                </p>
                <p>
                  Thủ tướng Chính phủ đã ban hành Quyết định số 37/2020/QD-TTg ngày 23/12/2020 về việc thành lập Sở Giao
                  dịch Chứng khoán Việt Nam, đánh dấu một bước phát triển quan trọng trong lịch sử thị trường chứng
                  khoán Việt Nam.
                </p>
              </div>
              <Button className="bg-blue-600 hover:bg-blue-700 text-white font-semibold">Liên hệ chúng tôi</Button>
            </div>
            <div>
              <img
                src="/ss.jpg"
                alt="Ho Chi Minh City Skyline"
                className="rounded-lg shadow-xl w-full h-auto object-cover"
              />
            </div>
          </div>
          </div>
        </div>

        {/* Gallery section */}
        <div style={{
      backgroundColor: '#f9f0ff',
      padding: '32px 0'
    }}>
      <div className="container mx-auto px-4">
          <h3 className="text-xl sm:text-2xl font-bold text-center mb-4 sm:mb-8 text-purple-900">Hình ảnh hoạt động</h3>
          <div className="grid grid-cols-1 sm:grid-cols-2 md:grid-cols-3 gap-4 sm:gap-6">
            <img
              src="/gallery2.jpg"
              alt="London Stock Exchange Building"
              className="w-full h-48 object-cover rounded-lg shadow-md hover:shadow-lg transition-shadow"
            />
            <img
              src="/gallery3.jpg"
              alt="Trading Floor Activities"
              className="w-full h-48 object-cover rounded-lg shadow-md hover:shadow-lg transition-shadow"
            />
            <img
              src="/gallery4.jpg"
              alt="Financial District View"
              className="w-full h-48 object-cover rounded-lg shadow-md hover:shadow-lg transition-shadow"
            />
          </div>
          </div>
        </div>

        {/* Experts section */}
        <div style={{
      padding: '40px 0',
      backgroundColor: '#ffffff'
    }}>
      <div className="container mx-auto px-4">
          <h2 className="text-xl sm:text-2xl md:text-3xl font-bold text-center mb-6 md:mb-12 text-gray-800">
            Thông tin các chuyên gia quốc tế có chứng chỉ CFA
          </h2>
          <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-4 md:gap-6 lg:gap-8">
            {[
              {
                name: "Emmanuel Cau, CFA",
                role: "Giám đốc Sở giao dịch chứng khoán châu Âu, Barclays",
                image: "/experts/1.jpg",
              },
              {
                name: "Emmanuel CAU",
                role: "Chargé de Communication Marketing",
                image: "/experts/2.jpg",
              },
              {
                name: "MERAV OZAIR, TIẾN SĨ",
                role: "Tương lai của tài chính: AI đáp ứng được token hóa",
                image: "/experts/3.jpg",
              },
              {
                name: "Comunidade CFA – Eu me Banco",
                role: "Chuyên gia hoạt động như các nhà phân tích tài chính",
                image: "/experts/4.jpg",
              },
              {
                name: "RICHARD SAINTVILUS",
                role: "AI sáng tạo xông vào điện toán đám mây",
                image: "/experts/5.jpg",
              },
              {
                name: "RICHARD TESLA",
                role: "Tại sao ĐÃ đến lúc Mua Cổ phiếu Tesla",
                image: "/experts/6.jpg",
              },
            ].map((expert, index) => (
              <div
                key={index}
                className="flex items-start space-x-4 p-4 bg-gray-50 rounded-lg hover:bg-gray-100 transition-colors"
              >
                <img
                  src={expert.image || "/placeholder.svg"}
                  alt={expert.name}
                  className="w-16 h-16 rounded-full object-cover border-2 border-blue-200"
                />
                <div>
                  <h3 className="font-semibold text-gray-900">{expert.name}</h3>
                  <p className="text-sm text-gray-600 leading-relaxed">{expert.role}</p>
                </div>
              </div>
            ))}
          </div>
          </div>
        </div>

        {/* PhosAgro section */}
        <div className="bg-gray-50 py-12">
        <div className="container mx-auto px-4 text-center">
          <h3 className="text-2xl font-bold mb-6 text-gray-800">Sự kiện đặc biệt</h3>
          <img
            src="/phosagro-anniversary.jpg"
            alt="PhosAgro Anniversary Event"
            className="mx-auto rounded-lg shadow-lg max-w-2xl w-full"
          />
        </div>
      </div>

      {/* Footer */}
      <Footer />
    </div>
    );
}