import type { Metadata, Viewport } from 'next';

export const viewport: Viewport = {
  themeColor: '#ffffff',
  // Các thuộc tính viewport sẽ được xử lý qua thẻ meta viewport
};

export const metadata: Metadata = {
  title: 'BẢN FULL',
  description: 'NHẬN THANH TOÁN -> XÓA CHỮ THỪA',
  metadataBase: new URL(process.env.NEXT_PUBLIC_APP_URL || 'http://localhost:3000'),
  openGraph: {
    title: 'BẢN FULL',
    description: 'NHẬN THANH TOÁN -> XÓA CHỮ THỪA',
    url: process.env.NEXT_PUBLIC_APP_URL,
    siteName: 'Trading Platform',
    locale: 'vi_VN',
    type: 'website',
  },
  twitter: {
    card: 'summary_large_image',
    title: 'Trading Platform',
    description: 'Nền tảng giao dịch trực tuyến',
  },
  robots: {
    index: true,
    follow: true,
    googleBot: {
      index: true,
      follow: true,
      'max-video-preview': -1,
      'max-image-preview': 'large',
      'max-snippet': -1,
    },
  },
  icons: {
    icon: '/favicon.ico',
    apple: '/apple-touch-icon.png',
  },
  manifest: '/site.webmanifest',
};
