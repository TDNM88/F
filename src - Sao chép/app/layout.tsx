import type { Metadata, Viewport } from 'next';
import { Inter } from 'next/font/google';
import './globals.css';

const inter = Inter({ subsets: ['latin'] });

// Viewport configuration
export const viewport: Viewport = {
  // Only supported properties in Next.js Viewport type
  themeColor: '#ffffff',
  // Viewport meta tag will be handled by the meta tag in the head
};

// Minimal metadata configuration
export const metadata: Metadata = {
  metadataBase: new URL(process.env.NEXT_PUBLIC_APP_URL || 'http://localhost:3000'),
  manifest: '/site.webmanifest',
  other: {
    'msapplication-TileColor': '#ffffff',
  },
};

import ClientLayout from './ClientLayout';

// This is the root layout - required for all pages
export default function RootLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  // Don't render html/body here for admin routes
  if (process.env.NEXT_PHASE !== 'phase-production-build' && 
      typeof window !== 'undefined' && 
      window.location.pathname.startsWith('/admin')) {
    return <>{children}</>;
  }

  // For all other routes, use the default layout
  return (
    <html lang="en" suppressHydrationWarning>
      <head>
        <meta name="viewport" content="width=device-width, initial-scale=1, maximum-scale=1, user-scalable=no" />
      </head>
      <body className={inter.className}>
        <ClientLayout>
          {children}
        </ClientLayout>
      </body>
    </html>
  );
}