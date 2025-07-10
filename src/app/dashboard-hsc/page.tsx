"use client";

// Import the default export from the admin page
import dynamic from 'next/dynamic';

// Dynamically import the AdminDashboard component with SSR disabled
const AdminDashboard = dynamic(
  () => import('@/app/(admin)/admin/page'),
  { ssr: false }
);

export default function DashboardHSC() {
  return <AdminDashboard />;
}
