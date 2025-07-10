'use client';

import { useState } from 'react';
import Link from 'next/link';

export default function NavMenu() {
  const [isMenuOpen, setIsMenuOpen] = useState(false);

  const toggleMenu = () => {
    setIsMenuOpen(!isMenuOpen);
  };

  return (
    <>
      <nav className="hidden md:flex">
        <ul className="flex space-x-6">
          <li>
            <Link href="/" className="hover:underline">Trang chủ</Link>
          </li>
          <li>
            <Link href="/account" className="hover:underline">Tài khoản</Link>
          </li>
          <li>
            <Link href="/deposit" className="hover:underline">Nạp tiền</Link>
          </li>
          <li>
            <Link href="/trade" className="hover:underline">Giao dịch</Link>
          </li>
          <li>
            <Link href="/register" className="hover:underline">Đăng ký</Link>
          </li>
          <li>
            <Link href="/login" className="hover:underline">Đăng nhập</Link>
          </li>
        </ul>
      </nav>
      <button className="md:hidden" onClick={toggleMenu}>
        <svg className="w-6 h-6" fill="none" stroke="currentColor" viewBox="0 0 24 24">
          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M4 6h16M4 12h16M4 18h16" />
        </svg>
      </button>
      {isMenuOpen && (
        <nav className="md:hidden bg-[#0b0033] p-4">
          <ul className="flex flex-col space-y-4">
            <li>
              <Link href="/" className="hover:underline" onClick={toggleMenu}>Trang chủ</Link>
            </li>
            <li>
              <Link href="/account" className="hover:underline" onClick={toggleMenu}>Tài khoản</Link>
            </li>
            <li>
              <Link href="/deposit" className="hover:underline" onClick={toggleMenu}>Nạp tiền</Link>
            </li>
            <li>
              <Link href="/trade" className="hover:underline" onClick={toggleMenu}>Giao dịch</Link>
            </li>
            <li>
              <Link href="/register" className="hover:underline" onClick={toggleMenu}>Đăng ký</Link>
            </li>
            <li>
              <Link href="/login" className="hover:underline" onClick={toggleMenu}>Đăng nhập</Link>
            </li>
          </ul>
        </nav>
      )}
    </>
  );
}
