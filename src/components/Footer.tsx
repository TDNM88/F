import { Facebook, Linkedin, Mail, MapPin, Globe, Shield, X } from 'lucide-react';
import Link from 'next/link';

export default function Footer() {
  const currentYear = new Date().getFullYear();
  
  const navigation = {
    left: [
      { name: 'Quan hệ đầu tư', href: '#' },
      { name: 'Nghề nghiệp', href: '#' },
      { name: 'Di động', href: '#' },
      { name: 'Trung tâm tin tức', href: '#' },
      { name: 'Tiện ích mở rộng của Chrome', href: '#' },
    ],
    right: [
      { name: 'Liên hệ', href: '#' },
      { name: 'Báo cáo', href: '#' },
      { name: 'Thị trường London', href: '#' },
      { name: 'Bản tin', href: '#' },
    ],
    main: [
      { name: 'Trang chủ', href: '/' },
      { name: 'Giao dịch', href: '/trade' },
      { name: 'Tài khoản', href: '/account' },
      { name: 'Lịch sử giao dịch', href: '/orders' },
      { name: 'Nạp tiền', href: '/deposit' },
      { name: 'Rút tiền', href: '/withdraw' },
    ],
    support: [
      { name: 'Hướng dẫn', href: '/help' },
      { name: 'Điều khoản', href: '/terms' },
      { name: 'Bảo mật', href: '/privacy' },
      { name: 'Liên hệ', href: '/contact' },
    ],
  };

  const social = [
    { name: 'Facebook', href: '#', icon: Facebook },
    { name: 'LinkedIn', href: '#', icon: Linkedin },
    { name: 'X', href: '#', icon: X },
    { name: 'Mail', href: 'mailto:support@londonHSC.com', icon: Mail },
  ];

  return (
    <footer className="bg-black text-gray-300">
      <div className="mx-auto max-w-7xl px-6 py-12 sm:py-16 lg:px-8">
        {/* Heading */}
        <h2 className="text-center text-blue-400 font-bold uppercase text-sm tracking-wider">
          Công Ty Cổ Phần Chứng Khoán Thành Phố Hồ Chí Minh
        </h2>
        <hr className="my-6 border-gray-700" />

        {/* Main footer grid */}
        <div className="grid grid-cols-1 md:grid-cols-3 gap-8">
          {/* Navigation lists */}
          <div className="grid grid-cols-2 gap-8 text-sm">
            <ul className="space-y-2">
              {navigation.left.map((item) => (
                <li key={item.name}>
                  <Link href={item.href} className="hover:text-white transition-colors duration-200">
                    {item.name}
                  </Link>
                </li>
              ))}
            </ul>
            <ul className="space-y-2">
              {navigation.right.map((item) => (
                <li key={item.name}>
                  <Link href={item.href} className="hover:text-white transition-colors duration-200">
                    {item.name}
                  </Link>
                </li>
              ))}
            </ul>
          </div>

          {/* Spacer for layout on md */}
          <div className="hidden md:block" />

          {/* Address section */}
          <div className="space-y-2 text-sm">
            <div className="flex items-start">
              <Shield className="h-4 w-4 text-blue-400 mt-1 mr-3" />
              <span className="leading-5 font-semibold">London - Thành Phố Hồ Chí Minh</span>
            </div>
            <div className="flex items-start">
              <MapPin className="h-4 w-4 text-blue-400 mt-1 mr-3" />
              <span className="leading-5">Tầng 5, 6 tòa nhà AB Tower, Số 76 Lê Lai, Phường Bến Thành, Quận 1 TP - HCM</span>
            </div>
            <div className="flex items-start">
              <MapPin className="h-4 w-4 text-blue-400 mt-1 mr-3" />
              <span className="leading-5">18 Patetoner Square, London ECM LS</span>
            </div>
            <div className="flex items-start">
              <Globe className="h-4 w-4 text-blue-400 mt-1 mr-3" />
              <span className="leading-5">MST : 030219050</span>
            </div>
          </div>
        </div>

        {/* Social icons */}
        <div className="mt-10 flex gap-6">
          {social.map((item) => (
            <a
              key={item.name}
              href={item.href}
              target="_blank"
              rel="noopener noreferrer"
              className="hover:text-white transition-colors duration-200"
            >
              <span className="sr-only">{item.name}</span>
              <item.icon className="h-5 w-5" aria-hidden="true" />
            </a>
          ))}
        </div>

        {/* Copyright */}
        <p className="mt-10 text-center text-xs leading-5 text-gray-400">
          Bản quyền {currentYear} HSCINC. Mọi quyền được bảo lưu.
        </p>
      </div>
    </footer>
  );
}
