import React from 'react';
import { TradeHistoryRecord } from './page';

interface TradeHistoryProps {
  trades: TradeHistoryRecord[];
  formatCurrency?: (value: number) => string;
}

export const TradeHistory: React.FC<TradeHistoryProps> = ({ 
  trades = [],
  formatCurrency = (value: number) => value.toString() 
}) => {
  if (trades.length === 0) {
    return (
      <div className="text-center py-4 text-gray-500">
        Chưa có giao dịch nào
      </div>
    );
  }

  return (
    <div className="mt-4">
      <div className="overflow-x-auto">
        <table className="min-w-full divide-y divide-gray-200">
          <thead className="bg-gray-50">
            <tr>
              <th scope="col" className="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                Phiên
              </th>
              <th scope="col" className="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                Lệnh
              </th>
              <th scope="col" className="px-4 py-3 text-right text-xs font-medium text-gray-500 uppercase tracking-wider">
                Số tiền
              </th>
              <th scope="col" className="px-4 py-3 text-right text-xs font-medium text-gray-500 uppercase tracking-wider">
                Kết quả
              </th>
              <th scope="col" className="px-4 py-3 text-right text-xs font-medium text-gray-500 uppercase tracking-wider">
                Lợi nhuận
              </th>
            </tr>
          </thead>
          <tbody className="bg-white divide-y divide-gray-200">
            {trades.map((trade) => (
              <tr key={trade.id} className="hover:bg-gray-50">
                <td className="px-4 py-3 whitespace-nowrap text-sm font-medium text-gray-900">
                  {trade.sessionId}
                </td>
                <td className="px-4 py-3 whitespace-nowrap">
                  <span 
                    className={`inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium ${
                      trade.direction === 'UP' 
                        ? 'bg-green-100 text-green-800' 
                        : 'bg-red-100 text-red-800'
                    }`}
                  >
                    {trade.direction === 'UP' ? 'TĂNG' : 'GIẢM'}
                  </span>
                </td>
                <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-500">
                  {formatCurrency(trade.amount)}
                </td>
                <td className="px-4 py-3 whitespace-nowrap text-sm text-right">
                  {trade.status === 'pending' ? (
                    <span className="px-2 inline-flex text-xs leading-5 font-semibold rounded-full bg-yellow-100 text-yellow-800">
                      Đang chờ
                    </span>
                  ) : trade.result === 'win' ? (
                    <span className="px-2 inline-flex text-xs leading-5 font-semibold rounded-full bg-green-100 text-green-800">
                      Thắng
                    </span>
                  ) : (
                    <span className="px-2 inline-flex text-xs leading-5 font-semibold rounded-full bg-red-100 text-red-800">
                      Thua
                    </span>
                  )}
                </td>
                <td className="px-4 py-3 whitespace-nowrap text-sm text-right">
                  <span className={`font-medium ${
                    trade.profit > 0 
                      ? 'text-green-600' 
                      : trade.profit < 0 
                        ? 'text-red-600' 
                        : 'text-gray-900'
                  }`}>
                    {trade.profit > 0 ? '+' : ''}{trade.profit.toLocaleString()} VNĐ
                  </span>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
};
