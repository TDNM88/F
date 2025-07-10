import { TradeHistoryRecord } from './page';

/**
 * Creates a new trade record
 */
export const createTradeRecord = ({
  id,
  sessionId,
  direction,
  amount,
  status = 'pending',
  result = null,
  profit = 0,
}: {
  id: string;
  sessionId: string;
  direction: 'UP' | 'DOWN';
  amount: number;
  status?: 'pending' | 'win' | 'lose';
  result?: 'win' | 'lose' | null;
  profit?: number;
}): TradeHistoryRecord => ({
  id,
  session: parseInt(sessionId.slice(-4)),
  direction,
  amount,
  status,
  result,
  profit,
  createdAt: new Date().toISOString(),
});

/**
 * Updates a trade record with new data
 */
export const updateTradeRecord = (
  trade: TradeHistoryRecord,
  updates: Partial<TradeHistoryRecord>
): TradeHistoryRecord => ({
  ...trade,
  ...updates,
  updatedAt: new Date().toISOString(),
});

/**
 * Validates if an object is a valid trade record
 */
export const isValidTradeRecord = (trade: any): trade is TradeHistoryRecord => {
  return (
    trade &&
    typeof trade.id === 'string' &&
    typeof trade.session === 'number' &&
    ['UP', 'DOWN'].includes(trade.direction) &&
    typeof trade.amount === 'number' &&
    ['pending', 'win', 'lose'].includes(trade.status) &&
    (trade.result === null || trade.result === 'win' || trade.result === 'lose') &&
    typeof trade.profit === 'number' &&
    typeof trade.createdAt === 'string'
  );
};

/**
 * Formats a number as currency
 */
export const formatCurrency = (value: number): string => {
  return new Intl.NumberFormat('vi-VN', {
    style: 'currency',
    currency: 'VND',
    minimumFractionDigits: 0,
  }).format(value);
};

/**
 * Calculates the profit for a trade
 */
export const calculateProfit = (
  amount: number,
  result: 'win' | 'lose' | null,
  multiplier = 1.9
): number => {
  if (!result) return 0;
  return result === 'win' ? amount * (multiplier - 1) : -amount;
};
