import 'next-auth';

declare module 'next-auth' {
  interface User {
    id: string;
    email: string;
    name: string;
    isAdmin: boolean;
    balance: number;
  }

  interface Session {
    user: User;
  }
}
