#!/bin/bash

# Install required shadcn/ui components
npx shadcn-ui@latest add alert
npx shadcn-ui@latest add avatar

# Fix the logout page by removing the non-existent import
sed -i "s/import { clearAuthSession } from '@/lib\/simple-auth'//g" src/app/logout/page.tsx
