import { NextResponse } from 'next/server';
import { getToken } from 'next-auth/jwt';
import { connectToDatabase } from '@/lib/db';
import SiteSettings from '@/models/SiteSettings';
import { Types } from 'mongoose';

export async function GET() {
  try {
    await connectToDatabase();
    const settings = await SiteSettings.findOne({}).lean();
    
    // If no settings exist, create default settings
    if (!settings) {
      const defaultSettings = await SiteSettings.create({
        telegramSupport: 'https://t.me/your_support_username'
      });
      return NextResponse.json({ settings: defaultSettings });
    }
    
    return NextResponse.json({ settings });
  } catch (error) {
    console.error('Error fetching site settings:', error);
    return NextResponse.json(
      { error: 'Internal server error' },
      { status: 500 }
    );
  }
}

export async function PUT(request: Request) {
  try {
    const token = await getToken({ req: request as any });
    
    if (!token) {
      return NextResponse.json(
        { error: 'Unauthorized' },
        { status: 401 }
      );
    }
    
    const { telegramSupport } = await request.json();
    
    if (!telegramSupport) {
      return NextResponse.json(
        { error: 'Telegram support link is required' },
        { status: 400 }
      );
    }
    
    await connectToDatabase();
    
    // Update or create settings
    const settings = await SiteSettings.findOneAndUpdate(
      {},
      { 
        telegramSupport,
        updatedBy: new Types.ObjectId(token.sub)
      },
      { 
        new: true,
        upsert: true,
        setDefaultsOnInsert: true 
      }
    );
    
    return NextResponse.json({ 
      message: 'Settings updated successfully',
      settings 
    });
    
  } catch (error) {
    console.error('Error updating site settings:', error);
    return NextResponse.json(
      { error: 'Internal server error' },
      { status: 500 }
    );
  }
}
