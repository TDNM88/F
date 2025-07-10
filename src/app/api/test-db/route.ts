import { NextResponse } from 'next/server';
import { getMongoDb } from '@/lib/db';

export async function GET() {
  try {
    console.log('Testing MongoDB connection...');
    const db = await getMongoDb();
    
    if (!db) {
      console.error('Failed to get MongoDB connection');
      return NextResponse.json(
        { success: false, message: 'Failed to connect to database' },
        { status: 500 }
      );
    }
    
    // Test the connection by getting server info
    const adminDb = db.admin();
    const serverStatus = await adminDb.serverStatus();
    
    // Get list of collections
    const collections = await db.listCollections().toArray();
    
    return NextResponse.json({
      success: true,
      serverStatus: {
        version: serverStatus.version,
        host: serverStatus.host,
        process: serverStatus.process,
      },
      collections: collections.map(c => c.name),
      stats: {
        collections: collections.length,
      }
    });
    
  } catch (error: any) {
    console.error('Database test error:', error);
    
    let errorMessage = 'Database connection failed';
    if (error.name === 'MongoServerError') {
      errorMessage = 'MongoDB server error';
    } else if (error.name === 'MongoNetworkError') {
      errorMessage = 'Could not connect to MongoDB server';
    }
    
    return NextResponse.json(
      { 
        success: false, 
        message: errorMessage,
        error: process.env.NODE_ENV === 'development' ? error.message : undefined
      },
      { status: 500 }
    );
  }
}
