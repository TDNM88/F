// scripts/seed-trading-sessions.ts
const { MongoClient } = require('mongodb');
require('dotenv').config();
// MongoDB connection string
const MONGODB_URI = process.env.MONGODB_URI;
const DB_NAME = process.env.MONGODB_DB || 'hsc1';
if (!MONGODB_URI) {
    throw new Error('Please define the MONGODB_URI environment variable');
}
// Function to generate a random session ID based on date
function generateSessionId(date) {
    const year = date.getFullYear().toString().slice(-2);
    const month = (date.getMonth() + 1).toString().padStart(2, '0');
    const day = date.getDate().toString().padStart(2, '0');
    const hours = date.getHours().toString().padStart(2, '0');
    const minutes = date.getMinutes().toString().padStart(2, '0');
    return `${year}${month}${day}${hours}${minutes}`;
}
// Function to generate random trading sessions
async function generateTradingSessions() {
    const client = new MongoClient(MONGODB_URI);
    try {
        await client.connect();
        console.log('Connected to MongoDB');
        const db = client.db(DB_NAME);
        const collection = db.collection('admin_trades');
        // Clear existing sessions (optional)
        // await collection.deleteMany({});
        const sessions = [];
        const now = new Date();
        // Generate 30 sessions, one for each day in the past month
        for (let i = 0; i < 30; i++) {
            const sessionDate = new Date(now);
            sessionDate.setDate(now.getDate() - (29 - i)); // Last 30 days
            // Generate random start time between 8:00 and 22:00
            const startHour = 8 + Math.floor(Math.random() * 14); // 8-22
            const startMinute = Math.floor(Math.random() * 60);
            const startTime = new Date(sessionDate);
            startTime.setHours(startHour, startMinute, 0, 0);
            // Session lasts between 1-5 minutes
            const durationMinutes = 1 + Math.floor(Math.random() * 5);
            const endTime = new Date(startTime.getTime() + durationMinutes * 60000);
            // Random result (UP or DOWN)
            const result = Math.random() > 0.5 ? 'UP' : 'DOWN';
            // Generate session ID
            const sessionId = generateSessionId(startTime);
            sessions.push({
                sessionId,
                result,
                startTime: startTime.toISOString(),
                endTime: endTime.toISOString(),
                status: 'completed',
                createdAt: new Date().toISOString(),
                updatedAt: new Date().toISOString()
            });
        }
        // Insert sessions
        if (sessions.length > 0) {
            const result = await collection.insertMany(sessions);
            console.log(`Successfully inserted ${result.insertedCount} trading sessions`);
        }
    }
    catch (error) {
        console.error('Error generating trading sessions:', error);
    }
    finally {
        await client.close();
        console.log('MongoDB connection closed');
    }
}
// Run the script
generateTradingSessions().catch(console.error);
