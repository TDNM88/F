// Connect to MongoDB
const conn = new Mongo();
const db = conn.getDB('hsc1');  // Using the database name from your config

// Create the admin_trades collection if it doesn't exist
db.createCollection('admin_trades', {
  validator: {
    $jsonSchema: {
      bsonType: 'object',
      required: ['sessionId', 'result', 'startTime', 'endTime', 'status'],
      properties: {
        sessionId: {
          bsonType: 'string',
          description: 'must be a string and is required'
        },
        result: {
          enum: ['UP', 'DOWN'],
          description: 'can only be UP or DOWN and is required'
        },
        startTime: {
          bsonType: 'date',
          description: 'must be a date and is required'
        },
        endTime: {
          bsonType: 'date',
          description: 'must be a date and is required'
        },
        status: {
          enum: ['active', 'completed'],
          description: 'can only be active or completed and is required'
        },
        createdAt: {
          bsonType: 'date',
          description: 'must be a date'
        },
        updatedAt: {
          bsonType: 'date',
          description: 'must be a date'
        }
      }
    }
  }
});

// Create an index on sessionId for faster lookups
db.admin_trades.createIndex({ sessionId: 1 }, { unique: true });

print('Database and collection initialized successfully');