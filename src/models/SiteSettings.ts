import mongoose, { Document, Schema } from 'mongoose';

interface ISiteSettings extends Document {
  telegramSupport: string;
  updatedAt: Date;
  updatedBy: mongoose.Types.ObjectId;
}

const siteSettingsSchema = new Schema<ISiteSettings>({
  telegramSupport: { 
    type: String, 
    required: true,
    default: 'https://t.me/your_support_username'
  },
  updatedAt: { type: Date, default: Date.now },
  updatedBy: { type: Schema.Types.ObjectId, ref: 'User' }
}, { timestamps: true });

// Create a singleton document
siteSettingsSchema.statics.getSettings = async function() {
  let settings = await this.findOne({});
  if (!settings) {
    settings = await this.create({});
  }
  return settings;
};

export default mongoose.models.SiteSettings || 
  mongoose.model<ISiteSettings>('SiteSettings', siteSettingsSchema);
