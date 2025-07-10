'use client';

import { Dialog, DialogContent, DialogHeader, DialogTitle } from '@/components/ui/dialog';
import Image from 'next/image';

interface VerificationImageModalProps {
  isOpen: boolean;
  onClose: () => void;
  frontImage: string;
  backImage: string;
  userName: string;
}

export function VerificationImageModal({
  isOpen,
  onClose,
  frontImage,
  backImage,
  userName
}: VerificationImageModalProps) {
  return (
    <Dialog open={isOpen} onOpenChange={onClose}>
      <DialogContent className="max-w-4xl">
        <DialogHeader>
          <DialogTitle>Xác minh CCCD/CMND - {userName}</DialogTitle>
        </DialogHeader>
        
        <div className="grid grid-cols-1 md:grid-cols-2 gap-4 mt-4">
          <div className="space-y-2">
            <h3 className="font-medium">Mặt trước</h3>
            <div className="relative w-full h-64 bg-gray-100 dark:bg-gray-800 rounded-lg overflow-hidden">
              <Image
                src={frontImage}
                alt="Mặt trước CCCD/CMND"
                fill
                className="object-contain"
              />
            </div>
          </div>
          
          <div className="space-y-2">
            <h3 className="font-medium">Mặt sau</h3>
            <div className="relative w-full h-64 bg-gray-100 dark:bg-gray-800 rounded-lg overflow-hidden">
              <Image
                src={backImage}
                alt="Mặt sau CCCD/CMND"
                fill
                className="object-contain"
              />
            </div>
          </div>
        </div>
        
        <div className="mt-4 flex justify-end">
          <button
            type="button"
            onClick={onClose}
            className="px-4 py-2 text-sm font-medium text-gray-700 dark:text-gray-300 bg-gray-100 dark:bg-gray-700 rounded-md hover:bg-gray-200 dark:hover:bg-gray-600"
          >
            Đóng
          </button>
        </div>
      </DialogContent>
    </Dialog>
  );
}
