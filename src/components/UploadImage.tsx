"use client"

import React, { useRef, useState } from "react"
import { Button } from "@/components/ui/button"
import { Input } from "@/components/ui/input"
import { Label } from "@/components/ui/label"
import { useToast } from "@/components/ui/use-toast"
import { Upload, X } from "lucide-react"
import Image from "next/image"

export interface UploadFile {
  uid: string
  name: string
  status?: 'uploading' | 'done' | 'error' | 'removed'
  url?: string
  response?: any
}

interface UploadImageProps {
  onChange: (fileList: UploadFile[]) => void
  maxCount?: number
}

const UploadImage: React.FC<UploadImageProps> = ({ 
  onChange, 
  maxCount = 1 
}) => {
  const fileInputRef = useRef<HTMLInputElement>(null)
  const [fileList, setFileList] = useState<UploadFile[]>([])
  const [isUploading, setIsUploading] = useState(false)
  const { toast } = useToast()

  const handleUpload = async (file: File) => {
    if (!file) return

    const newFile: UploadFile = {
      uid: `rc-upload-${Date.now()}`,
      name: file.name,
      status: 'uploading',
    }

    setFileList([newFile])
    onChange([{ ...newFile }])
    setIsUploading(true)

    try {
      // Lấy token từ localStorage hoặc context người dùng
      const token = localStorage.getItem('token') || ''
      
      // Sử dụng API upload để tải file lên Vercel Blob
      const formData = new FormData()
      formData.append("file", file)

      const response = await fetch("/api/upload", {
        method: "POST",
        headers: {
          'Authorization': `Bearer ${token}`,
        },
        body: formData,
      })

      if (!response.ok) {
        throw new Error(`HTTP error! status: ${response.status}`)
      }

      const data = await response.json()

      const uploadedFile: UploadFile = {
        ...newFile,
        status: 'done',
        url: data.url,
        response: data,
      }

      setFileList([uploadedFile])
      onChange([{ ...uploadedFile }])
      
      toast({
        title: "Thành công",
        description: "Tải ảnh lên thành công",
      })
    } catch (error) {
      console.error("Upload failed:", error)
      const errorFile: UploadFile = {
        ...newFile,
        status: 'error',
      }
      setFileList([errorFile])
      onChange([{ ...errorFile }])
      
      toast({
        variant: "destructive",
        title: "Lỗi",
        description: "Tải ảnh lên thất bại. Vui lòng thử lại.",
      })
    } finally {
      setIsUploading(false)
    }
  }

  const handleFileChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0]
    if (file) {
      handleUpload(file)
    }
    // Reset the input value to allow selecting the same file again
    if (fileInputRef.current) {
      fileInputRef.current.value = ''
    }
  }

  const handleRemove = (e: React.MouseEvent) => {
    e.stopPropagation()
    setFileList([])
    onChange([])
  }

  const renderUploadButton = () => (
    <div className="flex flex-col items-center justify-center p-6 border-2 border-dashed rounded-md border-gray-300 dark:border-gray-700">
      <Upload className="w-6 h-6 mb-2 text-gray-400" />
      <p className="text-sm text-gray-500 dark:text-gray-400">
        <span className="font-medium text-blue-600 hover:text-blue-500 dark:text-blue-400 dark:hover:text-blue-300">
          Tải lên
        </span>{' '}
        hoặc kéo thả ảnh vào đây
      </p>
      <p className="text-xs text-gray-500 dark:text-gray-400">
        Hỗ trợ: JPG, PNG (Tối đa 5MB)
      </p>
    </div>
  )

  const renderFilePreview = (file: UploadFile) => {
    if (file.status === 'uploading') {
      return (
        <div className="relative p-4 border rounded-md border-gray-200 dark:border-gray-700">
          <div className="flex items-center justify-center h-32 bg-gray-100 dark:bg-gray-800 rounded">
            <div className="animate-pulse flex flex-col items-center">
              <div className="h-4 w-32 bg-gray-300 dark:bg-gray-600 rounded mb-2"></div>
              <div className="text-sm text-gray-500 dark:text-gray-400">Đang tải lên...</div>
            </div>
          </div>
        </div>
      )
    }

    if (file.status === 'error') {
      return (
        <div className="relative p-4 border border-red-200 dark:border-red-900 bg-red-50 dark:bg-red-950/30 rounded-md">
          <div className="flex items-center justify-center h-32 bg-red-100 dark:bg-red-900/20 rounded">
            <div className="text-center">
              <div className="text-red-600 dark:text-red-400 font-medium">Lỗi khi tải lên</div>
              <Button 
                variant="outline" 
                size="sm" 
                className="mt-2"
                onClick={() => setFileList([])}
              >
                Thử lại
              </Button>
            </div>
          </div>
        </div>
      )
    }

    return (
      <div className="relative group">
        <div className="relative w-full h-32 overflow-hidden rounded-md">
          <Image
            src={file.url || ''}
            alt={file.name}
            fill
            className="object-cover"
            sizes="(max-width: 768px) 100vw, 50vw"
          />
        </div>
        <Button
          type="button"
          variant="ghost"
          size="icon"
          className="absolute top-2 right-2 h-8 w-8 rounded-full bg-black/50 text-white hover:bg-black/70"
          onClick={handleRemove}
        >
          <X className="h-4 w-4" />
          <span className="sr-only">Xóa ảnh</span>
        </Button>
      </div>
    )
  }

  return (
    <div className="space-y-2">
      <Label htmlFor="upload">Tải ảnh lên</Label>
      <div className="relative">
        <Input
          id="upload"
          ref={fileInputRef}
          type="file"
          accept="image/*"
          className="sr-only"
          onChange={handleFileChange}
          disabled={isUploading || (maxCount > 0 && fileList.length >= maxCount)}
        />
        <Label 
          htmlFor="upload" 
          className={`block cursor-pointer ${isUploading ? 'opacity-50 cursor-not-allowed' : ''}`}
        >
          {fileList.length > 0 ? (
            renderFilePreview(fileList[0])
          ) : (
            renderUploadButton()
          )}
        </Label>
      </div>
    </div>
  )
}

export default UploadImage
