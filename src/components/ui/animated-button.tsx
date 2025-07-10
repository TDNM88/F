"use client"

import * as React from "react"
import { cn } from "@/lib/utils"
import { Button } from "./button"
import { motion } from "framer-motion"

interface AnimatedButtonProps extends React.ComponentProps<typeof Button> {
  children: React.ReactNode
}

export function AnimatedButton({ children, className, ...props }: AnimatedButtonProps) {
  return (
    <motion.div
      whileHover={{ scale: 1.05 }}
      whileTap={{ scale: 0.95 }}
      transition={{ duration: 0.2 }}
    >
      <Button className={cn(className)} {...props}>
        {children}
      </Button>
    </motion.div>
  )
}
