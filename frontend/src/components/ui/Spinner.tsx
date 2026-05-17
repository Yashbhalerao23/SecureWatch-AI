import React from 'react';
import { motion } from 'framer-motion';

export interface SpinnerProps {
  size?: 'sm' | 'md' | 'lg';
  text?: string;
  fullScreen?: boolean;
}

const sizeClasses = {
  sm: 'w-6 h-6',
  md: 'w-10 h-10',
  lg: 'w-16 h-16',
};

const Spinner: React.FC<SpinnerProps> = ({ size = 'md', text, fullScreen = false }) => {
  const spinner = (
    <div className="flex flex-col items-center gap-3">
      <motion.div
        className={`rounded-full border-3 border-slate-600 border-t-soc-accent ${sizeClasses[size]}`}
        animate={{ rotate: 360 }}
        transition={{ duration: 1, repeat: Infinity, easing: 'linear' }}
      />
      {text && <p className="text-sm text-slate-400">{text}</p>}
    </div>
  );

  if (fullScreen) {
    return (
      <div className="fixed inset-0 z-50 flex items-center justify-center bg-slate-950/50 backdrop-blur-sm">
        {spinner}
      </div>
    );
  }

  return spinner;
};

export default Spinner;
