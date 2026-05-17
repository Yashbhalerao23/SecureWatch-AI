import React from 'react';
import { motion, AnimatePresence } from 'framer-motion';

export interface DialogProps {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  title: string;
  description?: string;
  children: React.ReactNode;
  size?: 'sm' | 'md' | 'lg' | 'xl';
  footer?: React.ReactNode;
}

const sizeClasses = {
  sm: 'max-w-sm',
  md: 'max-w-md',
  lg: 'max-w-lg',
  xl: 'max-w-xl',
};

const Dialog: React.FC<DialogProps> = ({
  open,
  onOpenChange,
  title,
  description,
  children,
  size = 'md',
  footer,
}) => {
  React.useEffect(() => {
    if (open) {
      document.body.style.overflow = 'hidden';
    } else {
      document.body.style.overflow = 'unset';
    }
    return () => {
      document.body.style.overflow = 'unset';
    };
  }, [open]);

  const handleEscape = (e: KeyboardEvent) => {
    if (e.key === 'Escape' && open) {
      onOpenChange(false);
    }
  };

  React.useEffect(() => {
    window.addEventListener('keydown', handleEscape);
    return () => window.removeEventListener('keydown', handleEscape);
  }, [open]);

  return (
    <AnimatePresence>
      {open && (
        <>
          <motion.div
            className="fixed inset-0 z-40 bg-slate-950/50 backdrop-blur-sm"
            onClick={() => onOpenChange(false)}
            initial={{ opacity: 0 }}
            animate={{ opacity: 1 }}
            exit={{ opacity: 0 }}
          />
          <motion.div
            className="fixed inset-0 z-50 flex items-center justify-center p-4"
            initial={{ opacity: 0, scale: 0.95 }}
            animate={{ opacity: 1, scale: 1 }}
            exit={{ opacity: 0, scale: 0.95 }}
          >
            <div
              className={`w-full ${sizeClasses[size]} rounded-3xl border border-soc-border bg-slate-950/95 shadow-lg`}
              onClick={(e) => e.stopPropagation()}
            >
              <div className="border-b border-soc-border p-6">
                <h2 className="text-xl font-semibold text-white">{title}</h2>
                {description && (
                  <p className="mt-1 text-sm text-slate-400">{description}</p>
                )}
              </div>
              <div className="max-h-[calc(100vh-16rem)] overflow-y-auto p-6">
                {children}
              </div>
              {footer && (
                <div className="border-t border-soc-border bg-slate-900/50 p-6">
                  {footer}
                </div>
              )}
            </div>
          </motion.div>
        </>
      )}
    </AnimatePresence>
  );
};

export default Dialog;
