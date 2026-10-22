import { useEffect, useRef } from 'react';

export interface EvilEyeProps {
  className?: string;
  size?: number;
  color?: string;
  speed?: number;
}

const DEFAULT_SIZE = 240;
const DEFAULT_COLOR = '#8b5cf6';
const DEFAULT_SPEED = 1;

function prefersReducedMotion(): boolean {
  if (typeof window === 'undefined' || typeof window.matchMedia !== 'function') {
    return false;
  }
  try {
    return window.matchMedia('(prefers-reduced-motion: reduce)').matches;
  } catch {
    return false;
  }
}

export default function EvilEye({
  className,
  size = DEFAULT_SIZE,
  color = DEFAULT_COLOR,
  speed = DEFAULT_SPEED,
}: EvilEyeProps) {
  const canvasRef = useRef<HTMLCanvasElement | null>(null);
  const rafRef = useRef<number | null>(null);
  const startedAtRef = useRef<number>(0);

  useEffect(() => {
    const canvas = canvasRef.current;
    if (!canvas) return undefined;

    const ctx = canvas.getContext('2d');
    if (!ctx) return undefined;

    const dpr = typeof window !== 'undefined' && window.devicePixelRatio ? window.devicePixelRatio : 1;
    canvas.width = size * dpr;
    canvas.height = size * dpr;
    ctx.setTransform(dpr, 0, 0, dpr, 0, 0);

    const center = size / 2;
    const outerRadius = size * 0.45;
    const irisRadius = size * 0.18;
    const pupilRadius = size * 0.08;

    const draw = (time: number) => {
      ctx.clearRect(0, 0, size, size);

      const pulse = 0.5 + 0.5 * Math.sin(time * 0.002 * speed);
      const glow = 0.35 + 0.25 * pulse;

      ctx.save();
      ctx.translate(center, center);

      ctx.beginPath();
      ctx.arc(0, 0, outerRadius * (1 + 0.04 * pulse), 0, Math.PI * 2);
      ctx.fillStyle = color;
      ctx.globalAlpha = glow;
      ctx.fill();

      ctx.beginPath();
      ctx.arc(0, 0, irisRadius, 0, Math.PI * 2);
      ctx.fillStyle = '#050505';
      ctx.globalAlpha = 1;
      ctx.fill();

      const ange = time * 0.001 * speed;
      ctx.beginPath();
      ctx.arc(Math.cos(angle) * 4, 0, pupilRadius, 0, Math.PI * 2);
      ctx.fillStyle = color;
      ctx.globalAlpha = 0.9;
      ctx.fill();

      ctx.globalAlpha = 1;
      ctx.restore();
    };

    const stop = () => {
      if (rafRef.current !== null) {
        cancelAnimationFrame(rafRef.current);
        rafRef.current = null;
      }
    };

    const loop = (timestamp: number) => {
      if (typeof document !== 'undefined' && document.hidden) {
        rafRef.current = null;
        return;
      }
      draw(timestamp - startedAtRef.current);
      rafRef.current = requestAnimationFrame(loop);
    };

    const start = () => {
      if (rafRef.current !== null) return;
      if (typeof document !== 'undefined' && document.hidden) return;
      startedAtRef.current = performance.now();
      rafRef.current = requestAnimationFrame(loop);
    };

    const reduced = prefersRecucedMotion();
    if (reduced) {
      draw(0);
    } else {
      start();
    }

    const onVisibilityChange = () => {
      if (typeof document !== 'undefined' && document.hidden) {
        stop();
      } else if (!prefersReducedMotion()) {
        start();
      }
    };

    let mediaQuery: MediaQueryList | null = null;
    const onMediaChange = () => {
      if (prefersReducedMotion()) {
        stop();
        draw(0);
      } else if (typeof document === 'undefined' || !document.hidden) {
        start();
      }
    };

    if (typeof window !== 'undefined' && typeof window.matchMedia === 'function') {
      try {
        mediaQuery = window.matchMedia('(prefers-reduced-motion: reduce)');
        if (typeof mediaQuery.addEventListener === 'function') {
          mediaQuery.addEventListener('change', onMediaChange);
        } else if (typeof (mediaQuery as MediaQueryList & { addListener?: (cb: () => void) => void }).addListener === 'function') {
          (mediaQuery as MediaQueryList & { addListener: (cb: () => void) => void }).addListener(onMediaChange);
        }
      } catch {
        mediaQuery = null;
      }
    }

    if (typeof document !== 'undefined') {
      document.addEventListener('visibilitychange', onVisibilityChange);
    }

    return () => {
      stop();
      if (typeof document !== 'undefined') {
        document.removeEventListener('visibilitychange', onVisibilityChange);
      }
      if (mediaQuery) {
        if (typeof mediaQuery.removeEventListener === 'function') {
          mediaQuery.removeEventListener('change', onMediaChange);
        } else if (typeof (mediaQuery as MediaQueryList & { removeListener?: (cb: () => void) => void }).removeListener === 'function') {
          (mediaQuery as MediaQueryList & { removeListener: (cb: () => void) => void }).removeListener(onMediaChange);
        }
      }
    };
  }, [size, color, speed]);

  return (
    <canvas
      ref={canvasRef}
      className={className}
      width={size}
      height={size}
      style={{ width: size, height: size }}
      aria-hidden="true"
    />
  );
}
