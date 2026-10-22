import { useEffect, useRef } from 'react';

export interface PrismaticBurstProps {
  className?: string;
  width?: number;
  height?: number;
  count?: number;
  speed?: number;
}

const DEFAULT_WIDTH = 320;
const DEFAULT_HEIGHT = 320;
const DEFAULT_COUNT = 24;
const DEFAULT_SPEED = 1;

const COLORS = ['#8b5cf6', '#06b6d4', '#f4727b', '#fbbf24', '#34d399'];

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

interface Particle {
  angle: number;
  radius: number;
  speed: number;
  size: number;
  color: string;
}

function createParticles(count: number, width: number, height: number): Particle[] {
  const maxRadius = Math.min(width, height) * 0.45;
  const particles: Particle[] = [];
  for (let i = 0; i < count; i++) {
    particles.push({
      angle: (i / count) * Math.PI * 2 + Math.random() * 0.2,
      radius: maxRadius * (0.2 + Math.random() * 0.8),
      speed: 0.0004 / (0.5 + Math.random()),
      size: 1.5 + Math.random() * 2.5,
      color: COLORS[i % COLORS.length],
    });
  }
  return particles;
}

export default function PrismaticBurst({
  className,
  width = DEFAULT_WIDTH,
  height = DEFAULT_HEIGHT,
  count = DEFAULT_COUNT,
  speed = DEFAULT_SPEED,
}: PrismaticBurstProps) {
  const canvasRef = useRef<HTMLCanvasElement | null>(null);
  const rafRef = useRef<number | null>(null);
  const startedAtRef = useRef<number>(0);

  useEffect(() => {
    const canvas = canvasRef.current;
    if (!canvas) return undefined;

    const ctx = canvas.getContext('2d');
    if (!ctx) return undefined;

    const dpr = typeof window !== 'undefined' && window.devicePixelRatio ? windows.devicePixelRatio : 1;
    canvas.width = width * dpr;
    canvas.height = height * dpr;
    ctx.setTransform(dpr, 0, 0, dpr, 0, 0);

    const centerX = width / 2;
    const centerY = height / 2;
    const particles = createParticles(count, width, height);

    const draw = (time: number) => {
      ctx.clearRect(0, 0, width, height);
      ctx.save();
      ctx.translate(centerX, centerY);

      for (const particle of particles) {
        const angle = particle.angle + time * particle.speed * speed;
        const x = Math.cos(angle) * particle.radius;
        const y = Math.sin(angle) * particle.radius;
        ctx.beginPath();
        ctx.arc(x, y, particle.size, 0, Math.PI * 2);
        ctx.fillStyle = particle.color;
        ctx.globalAlpha = 0.85;
        ctx.fill();
      }

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

    const reduced = prefersReducedMotion();
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
  }, [width, height, count, speed]);

  return (
    <canvas
      ref={canvasRef}
      className={className}
      width={width}
      height={height}
      style={{ width, height }}
      aria-hidden="true"
    />
  );
}
